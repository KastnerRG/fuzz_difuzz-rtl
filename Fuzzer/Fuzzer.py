import time
import random
import json
from pathlib import Path

from cocotb.decorators import coroutine
from RTLSim.host import ILL_MEM, SUCCESS, TIME_OUT, ASSERTION_FAIL

from src.utils import *
from src.multicore_manager import proc_state


@coroutine
def Run(dut, toplevel,
        num_iter=1, template='Template', in_file=None,
        out='output', record=False, cov_log=None,
        multicore=0, manager=None, proc_num=0, start_time=0, start_iter=0, start_cov=0,
        prob_intr=0, no_guide=False, debug=False):

    assert toplevel in ['RocketTile', 'BoomTile' ], \
        '{} is not toplevel'.format(toplevel)

    random.seed(time.time() * (proc_num + 1))

    (mutator, preprocessor, isaHost, rtlHost, checker) = \
        setup(dut, toplevel, template, out, proc_num, debug, no_guide=no_guide)

    if in_file: num_iter = 1

    stop = [ proc_state.NORMAL ]
    mNum = 0
    cNum = 0
    iNum = 0
    last_coverage = 0
    started = time.monotonic()
    duration = 0 if multicore else float(os.environ.get('FUZZ_DURATION', '0'))
    stats = dict(rtl_executions=0, rtl_successes=0, isa_matches=0, coverage=0,
                 symbolic_executions=0, symbolic_successes=0, symbolic_matches=0,
                 finished=False, backend_status=0)
    # External candidates and their feedback artifacts are explicitly enabled.
    queue_path = os.environ.get('FUSS_QUEUE')
    queue = Path(queue_path) if queue_path and not multicore else None
    replay_dir = Path(out) / 'symbolic_replays'
    if queue is not None:
        replay_dir.mkdir(exist_ok=True)

    def publish_stats():
        # The native FuSS launcher owns one backend; multicore uses its manager.
        if queue is None:
            return
        stats['elapsed'] = time.monotonic() - started
        temporary = Path(out) / 'campaign.json.tmp'
        temporary.write_text(json.dumps(stats, indent=2) + '\n')
        os.replace(temporary, Path(out) / 'campaign.json')

    publish_stats()

    debug_print('[DifuzzRTL] Start Fuzzing', debug)

    if multicore:
        yield manager.cov_restore(dut)

    for it in range(num_iter):
        if duration and time.monotonic() - started >= duration:
            break
        debug_print('[DifuzzRTL] Iteration [{}]'.format(it), debug)

        if multicore:
            if it == 0:
                mutator.update_corpus(out + '/corpus', 1000)
            elif it % 1000 == 0:
                mutator.update_corpus(out + '/corpus')

        assert_intr = False
        if random.random() < prob_intr:
            assert_intr = True

        symbolic_input = next(iter(sorted(queue.glob('*.si'))), None) if queue is not None else None
        if in_file:
            (sim_input, data, assert_intr) = mutator.read_siminput(in_file)
            symbolic_input = None
        elif symbolic_input:
            claimed = replay_dir / symbolic_input.name
            os.replace(symbolic_input, claimed)
            metadata = symbolic_input.with_suffix('.json')
            if metadata.exists():
                os.replace(metadata, claimed.with_suffix('.json'))
            symbolic_input = claimed
            (sim_input, data, assert_intr) = mutator.read_siminput(str(claimed))
        else:
            (sim_input, data) = mutator.get(assert_intr)

        if debug:
            print('[DifuzzRTL] Fuzz Instructions')
            for inst, INT in zip(sim_input.get_insts(), sim_input.ints + [0]):
                print('{:<50}{:04b}'.format(inst, INT))

        (isa_input, rtl_input, symbols) = preprocessor.process(sim_input, data, assert_intr)

        if isa_input and rtl_input:
            ret = run_isa_test(isaHost, isa_input, stop, out, proc_num)
            if ret == proc_state.ERR_ISA_TIMEOUT: continue
            elif ret == proc_state.ERR_ISA_ASSERT: break

            try:
                (ret, coverage) = yield rtlHost.run_test(rtl_input, assert_intr)
            except:
                stop[0] = proc_state.ERR_RTL_SIM
                break

            if queue is not None:
                stats['rtl_executions'] += 1
                stats['rtl_successes'] += int(ret == SUCCESS)
                stats['coverage'] = max(stats['coverage'], int(coverage))
            if symbolic_input:
                stats['symbolic_executions'] += 1
                stats['symbolic_successes'] += int(ret == SUCCESS)
                symbolic_input.with_suffix('.result.json').write_text(json.dumps(
                    dict(rtl_status=int(ret), coverage=int(coverage), iteration=it)) + '\n')
            # Sample every completed RTL execution, including plateaus.
            if record and queue is not None:
                save_file(cov_log, 'a', '{:<10}\t{:<10}\t{:<10}\n'.format(
                    time.time() - start_time, start_iter + it, start_cov + coverage))

            if assert_intr and ret == SUCCESS:
                (intr_prv, epc) = checker.check_intr(symbols)
                if epc != 0:
                    preprocessor.write_isa_intr(isa_input, rtl_input, epc)
                    ret = run_isa_test(isaHost, isa_input, stop, out, proc_num, True)
                    if ret == proc_state.ERR_ISA_TIMEOUT: continue
                    elif ret == proc_state.ERR_ISA_ASSERT: break
                else: continue

            cause = '-'
            match = False
            if ret == SUCCESS:
                match = checker.check(symbols)
            elif ret == ILL_MEM:
                match = True
                debug_print('[DifuzzRTL] Memory access outside DRAM -- {}'. \
                            format(iNum), debug, True)
                if record:
                    save_mismatch(out, proc_num, out + '/illegal',
                                  sim_input, data, iNum)
                iNum += 1

            if queue is not None and ret == SUCCESS and match:
                stats['isa_matches'] += 1
                stats['symbolic_matches'] += int(symbolic_input is not None)
            publish_stats()
            if symbolic_input:
                symbolic_input.with_suffix('.result.json').write_text(json.dumps(
                    dict(rtl_status=int(ret), isa_match=bool(match),
                         coverage=int(coverage), iteration=it)) + '\n')

            if not match or ret not in [SUCCESS, ILL_MEM]:
                if multicore:
                    mNum = manager.read_num('mNum')
                    manager.write_num('mNum', mNum + 1)

                if record:
                    save_mismatch(out, proc_num, out + '/mismatch',
                                  sim_input, data, mNum)

                mNum += 1
                if ret == TIME_OUT: cause = 'Timeout'
                elif ret == ASSERTION_FAIL: cause = 'Assertion fail'
                else: cause = 'Mismatch'

                debug_print('[DifuzzRTL] Bug -- {} [{}]'. \
                            format(mNum, cause), debug, not match or (ret != SUCCESS))

            if coverage > last_coverage:
                if multicore:
                    cNum = manager.read_num('cNum')
                    manager.write_num('cNum', cNum + 1)

                if record:
                    if queue is None:
                        save_file(cov_log, 'a', '{:<10}\t{:<10}\t{:<10}\n'.
                                  format(time.time() - start_time, start_iter + it,
                                         start_cov + coverage))
                        sim_input.save(out + '/corpus/id_{}.si'.format(cNum))
                    else:
                        corpus_path = out + '/corpus/id_{}.si'.format(cNum)
                        sim_input.save(corpus_path + '.tmp', data)
                        os.replace(corpus_path + '.tmp', corpus_path)

                cNum += 1
                mutator.add_corpus(sim_input)
                last_coverage = coverage

            mutator.update_phase(it)

        else:
            stop[0] = proc_state.ERR_COMPILE
            # Compile failed
            break

    stats['finished'] = True
    stats['backend_status'] = stop[0]
    publish_stats()
    if not multicore and stop[0] != proc_state.NORMAL:
        raise RuntimeError('DifuzzRTL backend failed: {}'.format(proc_state.tpe[stop[0]]))

    if multicore:
        save_err(out, proc_num, manager, stop[0])
        manager.set_state(proc_num, stop[0])

    debug_print('[DifuzzRTL] Stop Fuzzing', debug)

    if multicore:
        yield manager.cov_store(dut, proc_num)
        manager.store_covmap(proc_num, start_time, start_iter, num_iter)
