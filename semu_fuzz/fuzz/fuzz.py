from .. import globs
from ..exit import do_exit, force_crash
from ..log.debug import debug_info

from unicorn import *
from unicornafl import uc_afl_fuzz, UcAflError

fork_point_times = 0
def _hook_fork_point_exit(uc, address, size, user_data):
    '''
    hook fork_point and exit when meet times > config.fork_point_times.
    Note: Default fork_point_times is 2. 
    Used if globs.fork_points is set.
    '''
    global fork_point_times
    fork_point_times += 1
    debug_info("meet fork point.\n", 1)
    if fork_point_times >= globs.config.fork_point_times:
        do_exit(0)

def _place_input_callback(uc, fuzz_input, persistent_round, data):
    '''
    Be called when the fuzzer place an input.
    Used if globs.enable_fuzz = True.
    '''
    #-just for not unicornafl-#
    # with open(fuzz_input, "rb") as f:
    #     fuzz_input = f.read()
    #-#######################-#
    while len(fuzz_input):
        value = int.from_bytes(fuzz_input[:1], 'little')
        globs.user_input.append(value)
        fuzz_input = fuzz_input[1:]
    debug_info("len:{}; fuzz_input: {}\n".format(len(globs.user_input),[hex(i) for i in globs.user_input]), 1)

def _validate_crash_callback(uc, unicorn_errno, input, persistent_round, data):
    '''
    be called when a crash occurs.
    Used if globs.enable_fuzz = True.
    '''
    pass

def _for_fuzzing_instruction_hook(uc, address, size, user_data):
    pass

def fuzz_emulate(uc):
    uc.hook_add(UC_HOOK_CODE, _for_fuzzing_instruction_hook) # don't remove it when fuzz!!!
    # add fork point hook
    for fork_point in globs.config.fork_points:
        uc.hook_add(UC_HOOK_CODE, _hook_fork_point_exit, begin=fork_point, end=fork_point) # don't remove it when fuzz!!!
    try:
        uc_afl_fuzz(uc=uc, input_file=globs.args.input_file, place_input_callback=_place_input_callback, validate_crash_callback=_validate_crash_callback, data=None, exits=[0])
    except UcAflError as e:
        if e.errno == 3: # No afl
            debug_info("[WARN] Fuzz mode but no AFL.\n", 1)
            do_exit(0)
        else: # other afl error
            print("[-] Crash! {}".format(e))
            force_crash(e)
    except UcError as e:
        print("[-] Crash! {}".format(e))
        force_crash(e)
    except Exception as e:
        print("[-] Crash! {}".format(e))
        force_crash(e)