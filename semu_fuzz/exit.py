from . import globs

from unicorn import *
from unicorn.arm_const import *
import sys
import os

def do_exit(status, kill_signal=-1):
    '''
    some output before exiting.
    '''
    # exit log
    if globs.args.debug_level > 0:
        from .log.debug import debug_exit
        debug_exit(kill_signal)
    if globs.args.stat:
        from .log.fuzz_stat import stat_exit
        stat_exit()
    # exit
    if kill_signal == -1:
        os._exit(status)
    else:
        os.kill(os.getpid(), kill_signal)



def force_crash(uc_error):
    '''
    Be called to indicate to the fuzzer that a crash occurred during emulation.
    Used if globs.enable_fuzz = True.
    '''
    from .exit import do_exit
    mem_errors = [
        UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED, UC_ERR_EXCEPTION
    ]
    if uc_error.errno in mem_errors:
        # Memory error - throw SIGSEGV
        sig = signal.SIGSEGV # sig: 11
    elif uc_error.errno == UC_ERR_INSN_INVALID:
        # Invalid instruction - throw SIGILL
        sig = signal.SIGILL # sig: 4
    else:
        # Not sure what happened - throw SIGABRT
        sig = signal.SIGABRT # sig: 4
    do_exit(-1, sig)