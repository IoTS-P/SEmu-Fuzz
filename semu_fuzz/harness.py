from . import globs
from .configuration import args, config
from .emulate import uc, nvic
from .log import debug, fuzz_stat
from .emulate.semu.rule import rules_configure

import gc

# for debug when haven't install this pkg.
# import sys
# import os
# sys.path.append(os.pos.path.dirname(__file__))

def main():
    global args, config, uc
    # configure args and config
    args = args.parse_args()
    config = config.parse_config()

    # configure uc
    uc = uc.uc_configure()
    
    # configure log
    if args.debug_level:
        debug.debug_configure()
    if args.stat:
        fuzz_stat.stat_configure()

    # configure nvic
    nvic.nvic_configure(uc)

    # configure rule
    rules_configure(uc, globs.config.rules)

    # Collect garbage once in order to avoid doing so while fuzzing
    gc.collect()

    # start emulation or fuzz
    emulate_mode = globs.config.emulate_mode
    if emulate_mode == 'emulate':
        from .emulate.uc import uc_emulate
        uc_emulate(uc)
    elif emulate_mode == 'fuzz':
        from .fuzz.fuzz import fuzz_emulate
        fuzz_emulate(uc)
    else:
        print("%s mode has not been supported, yet." % emulate_mode)


    

