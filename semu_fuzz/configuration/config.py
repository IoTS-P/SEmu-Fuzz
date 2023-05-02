from .. import globs
from ..utils import get_realpath, yaml_load, merge_dict
from ..exit import do_exit

import yaml
import os
from argparse import Namespace

default_config = Namespace(
    memory_map=None,  # memory map
    entry_point=None,  # entry point
    initial_sp=None,  # initial stack pointer
    rules=None,  # rule path
    symbols=None,  # symbol table
    isr_vector=0, # the isr vector
    emulate_mode='fuzz',  # support: emulate, fuzz
    begin_point=0,  # the beginning of the data input, default is entry_point
    fork_points=[],  # the point of the main loop of the bin
    fork_point_times=2, # the max time to meet fork point when fuzz
    enable_native=True, # True if your want to use c 
    enable_bitband=True,  # note: bitband used only when Cortex M3 and M4, so if not, set it False
    enable_systick=True,
    systick_reload=globs.INTERRUPT_INTERVAL  # the block interval of systick
)

def parse_config():
    config_path = globs.args.config_file
    # load config
    config = yaml_load(config_path)
    # store config_dir
    globs.config_dir = os.path.dirname(config_path)
    # (optional)include: import another config in this one.
    if 'include' in config:
        newconfig = {}
        # note: the end file get the highest priority.
        for f in config['include']:
            f = get_realpath(config_path, f)
            merge_dict(newconfig, yaml_load(f))
        merge_dict(newconfig, config)
        config = newconfig
    # check the nessary parameters
    nessary_parameters = ['memory_map', 'entry_point', 'rules', 'initial_sp']
    for p in nessary_parameters:
        if p not in config:
            print("[-] Config Error! '%s' not exists!" % p)
            do_exit(-1)
    # reset symbols
    if 'symbols' in config:
        symbols_addr = list(config['symbols'].keys())
        for addr in symbols_addr:
            if (addr & 1) == 1:
                config['symbols'][addr - 1] = config['symbols'].pop(addr)
    # set default begin_point
    if 'begin_point' not in config:
        config['begin_point'] = config['entry_point']
    # record config content
    default_config.__dict__.update(config)
    globs.config = default_config
    return globs.config
    