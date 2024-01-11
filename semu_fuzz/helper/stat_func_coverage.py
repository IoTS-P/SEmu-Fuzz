'''
Description: stat func coverage from stat_output/new_blocks.txt.
Usage: fuzzemu-helper func <base_configs.yml>
'''

from ..utils import get_realpath, yaml_load, merge_dict, find_output_folders

import os

def _dump_new_funcs(stat_path, symbol_dict):
    # get all the symbols
    new_blocks_path = os.path.join(stat_path, 'new_blocks.txt')
    new_func_path = os.path.join(stat_path, 'new_funcs.txt')
    new_funcs_blocks = set()
    new_funcs_blocks_with_stamp = []
    new_blocks_set = set()
    with open(new_blocks_path, "r") as f:
        lines = f.readlines()
    with open(new_func_path, "w") as f:
        first_flag = True
        first_stamp = 0
        for line in lines:
            new_funcs = []
            stamp, _, new_blocks = line.split('\t')
            if first_flag:
                first_stamp = int(stamp)
                first_flag = False
            for block in new_blocks.split(' ')[:-1]:
                block = int(block, 16)
                new_blocks_set.add(block)
                if (block in symbol_dict) and (block not in new_funcs_blocks):
                    new_funcs_blocks.add(block)
                    new_funcs_blocks_with_stamp.append((int(stamp) - first_stamp, block))
                    new_funcs.append(symbol_dict[block])
            new_funcs_str = " ".join(new_funcs)
            f.write(f"{stamp}\t{len(new_funcs_blocks)}\t{new_funcs_str}\n")
        print(f"[+] Output new funcs to {new_func_path}")
    return new_funcs_blocks_with_stamp, new_blocks_set

def _dump_visit_funcs(stat_path, all_funcs_blocks_with_stamp):
    visit_func_path = os.path.join(stat_path, 'visit_funcs.txt')
    with open(visit_func_path, "w") as f:
        f.write("\n".join([f"{stamp}\t{hex(block)}\t{func}" for stamp, block, func in all_funcs_blocks_with_stamp]))
        print(f"[+] Output visit funcs to {visit_func_path}")

def _dump_visit_blocks(stat_path, all_blocks):
    visit_func_path = os.path.join(stat_path, 'visit_blocks.txt')
    with open(visit_func_path, "w") as f:
        f.write("\n".join([f"{hex(block)}" for block in all_blocks]))
        print(f"[+] Output visit funcs to {visit_func_path}")

def get_config(config_path):
    # load config
    config = yaml_load(config_path)
    # (optional)include: import another config in this one.
    if 'include' in config:
        newconfig = {}
        # note: the end file get the highest priority.
        for f in config['include']:
            f = get_realpath(config_path, f)
            merge_dict(newconfig, yaml_load(f))
        merge_dict(newconfig, config)
        config = newconfig
    return config

def func(base_configs):
    for firmware_elfpath, base_config in base_configs.items():
        # set default model
        model = 'semu'
        if 'model' in base_config.keys():
            model = base_config['model']
        firmware_dir = os.path.dirname(firmware_elfpath)
        stat_path = os.path.join(firmware_dir, 'stat')
        syms_path = os.path.join(stat_path, 'syms.yml')
        # load yaml config file
        if os.path.exists(syms_path):
            symbol_dict = yaml_load(syms_path)
        else:
            config_path = os.path.join(firmware_dir, f'{model}_config.yml')
            # load yaml config file
            config = get_config(config_path)
            symbol_dict = config["symbols"]
        # find_folders
        dirs = find_output_folders(firmware_dir, "stat")
        all_funcs = {}
        all_new_block = set()
        for stat_path in dirs:
            new_funcs_blocks_with_stamp, new_blocks = _dump_new_funcs(stat_path, symbol_dict)
            all_new_block = all_new_block | new_blocks
            for stamp, block in new_funcs_blocks_with_stamp:
                if (block not in all_funcs) or (block in all_funcs and all_funcs[block] > stamp):
                    all_funcs[block] = stamp
        # sort by stamp
        all_funcs_list = sorted(all_funcs.items(), key=lambda x: x[1])
        # add symbol
        all_funcs_blocks_with_stamp = []
        for block, stamp in all_funcs_list:
            all_funcs_blocks_with_stamp.append((stamp, block, symbol_dict[block]))
        if len(all_funcs_blocks_with_stamp):
            _dump_visit_funcs(firmware_dir, all_funcs_blocks_with_stamp)
        _dump_visit_blocks(firmware_dir, all_new_block)

if __name__ == "__main__":
    import sys
    func(yaml_load(sys.argv[1]))