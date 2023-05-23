'''
Description: stat bb coverage from afl output.
Usage: emuwp-fuzz-helper stat <base_configs.yml> [-t <time>]
'''

import os
import concurrent.futures

from ..globs import tool_name
from ..utils import run_task
from .stat_draw_bb_img import draw

DEBUG = True # Recommend setting True to get most info in stat.

def _find_file(folder_path):
    # find all the files in folder_path
    return [os.path.join(folder_path, file) for file in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, file))]

def _dump_new_blocks(stat_path):
    visit_blocks_path = os.path.join(stat_path, 'visit_blocks.txt')
    new_blocks_path = os.path.join(stat_path, 'new_blocks.txt')
    visit_blocks = set()
    # get all the stat output
    with open(visit_blocks_path, "r") as f:
        lines = f.readlines()
    # sort by timestamp
    lines = sorted(lines, key=lambda x: int(x.split('\t')[0]))
    with open(new_blocks_path, "w") as f:
        for line in lines:
            new_blocks = set()
            stamp, visit_block = line.split('\t')
            for block in visit_block.split(' '):
                block = int(block, 16)
                if block not in visit_blocks:
                    visit_blocks.add(block)
                    new_blocks.add(block)
            new_block = [hex(x) for x in sorted(list(new_blocks))]
            new_block_str = " ".join(new_block)
            f.write(f"{stamp}\t{len(visit_blocks)}\t{new_block_str}\n")
    
def _find_output_folders(base_path, search_key):
    result = []
    for root, dirs, files in os.walk(base_path):
        for dir in dirs:
            if dir.startswith(search_key):
                result.append(os.path.join(root, dir))
    return result


def stat(base_configs, duration):
    # dump all the file
    for firmware_elfpath, base_config in base_configs.items():
        try:
            # set default module
            module = 'semu'
            if 'module' in base_config.keys():
                module = base_config['module']
            firmware_dir = os.path.dirname(firmware_elfpath)
            stat_path = os.path.join(firmware_dir, 'stat_output')
            config_path = os.path.join(firmware_dir, f'{module}_config.yml')
            # find_folders
            dirs = _find_output_folders(firmware_dir, "output")
            # get all the results
            result_index = 0
            for base_dir in dirs:
                possible_fuzz_queue_dir = ['queue', 'default/queue'] # AFL and AFLplusplus
                # check all path to know whether fuzz or not
                for qd in possible_fuzz_queue_dir:
                    qd = os.path.join(base_dir, qd)
                    if os.path.exists(qd):
                        fuzz_queue_dir = qd
                        break
                else:
                    print(f"[+] No Fuzz output in {base_dir}")
                    continue

                # start to stat
                print(f'[*] Stat Block Coverage of {base_dir}...')
                unique_stat_path = stat_path + str(result_index)
                # rm the old stat
                os.system(f"rm -r {unique_stat_path} 2>/dev/null")
                commands = []
                # find all the file in fuzz_queue_dir and sort them.
                for fuzz_input in _find_file(fuzz_queue_dir):
                    command_line = f"{tool_name} {fuzz_input} {config_path} -s {unique_stat_path.rsplit('/',1)[-1]}"
                    commands.append(command_line)
                # execute the command no order
                # create threadpool
                max_threads = 100
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
                # add task into threadpool
                futures = []
                
                task_id = 0
                for command in commands:
                    # add this task into thread pool
                    future = pool.submit(run_task, command, task_id, 600)
                    futures.append(future)
                    task_id += 1

                # wait tasks to the end
                results = []
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    results.append(result)
            
                _dump_new_blocks(unique_stat_path)
            
                print("[+] All the files in the output queue have been processed!")
                # draw picture with 'new_blocks.txt'
                draw(unique_stat_path, result_index, duration * 3600)

                result_index += 1
        except Exception as e:
            print("[-] Failed! {}".format(e))