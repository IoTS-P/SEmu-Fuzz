'''
Description: stat bb coverage from afl output.
Usage: semu-fuzz-helper stat <base_configs.yml> [-t <time>]
'''

import argparse
import os
import subprocess
from time import perf_counter, sleep
import concurrent.futures

from .stat_draw_bb_img import draw

DEBUG = True # Recommend setting True to get most info in stat.

def _find_file(folder_path):
    # find all the files in folder_path
    return [os.path.join(folder_path, file) for file in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, file))]

def _get_file_sorted(folder_path):
    # get create time
    files = []
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            create_time = os.path.getctime(file_path)
            files.append((file_name, create_time))
    # sort
    return [os.path.join(folder_path, file_name) for file_name,_ in sorted(files, key=lambda x: x[1])]

def _run_task(command, task_id):
    if DEBUG:
        print("[*] %05d Start Command: %s" % (task_id, command))
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # wait for proc stop
    start_time = perf_counter()
    while True:
        if proc.poll() is not None:
            break
        # timeout: 10s
        if perf_counter() - start_time > 10:
            if DEBUG:
                print("[-] %05d Process timed out. Killing process..." % task_id)
                # exit(-1)
            proc.kill()
            return False
        sleep(0.1) # check proc status every 0.1s
    return True

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
    

def stat(base_configs, duration):
    # dump all the file
    for firmware_elfpath, base_config in base_configs.items():
        try:
            firmware_dir = os.path.dirname(firmware_elfpath)
            stat_path = os.path.join(firmware_dir, 'stat_output')
            possible_fuzz_queue_dir = [
                os.path.join(firmware_dir, "output/queue"), # AFL
                os.path.join(firmware_dir, "output/default/queue")  # AFLplusplus
            ]
            fuzz_queue_dir = possible_fuzz_queue_dir[0]
            config_path = os.path.join(firmware_dir, 'semu_config.yml')
            
            # check all path to know whether fuzz or not
            for qd in possible_fuzz_queue_dir:
                if os.path.exists(qd):
                    fuzz_queue_dir = qd
                    break
            else:
                print("[+] No Fuzz output of %s" % firmware_elfpath)
                continue

            print('[*] Stat Block Coverage of %s...' % firmware_elfpath)

            # rm the old stat
            os.system("rm -r " + stat_path)

            # start stat
            commands = []
            # find all the file in fuzz_queue_dir and sort them.
            for fuzz_input in _get_file_sorted(fuzz_queue_dir):
                command_line = "semu-fuzz %s %s -s " % (fuzz_input, config_path)
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
                future = pool.submit(_run_task, command, task_id)
                futures.append(future)
                task_id += 1

            # wait tasks to the end
            results = []
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
            
            _dump_new_blocks(stat_path)
            
            print("[+] All the files in the output queue have been processed!")
            # draw picture with 'new_blocks.txt'
            draw(firmware_dir, duration * 3600)
        except Exception as e:
            print("[-] Failed! {}".format(e))