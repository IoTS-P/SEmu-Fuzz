from .. import globs
from .log import log_configure

from unicorn import UC_HOOK_CODE
import os

stat_file_list = {
    "new_block": "new_blocks.txt",
    "visit_block": "visit_blocks.txt"
}

new_blocks = []
valid_block = set()
visit_block = set()

def _hook_bb(uc, address, size, user_data):
    '''
    hook every code and match valid blocks table.
    Used if -s arg set.
    '''
    global new_blocks, visit_block, valid_block
    if address not in visit_block and address in valid_block:
        new_blocks.append(address)
        visit_block.add(address)
        stat_visit_block(address)

def stat_configure():
    global stat_file_list, new_blocks, visit_block, valid_block
    stat_file_list = log_configure("stat_output", stat_file_list, False)
    # add stat hook
    globs.uc.hook_add(UC_HOOK_CODE, _hook_bb)
    # get valid block(necessary)
    valid_block_path = os.path.join(globs.config_dir, 'valid_basic_blocks.txt')
    if not os.path.exists(valid_block_path):
        print('[-] Stat Configure Error! File Not Exist: %s', valid_block_path)
    with open(valid_block_path, 'r') as f:
        for line in f:
            valid_block.add(int(line.strip(), 16))
    # get visit block
    visit_block_path = stat_file_list['visit_block']
    if os.path.exists(visit_block_path):
        with open(visit_block_path, 'r') as f:
            for line in f:
                visit_block.add(int(line.strip(), 16))

def stat_visit_block(address):
    with open(stat_file_list['visit_block'], 'a+') as f:
        f.write('%x\n' % address)

def stat_new_block():
    ''' called when exit '''
    global new_blocks, visit_block, valid_block
    with open(stat_file_list['new_block'], "a+") as f:
        new_blocks = [hex(x) for x in sorted(new_blocks)]
        new_blocks_str = " ".join(new_blocks)
        f.write("%d\t%d\t%s\n" % (int(round(os.path.getctime(globs.args.input_file))), len(visit_block), new_blocks_str))

def stat_exit():
    stat_new_block()
        
