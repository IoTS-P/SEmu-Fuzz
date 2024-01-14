from .. import globs
from .log import log_configure

from unicorn import UC_HOOK_CODE
import os

stat_file_list = {
    "visit_block": "visit_blocks.txt"
}

valid_block = set()
visit_block = set()

def _hook_bb(uc, address, size, user_data):
    '''
    hook every code and match valid blocks table.
    Used if -s arg set.
    '''
    global visit_block, valid_block
    if address not in visit_block and address in valid_block:
        visit_block.add(address)

def stat_configure():
    global stat_file_list, visit_block, valid_block
    stat_file_list = log_configure(globs.args.stat, stat_file_list, False)
    # add stat hook
    globs.uc.hook_add(UC_HOOK_CODE, _hook_bb)
    # get valid block (necessary)
    valid_block_path = os.path.join(globs.config_dir, 'valid_basic_blocks.txt')
    if not os.path.exists(valid_block_path):
        print('[-] Stat Configure Error! File Not Exist: %s', valid_block_path)
    with open(valid_block_path, 'r') as f:
        for line in f:
            valid_block.add(int(line.strip(), 16))

def stat_visit_block():
    ''' called when exit '''
    global visit_block, valid_block
    with open(stat_file_list['visit_block'], "a+") as f:
        visit_block = [hex(x) for x in list(visit_block)]
        visit_block_str = " ".join(visit_block)
        timestamp = int(globs.args.timestamp)
        if timestamp == -1:
            timestamp = int(round(os.path.getctime(globs.args.input_file)))
        f.write("%d\t%s\n" % (timestamp, visit_block_str))

def stat_exit():
    stat_visit_block()