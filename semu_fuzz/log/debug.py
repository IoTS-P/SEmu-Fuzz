from .. import globs
from ..exit import do_exit
from .log import log_configure

from unicorn import UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_READ_INVALID, UC_MEM_WRITE_UNMAPPED
from unicorn.arm_const import *
from time import perf_counter
import sys

debug_file_list = {
    "function": "function.txt",
    "debug": "debug.txt"
}

glob_debug_level = 0
time_start = 0

def debug_configure():
    global debug_file_list, glob_debug_level, time_start
    debug_file_list = log_configure("debug_output", debug_file_list)
    glob_debug_level = globs.args.debug_level
    # add invalid mem access hook
    globs.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID, _hook_mem_invalid_access)
    # add function hook
    if glob_debug_level > 0 and globs.config.symbols:
        globs.uc.hook_add(UC_HOOK_BLOCK, _hook_funtion)
        globs.uc.hook_add(UC_HOOK_CODE, _hook_caller_code)
    if glob_debug_level > 2:
        globs.uc.hook_add(UC_HOOK_CODE, _hook_instruction)
        globs.uc.hook_add(UC_HOOK_BLOCK, _hook_block) 
    # record time
    time_start = perf_counter()

def debug_info(info, debug_level):
    if glob_debug_level < debug_level:
        return
    with open(debug_file_list['debug'], "a+") as f:
        f.write(info)
    
def debug_function(info):
    with open(debug_file_list['function'], "a+") as f:
        f.write(info)

def debug_exit(kill_signal):
    global time_start
    # output the exit pc
    debug_info("end pc: 0x%x\n"%(globs.uc.reg_read(UC_ARM_REG_PC)), 1)
    # output the running CPU time
    debug_info("running time: %.3fs\n"%(perf_counter() - time_start), 1)
    # output the exit type
    if kill_signal == -1:
        debug_info("Exiting via os._exit\n", 0)
    else:
        debug_info("Exiting via os.kill\n", 0)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_MCLASS|CS_MODE_THUMB)
def _hook_instruction(uc, address, size, user_data):
    '''
    dump instruction disassembly and log. 
    Used if globs.debug_level > 2.
    '''
    curpc = uc.reg_read(UC_ARM_REG_PC)
    mem = uc.mem_read(address, size)
    for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
        debug_info("    Instr: {:#016x}:\t{}\t{}\n".format(address, cs_mnemonic, cs_opstr), 3)

def _hook_mem_invalid_access(uc, access, address, size, value, user_data):
    '''
    hook invalid mem access and log. 
    Used if globs.debug_level > 0.
    '''
    if access == UC_MEM_WRITE_UNMAPPED:
        print("[-] INVALID Mem Write: addr= 0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
    else:
        print("[-] INVALID Read: addr= 0x{0:016x} size={1}, pc= 0x{2:016x}".format(address, size, uc.reg_read(UC_ARM_REG_PC)))
    sys.stdout.flush()
    do_exit(-1)

def _hook_block(uc, address, size, user_data):
    '''
    hook block and log. 
    Used if globs.debug_level > 2.
    '''
    debug_info("Basic Block: addr= 0x{0:016x} , size=0x{1:016x} (lr=0x{2:x})\n".format(address, size, uc.reg_read(UC_ARM_REG_LR)), 3)

last_code = 0
def _hook_caller_code(uc, address, size, user_data):
    '''
    hook every code and log. 
    Used if globs.debug_level > 0.
    '''
    global last_code
    last_code = address

def _hook_funtion(uc, address, size, user_data):
    '''
    hook every code and match symbol table.
    Used if globs.args.debug_level > 0 and has symbols.
    '''
    if address in globs.config.symbols:
        global last_code
        debug_function("%d %s %s %s\n"%(globs.block_count, hex(last_code), hex(address), globs.config.symbols[address]))

