from .. import globs
from ..utils import get_realpath
from ..exit import do_exit, force_crash
from ..log.debug import debug_info

from unicorn import *
from unicorn.arm_const import *

def _hook_block_add(uc, address, size, user_data):
    globs.block_count = globs.block_count + 1

def uc_configure():
    config = globs.config
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    # setup regions
    regions = {}
    for rname, region in config.memory_map.items():
        # memory map
        prot = 0
        if 'permissions' in region:
            prot = 7 # UC_PROT_ALL
        if 'r' in region['permissions']:
            prot |= 1
        if 'w' in region['permissions']:
            prot |= 2
        if 'x' in region['permissions']:
            prot |= 4
        base_addr = region['base_addr']
        size = region['size']
        regions[rname] = (base_addr, size, prot)
        try:
            # align size to page size
            if size & (globs.PAGE_SIZE-1) != 0:
                debug_info(f"[WARN] Size 0x{size:x} of region '{rname}' not page aligned. Aligning to next page boundary size.", 1)
                size -= size & (globs.PAGE_SIZE-1)
                size += globs.PAGE_SIZE
            # align base_addr to page size
            if base_addr & (globs.PAGE_SIZE-1) != 0:
                debug_info(f"[WARN] Start 0x{base_addr:x} of region '{rname}' not page aligned. Aligning to previous page boundary.", 1)
                unalignment = base_addr & (globs.PAGE_SIZE-1)
                base_addr -= unalignment
            uc.mem_map(base_addr, size, prot)
        except Exception as e:
            print("[-] Unicorn Setting Error! Fail to map region %s at %#08x, size %#08x, perms: %d, because %s\n" % (rname, region['base_addr'], region['size'], prot, e))
            do_exit(-1)
        # load the file in region
        if 'file' in region:
            file_offset = 0
            load_offset = 0
            file_size = region['size']
            if 'file_offset' in region:
                file_offset = region['file_offset']
            if 'load_offset' in region:
                load_offset = region['load_offset']
            if 'file_size' in region:
                file_size = region['file_size']
            f = get_realpath(globs.args.config_file, region['file'])
            with open(f, 'rb') as fp:
                fp.seek(file_offset)
                region_data = fp.read(file_size)
                try:
                    uc.mem_write(region['base_addr'] + load_offset, region_data)
                except Exception as e:
                    print("[-] Unicorn Setting Error! Fail to load %#08x bytes at %#08x\n" % (len(region_data), region['base_addr'] + load_offset))
                    do_exit(1)
    # TODO: Make this arch-independent
    uc.reg_write(UC_ARM_REG_PC, config.entry_point)
    uc.reg_write(UC_ARM_REG_SP, config.initial_sp)
    # add necessary hook
    uc.hook_add(UC_HOOK_BLOCK, _hook_block_add)
    # store in globs
    globs.uc = uc
    return globs.uc

def uc_emulate(uc):
    with open(globs.args.input_file, "rb") as f:
        user_input = f.read()
    while len(user_input):
        value = int.from_bytes(user_input[:1], 'little')
        globs.user_input.append(value)
        user_input = user_input[1:]
    globs.raw_input = globs.user_input[:]
    try:
        result = uc.emu_start(uc.reg_read(UC_ARM_REG_PC)|1, 0, timeout=0, count=globs.args.instr_limit)
    except UcError as e:
        print("[-] Crash! {}".format(e))
        force_crash(e)
        return