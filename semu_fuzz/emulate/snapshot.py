from .. import globs
from ..log.debug import debug_info
from .nvic import nvic_state_dump, nvic_state_load

from unicorn import *
from unicorn.arm_const import *
from ..utils import my_debug_log
import re
from intelhex import IntelHex

uc_reg_consts = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
            UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_CONTROL, UC_ARM_REG_SP, UC_ARM_REG_MSP, UC_ARM_REG_PSP, UC_ARM_REG_XPSR]

reg_names = ['r0', 'r1', 'r2', 'r3', 'r4',
        'r5', 'r6', 'r7', 'r8', 'r9',
        'r10', 'r11', 'r12', 'lr', 'pc',
        'ctrl','sp', 'msp', 'psp', 'xpsr']

uc_reg_consts_by_reg_name = {
    name: uc_reg_consts[i] for i, name in enumerate(reg_names)
}

def load_reg_and_memory(filename):
    '''
    load register and memory from file
    '''
    uc = globs.uc

    reg_regex = re.compile(r"(.*)=0x(.*)$")

    with open(filename, "r") as file:
        reg_vals = {}

        for _ in uc_reg_consts:
            line = file.readline()
            name, val_str = reg_regex.match(line).groups()
            val = int(val_str, 16)
            reg_vals[name] = val

        mem_segments = {}
        ih = IntelHex(file)
        for addr, end in ih.segments():
            contents = ih.gets(addr, end - addr)
            mem_segments[addr] = contents
    
    for addr, contents in mem_segments.items():
        debug_info("Restoring 0x{:x} bytes of contents to 0x{:08x}\n".format(len(contents), addr),3)

        try:
            # strip address and trailing newline
            uc.mem_write(addr, contents)
        except UcError:
            # map regions that are not mapped in the default configuration
            start = addr & (~0xfff)
            debug_info("Got exception, need to map at 0x{}\n".format(addr),3)
            size = ((len(contents)+addr-start) + 0xfff) & (~0xfff)
            uc.mem_map(start, size, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_write(addr, contents)
    for reg_name, val in reg_vals.items():
        reg_const = uc_reg_consts_by_reg_name[reg_name]

        if reg_const == UC_ARM_REG_PC:
            val |= 1

        debug_info("Restoring reg val: 0x{:x}, {}\n".format(val,reg_name),3)
        uc.reg_write(reg_const, val)

def load_snapshot(path):
    '''
    load snapshot from path
    '''
    from os.path import exists
    if not exists(path):
        debug_info("[WARN] Snapshot file does not exist, skipping\n",3)
        return
    load_reg_and_memory(path)
    nvic_state_load(path+'_nvic')
    my_debug_log("load_snapshot: "+path)

def collect_regs(uc):
    return {const: uc.reg_read(const) for const in uc_reg_consts}

def collect_state(uc):
    '''
    Get the current state of the unicorn emulator
    '''
    """
    debug_info("Collecting mmio contents\n")
    # select relevant mmio regions from mmio accesses
    from .mmio_fuzz import mem_events
    mmio_contents = {}
    for event_id, pc, mode, size, address, value in mem_events:
        aligned_addr = address & (~0xff)
        if aligned_addr not in mmio_contents:
            mmio_contents[aligned_addr] = uc.mem_read(aligned_addr, 0x100)
    """

    # Could do reg_read_batch here if that was exposed in bindings
    """
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r6 = uc.reg_read(UC_ARM_REG_R6)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    r8 = uc.reg_read(UC_ARM_REG_R8)
    r9 = uc.reg_read(UC_ARM_REG_R9)
    r10 = uc.reg_read(UC_ARM_REG_R10)
    r11 = uc.reg_read(UC_ARM_REG_R11)
    r12 = uc.reg_read(UC_ARM_REG_R12)

    lr = uc.reg_read(UC_ARM_REG_LR)
    pc = uc.reg_read(UC_ARM_REG_PC)  # retaddr
    sp = uc.reg_read(UC_ARM_REG_SP)
    xpsr = uc.reg_read(UC_ARM_REG_XPSR)
    """
    regs = collect_regs(uc)

    total_size = 0
    content_chunks = {}
    empty_page = 0x1000 * b'\0'

    # collect memory pages that are non-zero
    #for begin, end, perms in uc.mem_regions():
    for name, (begin, size, prot) in globs.regions.items():
        if name.lower().startswith("mmio"):
            debug_info("Skipping mmio region '{}': {:x}-{:x}\n".format(name, begin, begin+size),3)
            continue
        # TODO: if we at any point configure additional explicit MMIO regions in config files, we need to reflect that here
        #if any([bool((begin <= dynamic_start < end) or (begin <= dynamic_end < end)) for
        #    (dynamic_start, dynamic_end) in globs.dynamically_added_mmio_regions]):
        #    debug_info("Skipping dynamically added MMIO region {:08x}-{:08x} during state dumping\n".format(begin, end))
        #    break

        debug_info("looking at mapped region {:s}: 0x{:08x}-0x{:08x}\n".format(name, begin, begin+size),3)
        payload = uc.mem_read(begin, size)

        cursor = 0
        start = -1
        current_pl = b''
        while cursor < size:
            page = payload[cursor:cursor+0x1000]
            if page != empty_page:
                # if no region started, start one now
                if start == -1:
                    start = begin + cursor

                # add current page to region
                current_pl += page
            elif start != -1 or (cursor+0x1000 > size):
                # commit current adjacent region
                content_chunks[start] = current_pl
                total_size += len(current_pl)
                debug_info("Adding memory region of len 0x{:x} at 0x{:08x}\n".format(len(current_pl), start),3)
                start = -1
                current_pl = b''

            cursor += 0x1000

        if current_pl != b'':
            debug_info("Adding memory region of len 0x{:x} at 0x{:08x}\n".format(len(current_pl), start),3)
            content_chunks[start] = current_pl

    debug_info("Recorded current state of (mem size 0x{:x})\n".format(total_size),3)

    return regs, content_chunks


def dump_state(filename, regs, content_chunks):
    
    ih = IntelHex()

    for base_addr, contents in content_chunks.items():
        # debug_info("Adding chunk of size 0x{:x}\n".format(len(contents)))
        # f.write("0x{:08x} {}\n".format(base_addr, hexlify(contents.rstrip(b'\0')).decode()))
        ih.puts(base_addr, contents)

    with open(filename, "w") as f:
        f.write(
"""r0=0x{:x}
r1=0x{:x}
r2=0x{:x}
r3=0x{:x}
r4=0x{:x}
r5=0x{:x}
r6=0x{:x} 
r7=0x{:x}
r8=0x{:x}
r9=0x{:x}
r10=0x{:x}
r11=0x{:x}
r12=0x{:x}
lr=0x{:x}
pc=0x{:x}
ctrl=0x{:x}
sp=0x{:x}
msp=0x{:x}
psp=0x{:x}
xpsr=0x{:x}
""".format(*[regs[const] for const in uc_reg_consts]))
        debug_info("Writing ihex dump now...\n",3)
        ih.write_hex_file(f)

def dump_state_exit_hook(uc):
    global snapshot_path
    regs, content_map = collect_state(uc)
    dump_state(snapshot_path, regs, content_map)

def record_snapshot_hook(uc, address, size, user_data):
    '''
    hook snapshot store
    '''
    global snapshot_path
    global snapshot_hook
    # 1. Unicorn Engine State
    dump_state_exit_hook(uc)
    # 2. NVIC State
    nvic_state_dump(snapshot_path+'_nvic')
    uc.hook_del(snapshot_hook)

def record_snapshot(path, snapshot_point,uc):
    '''
    record snapshot
    '''
    global snapshot_path
    snapshot_path = path
    global snapshot_hook
    snapshot_hook = uc.hook_add(UC_HOOK_CODE, record_snapshot_hook, begin=snapshot_point - 1, end=snapshot_point | 1)
    my_debug_log("record_snapshot: "+path)