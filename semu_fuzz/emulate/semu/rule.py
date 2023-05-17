from ... import globs
from ...utils import get_realpath
from ...exit import do_exit
from ...log.debug import debug_info
from ..nvic import nvic_get_active, send_pending, nvic_get_pending

from .class_def import *

from unicorn.unicorn_const import *
from unicorn.arm_const import *
from random import choice
from math import ceil
import os
import re

#--------------Class Identification------------------#

def correct_addr_to_map(address, size, mode):
    '''
    peripherals' address has mapped, but firmware's read/write may isn't in the way of this map.  
    two mode (example mapped: 0x40080020, 32 bits):
    1) mode == bit: (0x40080020, 32, 'bit') to (0x40080021, 0) 
    2) mode == whole: (0x40080020, 64, 'whole') -> [(0x40080020, 0, 31), (0x40080021, 0, 31)]
    3) mode == whole: (0x40080022, 8, 'whole') -> [(0x40080020, 16, 23)]
    '''
    try:
        bit_begin = 0
        address_mapped = []
        address_raw = address
        # if address not in the map, adapt it
        while address not in RULE.regs:
            address -= 1
            bit_begin += 8
        bit_end = bit_begin + size
        # check map
        while bit_end and (bit_end >= RULE.regs[address].width):
            address_bits = RULE.regs[address].width
            address_mapped.append((address, bit_begin, address_bits - 1))
            address += address_bits >> 3
            bit_begin = 0
            bit_end -= address_bits
        # bit mode: just return the end bit
        if mode == 'bit':
            return address, bit_end
        # whole mode: return the whole map
        elif mode == 'whole':
            if address_mapped == []:
                return [(address, bit_begin, bit_end - 1)]
            return address_mapped
    except:
        # TODO: send to unmapped hook
        print('[-] Read or Write Error! Meet an address unmapped in the rule file: %s, address_raw: 0x%x, pc: %s'%(hex(address), address_raw, hex(globs.uc.reg_read(UC_ARM_REG_PC))))
        do_exit(-1)

def bit_band(address):
    '''
    return bit-band address and bit.
    example: 
    1) 0x42000000 -> (0x40000000, 0)
    2) 0x42000004 -> (0x40000000, 1)
    3) 0x42000080 -> (0x40000004, 0)
    4) 0x42400004 -> (0x40020000, 1)
    '''
    # calculate the bit of band
    bit = (address & 0x7f) >> 2
    # calculate the corresponding address
    address_index = (address & 0x1FFFFFF) >> 7
    address = (address_index << 2) | 0x40000000
    # check if the bit > the width of the address, and correct it.
    address, bit = correct_addr_to_map(address, bit, 'bit')
    return address, bit

def set_one_bit(raw, bit_shift, bit_value):
    '''
    set raw[bit_shift] = bit_value.
    '''
    raw_bit = (raw >> bit_shift) & 1
    if raw_bit != bit_value:
        raw ^= (1 << bit_shift)
    return raw

def set_some_bits(raw, bit_begin, bit_end, bits_value):
    '''
    set raw[bit_begin:bit_end] = bits_value.
    '''
    # get bit_shadow: 0x000000ff.. ^ 0xfffffff...
    bit_shadow = ((1 << bit_begin) - 1) ^ ((1 << (bit_end + 1)) - 1)
    # fix the location of bits_value
    bits_value <<= bit_begin
    value = (raw & ~bit_shadow) | (bits_value & bit_shadow)
    return value

def different_bits(value1, value2):
    """
    Returns a list of bit positions where `value1` and `value2` differ.
    Examples:
        >>> different_bits(6, 31)
        [0, 3, 4]
    """
    # XOR the two values and convert the result to binary string
    bits = bin(value1 ^ value2)[2:]
    # Count the number of bits that differ
    count = len(bits)
    # Initialize an empty list to store the positions of different bits
    different_bits_list = []
    # Loop through the binary string and find all positions where the bit is 1
    for i in range(len(bits)):
        if bits[i] == '1':
            # Add the position of the different bit to the list
            different_bits_list.append(count - i - 1)
    # Return the list of bit positions where the values differ
    return different_bits_list

def limit_change_to_bits_selected(bits, value_raw, value_after):
    '''
    set value_raw[bits] = value_after[bits]
    '''
    value_raw_protect = value_raw
    if bits != '*':
        for i in range(len(bits)):
            bit = bits[-i-1]
            value_raw = set_one_bit(value_raw, bit, (value_after >> i) & 1)
        value_after = value_raw
    return value_raw_protect, value_after

def get_field_value(field, value=None):
    '''
    value==0: get the value of reg field.  
    value!=0: get the bits of value, the bits are involved in field.
    '''
    if value != None:
        pass
    elif 'R' in field.type:
        reg = RULE.regs[field.phaddr].value
        if field.type == '#R':
            return reg.r_size
        elif field.type in ['*R','VR']:
            value = reg.r_value
        else:
            # just occur when code has bug
            print('[-] Code has bug! Strange Reg type: %s' % field.type)
            do_exit(-1)
    elif 'T' in field.type:
        reg = RULE.regs[field.phaddr].value
        if field.type == '#T':
            return reg.t_size
        elif field.type in ['*T','VT']:
            value = reg.t_value
        else:
            # just occur when code has bug
            print('[-] Code has bug! Strange Reg type: %s' % field.type)
            do_exit(-1)
    else:
        value = RULE.regs[field.phaddr].value
    
    if field.bits == '*':
        return value
    else:
        value_raw = value
        value = 0
        for i in range(len(field.bits)):
            bit = field.bits[-i-1]
            bit_value = (value_raw >> bit) & 1
            value |= (bit_value << i)
        return value

def set_field_value(field, value, name=''):
    '''
    reg[field] = value, value=0/1.
    '''
    reg_value = RULE.regs[field.phaddr].value
    for bit in field.bits:
        reg_value = set_one_bit(reg_value, bit, value)
    size_ = RULE.regs[field.phaddr].width>>3
    RULE.regs[field.phaddr].value = reg_value
    globs.uc.mem_write(field.phaddr, reg_value.to_bytes(size_, 'little'))
    debug_info("{}\t==> Peripheral set: address: {}, bits: {}, set_value: {}, full_value: {}, size: {}, is_data_reg: False.\n".format(name, hex(field.phaddr), field.bits, value, hex(reg_value), size_), 2)
    deal_rule_RWVB(field.phaddr, 'V')


def compare(a1, eq, a2):
    if (eq == "*"):
        return True
    if (eq == "="):
        return a1 == a2
    if (eq ==  ">"):
        return a1 > a2
    if (eq ==  "<"):
        return a1 < a2
    if (eq ==  ">="):
        return a1 >= a2
    if (eq ==  "<="):
        return a1 <= a2
    return False

#------------------------------------------#

def emit_dma(dma):
    uc = RULE.uc
    # if disable, don't emit_dma.
    if dma.state == 0: 
        return False
    # random choose one memo field.
    memo_field = choice(dma.memo_field)
    # get the really addr from regs
    peri_addr = get_field_value(dma.peri_field)
    memo_addr = get_field_value(memo_field)
    debug_info("Active dma(%d) peri_reg: %s, memo reg: %s, peri_addr: %s, memo_addr: %s, state: %d.\n"%(dma.dma_irq, hex(dma.peri_field.phaddr), hex(memo_field.phaddr), hex(peri_addr), hex(memo_addr), dma.state), 1)
    # if the really addr is 0, don't emit_dma.
    if peri_addr == 0 or memo_addr == 0:
        return False
    if peri_addr not in RULE.data_regs:
        print("[-] Emit DMA Error! DMA Periphral %s Not a Data Reg." % hex(peri_addr))
        do_exit(-1)
    # if state=1, active the first dma_irq.
    if dma.state == 1:
        # push 0 into peri_addr until its size equal 64*8.
        data_reg = RULE.regs[peri_addr].value
        data_reg.r_fifo += [0] * (64 - (data_reg.r_size >> 3))
        data_reg.r_size = len(data_reg.r_fifo) * 8
        # set flag: htif=1, gif=1.
        set_field_value(dma.HTIF, 1, 'HTIF')
        if dma.GIF != 'N/A':
            set_field_value(dma.GIF, 1, 'GIF')
        # pend irq.
        send_pending(RULE.uc, dma.dma_irq + 0x10)
        # set state=half complete.
        dma.state = 2
    # if state=2, active the second dma_irq.
    elif dma.state == 2:
        # set flag: htif=0, tcif=1, gif=1.
        set_field_value(dma.HTIF, 0, 'HTIF')
        set_field_value(dma.TCIF, 1, 'TCIF')
        if dma.GIF != 'N/A':
            set_field_value(dma.GIF, 1, 'GIF')
        # clear peri_addr.
        data_reg = RULE.regs[peri_addr].value
        data_reg.r_fifo = []
        data_reg.r_size = 0
        # pend irq.
        send_pending(RULE.uc, dma.dma_irq + 0x10)
        # set state=disabled.
        dma.state = 0
    deal_rule_RWVB(peri_addr, 'B')
    return True

def take_action(actions, rule_type, debug=False):
    '''
    take action of rule.
    '''
    debug_info("======> Match rule: {}\n".format(debug), 3)
    # pending IRQ
    irq = actions[0].interrupt
    if irq != 0 and (nvic_get_pending(irq) == False):
        debug_info("======> Take Action: IRQ(%d)\n"%(irq-0x10), 3)
        send_pending(RULE.uc, irq)
    dma_irq = actions[0].dma_irq
    if dma_irq != 0:
        dma_list = RULE.dma[dma_irq]
        # prevent repeat emit dma
        for dma in dma_list:
            if dma.state != 0: 
                return
        debug_info("======> Take Action: DMA(%d)\n"%(dma_irq), 3)
        if dma_irq not in RULE.dma:
            print("[-] DMA Activative Error! DMA(%d) Not in rule txt." % dma_irq)
            do_exit(-1)
        for dma in dma_list:
            if dma.state == 0:
                dma.state = 1
            emit_dma(dma)
    # execute action
    for action in actions:
        # get a1.value
        value1 = get_field_value(action.a1)
        # get a2.value
        if action.type_a2 == 'F':
            field = action.a2_field
            value2 = get_field_value(field)
        elif action.type_a2 == 'V':
            value2 = action.a2_value
        # set a2.value to a1
        if value1 != value2:
            debug_info("======> Take Action: 0x%x, %s->%s\n"%(action.a1.phaddr, bin(value1), bin(value2)), 3)
            if action.a1.phaddr not in RULE.data_regs:
                # limit change to bits selected
                value_raw = RULE.regs[action.a1.phaddr].value
                value_raw, value2 = limit_change_to_bits_selected(action.a1.bits, value_raw, value2)
                # write back to phaddr
                RULE.regs[action.a1.phaddr].value = value2
                try:
                    RULE.uc.mem_write(action.a1.phaddr, value2.to_bytes(RULE.regs[action.a1.phaddr].width >> 3, 'little'))
                except OverflowError as e:
                    print("[-] Not Acceptable Rule Action! Error: %s. 0x%x.width=%d, But the action try to set value %d in it."%(e, action.a1.phaddr, RULE.regs[action.a1.phaddr].width, value2))
                    do_exit(-1)
            else: # special handler for data_regs
                if action.a1.type == '#R':
                    data_reg = RULE.regs[action.a1.phaddr].value
                    data_reg.r_size = value2
                    a1_fifo = data_reg.r_fifo
                    # push value into a1_fifo
                    if (len(a1_fifo) <= int(value2/8)):
                        print("[-] Not Acceptable Rule Action! Error: (fifo.size != size) or (to add unknown value). Action Reg: %s" % hex(action.a1.phaddr))
                        do_exit(-1)
                    # pop value from a1_fifo
                    while(len(a1_fifo) > int(value2/8)):
                        a1_fifo = a1_fifo[1:]
                    data_reg.r_fifo = a1_fifo
                elif 'T' in action.a1.type:
                    pass
                else:
                    # just occur when code has bug
                    print("[-] Code has Bug! Unknown action!")
                    do_exit(-1)
            # once any change, check rule v
            deal_rule_RWVB(action.a1.phaddr, 'B', action.a1.bits)
            deal_rule_RWVB(action.a1.phaddr, 'V', action.a1.bits)
        # if value hasn't change, but it is in 'B' rule, still need to check the V rule of the address of action again, to deplete the receive buffer.
        elif rule_type == 'B':
            deal_rule_RWVB(action.a1.phaddr, 'V')

def deal_rule_O(phaddr=None):
    if phaddr == None:
        for addr, rules in RULE.rules['O'].items():
            for rule in rules:
                take_action(rule[1], 'O')
    else:
        try:
            rules = RULE.rules['O'][phaddr]
        except:
            return
        for rule in rules:
            take_action(rule[1], 'O')

def deal_rule_RWVB(address, rule_type, limit_bits='*'):
    '''
    if limit_bits is set,
    only deal with the rule contain 'address,limit_bits'.
    '''
    try:
        rules = RULE.rules[rule_type][address]
    except:
        return -1
    for rule in rules:
        if limit_bits != '*' and not len([trigger for trigger in rule[0] if trigger.a1.phaddr == address and len((set(trigger.a1.bits) & set(limit_bits)))]):
            continue
        for trigger in rule[0]:
            # get a1.value
            value1 = get_field_value(trigger.a1)
            # get a2.value
            if trigger.type_a2 == 'F':
                value2 = get_field_value(trigger.a2_field)
            elif trigger.type_a2 == 'V':
                value2 = trigger.a2_value
            # a2.value == '*' then don't compare
            if value2 != "*" and not compare(value1, trigger.eq, value2):
                break
        # if no break, take action.
        else:
            if globs.args.debug_level > 2:
                # log the actions of rule.
                take_action(rule[1], rule_type, rule[2])
            else:
                take_action(rule[1], rule_type)

def deal_rule_L(address, cur_dp_addr=None):
    uc = RULE.uc
    try:
        rules = RULE.rules["L"][address]
    except:
        return -1
    if cur_dp_addr != None:
        ret = 0
        for rule in rules:
            for action in rule[1]:
                # get RDES_adddr
                RDES_index = action.a1.phaddr
                action_address = cur_dp_addr + RDES_index
                # get value
                value_raw = int.from_bytes(uc.mem_read(action_address, 4), 'little')
                value2 = action.a2_value
                action_size = 4
                # write to the descriptor
                if address in ['E', 'F', 'O']:
                    # limit change to bits selected
                    value_raw, value2 = limit_change_to_bits_selected(action.a1.bits, value_raw, value2)
                    if value_raw != value2:
                        uc.mem_write(action_address, value2.to_bytes(action_size, 'little'))
                        # log the actions of rule L.
                        debug_info("======> Take Action: 0x%x, %s->%s\n"%(action_address, bin(value_raw), bin(value2)), 3)
                # check the descriptor
                elif address == 'C':
                    value1 = get_field_value(action.a1, value_raw)
                    # fail to check
                    if not compare(value1, action.eq, value2):
                        ret = 1
                        # log the actions of rule L.
                        debug_info("======> Failed to Match rule: {}".format(rule[2]), 3)
                        debug_info("\t| Action: return error.\n", 3)
        return ret
    for rule in rules:
        for trigger in rule[0]:
            # the address in L rule is the value in address
            trigger_address = RULE.regs[trigger.a1.phaddr].value
            trigger_size = RULE.regs[trigger.a1.phaddr].data_width >> 3
            # get a1.value
            value1 = get_field_value(trigger.a1, int.from_bytes(uc.mem_read(trigger_address, trigger_size), "little"))
            # get a2.value
            value2 = trigger.a2_value
            if not compare(value1, trigger.eq, value2):
                break 
        else: # reach the end of for, then take action 
            for action in rule[1]:
                # the address in L rule is the value in address
                action_address = RULE.regs[action.a1.phaddr].value
                action_size = RULE.regs[action.a1.phaddr].data_width >> 3
                # get the value of a1 and a2
                value_raw = int.from_bytes(uc.mem_read(action_address, action_size), "little")
                value1 = get_field_value(action.a1, value_raw)
                value2 = action.a2_value
                # set a2.value to a1
                if value1 != value2:
                    # log the actions of rule RWVB.
                    debug_info("======> Take Action: 0x%x, %s->%s\n"%(action_address, bin(value1), bin(value2)), 3)
                    # just take action of RXdescriptor
                    if 'R' in action.a1.type:
                        # limit change to bits selected
                        value1, value2 = limit_change_to_bits_selected(action.a1.bits, value_raw, value2)
                        uc.mem_write(action_address, value2.to_bytes(action_size, 'little'))
                    elif 'T' not in action.a1.type:
                        print("[-] Unknown L rule. action.a1.type: %s" % action.a1.type)
                        do_exit(-1)

def deal_rule_flag(flag_type='counter', address=None):
    if address:
        try:
            flag_dict = {address: RULE.flags[flag_type][address]}
            pass
        except:
            return
    else:
        flag_dict = RULE.flags[flag_type]
    for phaddr, flags in flag_dict.items():
        value1 = RULE.regs[phaddr].value
        value2 = value1
        for flag in flags:
            if flag.a1.phaddr in RULE.data_regs:
                print("[-] Flag Rule Error! Can't set action on data reg 0x%x" % flag.a1.phaddr)
                do_exit(-1)
            # get value1 bits
            value1_bits = get_field_value(flag.a1, value1)
            # get the value to set
            if flag_type == 'counter': # choose from 0 to value2
                value2 = int(flag.value[1:],16)
                value2 = (value1_bits + 1) % value2
            elif flag_type == 'timer': # ~ raw_value
                value2 = int(flag.value[1:],16)
                value2 ^= value1_bits
            elif flag_type == 'random': # random choose 0/1
                value2 = choice(flag.value.split('/'))
                value2 = int(value2,16)
            # limit change to bits selected
            value1, value2 = limit_change_to_bits_selected(flag.a1.bits, value1, value2)
            if value1 != value2:
                debug_info("======> Use Flag {} {}\n".format(flag_type, flag.debug_info), 3)
            # update value1
            value1 = value2
        # set value to a1
        if RULE.regs[phaddr].value != value2:
            debug_info("======> Take Action: 0x%x, %s->%s\n"%(flag.a1.phaddr, bin(RULE.regs[phaddr].value), bin(value2)), 3)
            changed_bits= different_bits(RULE.regs[phaddr].value, value2)
            RULE.regs[phaddr].value = value2
            RULE.uc.mem_write(phaddr, value2.to_bytes(int(RULE.regs[phaddr].width/8), 'little'))
            deal_rule_RWVB(phaddr, 'V', changed_bits)
            # deal_rule_RWVB(phaddr, 'B')
        
#------------------------------------------#

def hardware_write_to_receive_buffer(data_reg, phaddr, value_queue):
    '''
    hardware write to data_reg's receive buffer.
    '''
    data_reg.r_fifo += value_queue
    data_reg.r_size = len(data_reg.r_fifo) * 8
    # deal_rule_RWVB(phaddr, 'W') # the write rule means the writing of firmware.
    deal_rule_RWVB(phaddr, 'V') 
    deal_rule_RWVB(phaddr, 'B')

def hardware_write_to_receive_buffer_list(data_regs_list, value):
    '''
    hardware write to a list of data_regs' receive buffer.
    '''
    for address in data_regs_list:
        # write value into receive buffer
        data_reg = RULE.regs[address].value
        debug_info("hardware_write_to_receive_buffer: {}, {}\n".format(hex(address), value), 2)
        hardware_write_to_receive_buffer(data_reg, address, value)
        deal_rule_O(address) # once any change, reset by O
    

def hardware_write_to_descriptor(buffer_input):
    '''
    write buffer_input to the descriptor of the ETH.
    '''
    # get desciptor phaddr address
    cur_dp_addr = RULE.cur_dp_addr
    if cur_dp_addr == 0:
        print("[-] ETH Function Error! Write to descriptor when descriptor address hasn't been init.")
        do_exit(-1)
    else:
        debug_info("Start writing to descriptor phaddr 0x%x\n" % cur_dp_addr, 1)
    # calculate the count of desciptors to use for this buffer_input
    uc = globs.uc
    buffer_input_size = len(buffer_input)
    count = ceil(buffer_input_size / 1524) # TODO: what is the meaning of 1524?
    frame_size = 0
    if count > 3: # max count is 3
        count = 3
    # record current descriptors
    descriptor_list = []
    # write buffer_input into descriptor 
    for i in range(count):
        descriptor_list.append(cur_dp_addr)
        buffer_input_size = len(buffer_input)
        RDES = [0,0,0,0]
        for ii in range(4):
            RDES[ii] = int.from_bytes(uc.mem_read(cur_dp_addr + 4*ii, 4), 'little')
            debug_info("==> write start, descriptor RDES%d(0x%x)\n"%(ii, RDES[ii]), 1)
        # check RDES
        ret = deal_rule_L('C', cur_dp_addr)
        if ret != 0:
            # Cannot write to RDES0 or RDES2 because it hasn't been init, return.
            debug_info("[WARN] Cannot write to RDES0 or RDES2 because it hasn't been init, when cur_dp_addr: 0x%x.\n" % cur_dp_addr, 1)
            # just set not init to wait next write
            RULE.init_dp_addr_flag = False
            globs.config.fork_point_times = globs.config.fork_point_times + 1
            return
        # first RDES
        if i == 0:
            deal_rule_L('F', cur_dp_addr)
            # buffer 1 maximum size
            # maximum_size = 0x1FFF & RDES1;
            # ETH_DMARXDESC_FL add 32 to current frame
            frame_size = buffer_input_size
        # end RDES
        if i == count - 1:
            deal_rule_L('E', cur_dp_addr)
        # any RDES
        deal_rule_L('O', cur_dp_addr)
        RDES[0] = RDES[0] + (frame_size << 16)
        if buffer_input_size > 1524:
            # RBS1: Receive buffer 1 size
            RDES[1] = RDES[1] & 0xFFFFE5F4 # cur desc size 32
        else:
            RDES[1] = (RDES[1] & 0xFFFFE000) + buffer_input_size
        # buffer content
        cnt = 0
        if buffer_input_size > 1524:
            cnt = 1524
        else:
            cnt = buffer_input_size
        # write to RDES2
        for j in range(cnt):
            content = buffer_input[0]
            uc.mem_write(RDES[2] + j, content.to_bytes(1, 'little'))
            buffer_input = buffer_input[1:]
        uc.mem_write(cur_dp_addr, RDES[0].to_bytes(4, 'little'))
        uc.mem_write(cur_dp_addr + 4, RDES[1].to_bytes(4, 'little'))
        for ii in range(4):
            debug_info("==> write end, descriptor RDES%d(0x%x)\n"%(ii, RDES[ii]), 1)
        cur_dp_addr = RDES[3]
    RULE.cur_dp_addr = cur_dp_addr
    deal_rule_L(RULE.RXdescriptor)
    deal_rule_L("*", descriptor_list)

def firmware_write_to_transmit_buffer(data_reg, phaddr, value):
    '''
    firmware will write to data_reg's transmit buffer.
    '''
    data_reg.t_size = 0 # transmit to hardware immediately
    data_reg.t_value = value

    # special patch for some elf(TODO: maybe replace this part with uEmu)
    need_patch = True
    if value == 0xAAFA:
        r_fifo = [0x4F, 0x4B, 0x0D, 0x0A]
    # Patch the [DP83848_Init] of LwIP_UDP_Echo_Server.elf
    elif (phaddr == 0x40028014 and value == 0x8000):
        r_fifo = [0x4]
    # TODO: Patch ELF Unknown.
    elif (phaddr == 0x40028014 and value == 0x1000):
        r_fifo = [0x20]
    # Patch ELF ETH/LwIP_UDP_Echo_Server.elf
    elif (phaddr == 0x40005410 and value == 0x84): 
        r_fifo = [0x0, 0x16]
        for i in range(64):
            r_fifo += [0x1]
    else:
        need_patch = False
    # patch the r_fifo
    if need_patch:
        data_reg.r_fifo = r_fifo
        data_reg.r_size = len(r_fifo) << 3


def get_value_from_receive_buffer(data_reg, phaddr, size):
    '''
    return a value of data_reg's receive buffer.
    '''
    value = 0
    try:
        for i in range(size):
            value = (data_reg.r_fifo[0] << (8*i)) | value
            data_reg.r_fifo = data_reg.r_fifo[1:]
    except:
        pass
    if len(data_reg.r_fifo) == 0 and len(data_reg.user_r_fifo):
        data_reg.r_fifo = data_reg.user_r_fifo[:4]
        data_reg.user_r_fifo = data_reg.user_r_fifo[4:]
    data_reg.r_size = len(data_reg.r_fifo) * 8
    # if in irq, don't exit, because this data will be used after irq.
    # if in systick, still exit.
    if data_reg.r_size == 0:
        if nvic_get_active() == 0 or nvic_get_active() == 0xf:
            debug_info("[+] no data in 0x%x, need to exit.\n" % phaddr, 1)
            do_exit(0)
    data_reg.r_value = value
    return value


def readHook(uc, access, address, size, value, user_data):
    '''
    hook firmware read to peripheral.
    '''
    # only active when enable bit band
    if globs.config.enable_bitband and (address >= 0x42000000 and address <= 0x43ffffff):
        address_raw = address
        address, bit_shift = bit_band(address)
        # TODO: the code below hasn't been executed and tested.
        # get value and the bit of value
        value_band = RULE.regs[address].value
        value = (value_band >> bit_shift) & 1
        # match read(R) rule.
        deal_rule_flag('random', address)
        deal_rule_RWVB(address, 'R')
        # write back to the address_raw
        uc.mem_write(address_raw, value.to_bytes(4, 'little'))
        debug_info("==> Peripheral read: address: 0x%x, value: %d; bitband address: 0x%x, bit: %d, value: 0x%x.\n" % (address_raw, value, address, bit_shift, value_band), 2)
        return
    # correct address to the address map
    addr_mapped = correct_addr_to_map(address, size<<3, 'whole')
    for mapped in addr_mapped:
        address, bit_begin, bit_end = mapped
        # for data regs
        if address in RULE.data_regs:
            data_reg = RULE.regs[address].value
            # only get non-reserved fields
            size = RULE.regs[address].data_width >> 3
            value = get_value_from_receive_buffer(data_reg, address, size)
            # the change of receive buffer may match rules.
            deal_rule_O(address)
            deal_rule_flag('random', address)
            deal_rule_RWVB(address, 'V')
            deal_rule_RWVB(address, 'B')
            # record the data_reg read in irq
            if nvic_get_active() != 0 and address not in RULE.data_regs_in_irq:
                RULE.data_regs_in_irq.add(address)
                RULE.data_regs_in_irq_size[address] = size
            debug_info("==> Peripheral read: address: 0x%x, value: 0x%x, bits_value: 0x%x, bits: (%d, %d), is_data_reg: True.\n" % (address, value, value, bit_begin, bit_end), 2)
        # for not data regs
        else:
            value = RULE.regs[address].value
            size = RULE.regs[address].width >> 3
            debug_info("==> Peripheral read: address: 0x%x, value: 0x%x, size: (%d, %d), is_data_reg: False.\n" % (address, value, bit_begin, bit_end), 2)
        # write the saved value into uc.
        uc.mem_write(address, value.to_bytes(size, 'little'))
        # match read(R) rule.
        deal_rule_flag('random', address)
        deal_rule_RWVB(address, 'R')
            

def writeHook(uc, access, address, size, value, user_data):
    '''
    hook firmware write to peripheral.
    '''
    is_bitband = 0
    # Only active when enable bit band.
    if globs.config.enable_bitband and (address >= 0x42000000 and address <= 0x43ffffff):
        address_raw = address
        address, bit_shift = bit_band(address)
        # TODO: the code below hasn't been executed and tested.
        # get value
        value1 = RULE.regs[address].value
        value2 = set_one_bit(value1, bit_shift, value)
        # write to reg
        RULE.regs[address].value = value2
        # write into uc
        uc.mem_write(address, value2.to_bytes(size, 'little'))
        # deal with rule
        deal_rule_flag('random', address)
        deal_rule_RWVB(address, 'W') # whether value change or not
        if value1 != value2:
            changed_bits= different_bits(value1, value2)
            deal_rule_O(address) # once any change, reset by O
            deal_rule_RWVB(address, 'V', changed_bits) # when value change
        debug_info("==> Peripheral write: address: 0x%x, value: %d; bitband address: 0x%x, bit: %d, value: 0x%x.\n" % (address_raw, value, address, bit_shift, value2), 2)
        return
    # Correct addr and value to addr_map.
    addr_mapped = correct_addr_to_map(address, size<<3, 'whole')
    value_bytes = value.to_bytes(size, 'little')
    for mapped in addr_mapped:
        address, bit_begin, bit_end = mapped
        # get some bytes from value_bytes 
        size = (bit_end - bit_begin + 1) >> 3
        value = int.from_bytes(value_bytes[0:size],'little')
        value_bytes = value_bytes[size:]
        # data_regs
        if address in RULE.data_regs: 
            data_reg = RULE.regs[address].value
            value1 = data_reg.t_value
            value2 = set_some_bits(value1, bit_begin, bit_end, value)
            # write to transmit buffer
            firmware_write_to_transmit_buffer(data_reg, address, value2)
            value2 = -1
        # not data_regs
        else: 
            value1 = RULE.regs[address].value
            value2 = set_some_bits(value1, bit_begin, bit_end, value)
            # write to reg
            RULE.regs[address].value = value2
            uc.mem_write(address, value2.to_bytes(RULE.regs[address].width>>3, 'little'))
            debug_info("==> Peripheral write: address: 0x%x, value: 0x%x, bits_value: 0x%x, bits: (%d, %d), is_data_reg: False.\n" % (address, value2, value, bit_begin, bit_end), 2)
        deal_rule_flag('random', address)
        deal_rule_RWVB(address, 'W') # whether value change or not
        if value1 != value2:
            changed_bits= different_bits(value1, value2)
            deal_rule_O(address) # once any change, reset by O
            deal_rule_RWVB(address, 'V', changed_bits) # when value change
            deal_rule_RWVB(address, 'B') # when value change, don't care changed_bits
            
def blockHook(uc, address, size, user_data):
    # every INTERRUPT_INTERVAL blocks, update flag and write into receive buffer
    if (globs.block_count % globs.INTERRUPT_INTERVAL) == 0 :
        # update flag
        deal_rule_flag('counter')

def forkpointHook(uc, address, size, user_data):
    '''
    when fork point(the end of the main loop).
    '''
    deal_rule_flag('timer')
    RULE.meet_forkpoint = True
    # init RULE.RXdescriptor for the periphral which has ETH descriptor.
    if RULE.RXdescriptor and RULE.regs[RULE.RXdescriptor].is_eth and not RULE.init_dp_addr_flag:
        RULE.cur_dp_addr = RULE.regs[RULE.RXdescriptor].value
        if RULE.cur_dp_addr:
            RULE.init_dp_addr_flag = True
            # init the value of descriptor
            hardware_write_to_descriptor(globs.user_input)
            debug_info('init descriptor address: 0x%x\n' % RULE.cur_dp_addr, 1)
        
def beginpointHook(uc, address, size, user_data):
    ''' put user_input at the begin point. '''
    # # try to set fork_point_times related to user_input in the future
    globs.config.fork_point_times = len(globs.user_input)>>2 # will change it in the future
    # just write 4 bytes
    hardware_write_to_receive_buffer_list(RULE.data_regs, globs.user_input[:4])
    # tmp store other user input
    for data_reg in RULE.data_regs:
        RULE.regs[data_reg].value.user_r_fifo = globs.user_input[4:]
    uc.hook_del(RULE.beginpointHook_handler)

def exceptionexitHook(uc, intno, size):
    # deal_rule_flag('timer')
    pass
#------------------------------------------#

def rules_configure(uc, path):
    RULE.configure(uc, path)

class RULE():
    uc = None
    regs = {} # paddr->Reg
    data_regs = set() # paddr
    data_regs_in_irq = set() # paddr used in interrupt
    data_regs_in_irq_size = {} # size used in interrupt
    # ca_rules = {} # paddr->
    rules = {
        'W':{},
        'R':{},
        'B':{},
        'V':{},
        'L':{},
        'O':{}
    } # type->{paddr->(triggers, actions)}
    irq = []
    dma_irq = []
    # paddr->flag
    flags = {
        'counter': {},
        'timer': {},
        'random': {}
    }
    dma = {} # dma_irq->DMA
    RXdescriptor = 0 # ETH_DMARDLAR Receive descriptor list
    init_dp_addr_flag = False # whether the dscriptor addr is init.
    cur_dp_addr = 0 # current descriptor addr
    start_continuous_input = False
    start_descriptor_input = False
    raw_user_input = []

    meet_forkpoint = False
    beginpointHook_handler = None
    hit_hook = 0
    
    @classmethod
    def readNLPModelfromFile(ru, uc, path):
        def get_indexAll(lst=None, item=''):
            ''' from lst, get all the index of value '''
            return [i for i in range(len(lst)) if lst[i] == item]
        
        def parse_bits(bit_value, value_type=10):
            ''' parse bit_value to bit_list '''
            if bit_value == '*':
                return bit_value
            else:
                bit_list = [int(x, value_type) for x in re.findall(r'\d+', bit_value)]
                return bit_list

        def parse_paddr(paddr_str):
            ''' parse paddr_str to paddr_type, paddr '''
            # #R/*R/#L
            if paddr_str[0] in ['#', '*']:
                return paddr_str[0:2], int(paddr_str[2:], 16)
            # 0x00000000
            if paddr_str[0:2] == '0x':
                paddr = int(paddr_str,16)
                if paddr in RULE.data_regs:
                    return 'V' + RULE.regs[paddr].type, paddr
                else:
                    return '*', paddr
            # ETH RDES index
            return 'E', int(paddr_str, 16)
        
        def parse_interrupts(actions):
            ''' parse the interrupt information from actions to irq, is_dma '''
            interrupt_dict = {
                'IRQ': {'base': 0x10, 'is_dma': False},
                'DMA': {'base': 0x00, 'is_dma': True}
            }
            regex = re.compile(r'&(\w+)\((\d+)\)')
            matches = regex.findall(actions)
            for match in matches:
                interrupt_type, interrupt_number = match
                base = interrupt_dict[interrupt_type]['base']
                is_dma = interrupt_dict[interrupt_type]['is_dma']
                if is_dma:
                    interrupt = int(interrupt_number, 10)
                else:
                    interrupt = int(interrupt_number, 10) + base
                actions = actions.replace('&{}({})'.format(interrupt_type, interrupt_number), '')
                return actions, interrupt, is_dma
            return actions, 0, False # no match

        def extractEqu(expressions, interrupt, typ = 'trigger', is_dma=False):
            ''' extract Equation form expressions. '''
            split_chr = '&'
            res = []
            exp_format = {
                'trigger': ['type','paddr','bit','eq','value'],
                'action': ['paddr', 'bit', 'eq', 'value']
            }
            for v in expressions.split(split_chr):
                v = v.split(',')
                f = exp_format[typ]
                # eg: O,*->0x40021004,3/2,=,0x40021004,1/0
                if len(f) < len(v):
                    # if action value is field.
                    f.append('a2_bits')
                v = dict(zip(f, v))
                equ = Equation(0, interrupt) if is_dma else Equation(interrupt, 0)
                # default type is 'A'
                if 'type' in v.keys():
                    equ.type_eq = v['type'][0]
                # eg: O,*->0x400ea016,*,=,#R0x400ea007 / LO,*->0,31,=,0
                if v['paddr'] == '*': 
                    equ.a1.bits = '*'
                    # to record the special rule type, like LC,LO
                    if len(v['type']) > 1:
                        equ.a1.phaddr = v['type'][1:]
                    res.append(equ)
                    continue
                equ.a1.type, equ.a1.phaddr = parse_paddr(v['paddr'])
                equ.a1.bits = parse_bits(v['bit'])
                equ.eq = v['eq']
                # eg: value: #R0x400ea007
                if '0x' in v['value']:
                    equ.type_a2 = 'F'
                    equ.a2_field.type, equ.a2_field.phaddr = parse_paddr(v['value'])
                    if 'a2_bits' in v.keys():
                        equ.a2_field.bits = parse_bits(v['a2_bits'])
                # eg: value: 0010101011
                elif (v['value'] != '*'): 
                    equ.type_a2 = "V"
                    equ.a2_value = int(v['value'],2)
                res.append(equ)
            return res

        def recordRule(paddr, rule):
            ''' record rule with two keys, rule_type and paddr. '''
            rule_type = rule[0][0].type_eq
            try:
                if rule != ru.rules[rule_type][paddr][-1]: # avoid to add one rule twice
                    ru.rules[rule_type][paddr].append(rule)
            except:
                ru.rules[rule_type][paddr] = [rule]

        def readInit(lines):
            ''' the first part of rule: paddr init. '''
            for line in lines:
                line = line.split('_')
                typ = line[0] # type
                phaddr = int(line[1], 16)
                value = int(line[2],16)
                width = int(line[3],10)
                data_width = int(line[4],10)
                is_eth = False

                if 'E' in typ: # ethernet
                    is_eth = True

                typ_0 = typ[0]
                
                # just record the last L reg as ETH_DMARDLAR
                if typ_0 == 'L': 
                    ru.RXdescriptor = phaddr
                    continue
                
                # data_reg
                if typ_0 in ['R', 'T']: 
                    # just record the first type
                    if phaddr not in ru.data_regs: 
                        ru.regs[phaddr] = Reg(typ_0, data_width, width, DataReg(), is_eth)
                    # data reg set
                    ru.data_regs.add(phaddr)
                    continue

                # other regs
                ru.regs[phaddr] = Reg(typ_0, data_width, width, value, is_eth)
                uc.mem_write(phaddr, value.to_bytes(width>>3, 'little'))

        def readCA(lines):
            ''' the second part of rule: CA rule. '''
            for line in lines:
                # ignore split line 
                if line == '--':
                    continue
                triggers, actions = line.split('->')
                # parse interrupt(IRQ(x) or DMA(x))
                actions, interrupt, is_dma = parse_interrupts(actions)
                # parse triggers and actions
                triggers = extractEqu(triggers, interrupt, 'trigger')
                actions = extractEqu(actions, interrupt, 'action', is_dma)
                rule = (triggers, actions)
                # (debug_level > 2) record rule raw_str
                if globs.args.debug_level > 2: 
                    rule = rule + (line,)
                # record rules by the paddr in triggers and actions
                for equ in triggers:
                    # don't record the trigger of O rule.
                    if equ.eq == '*' and equ.type_eq == 'O':
                        continue
                    # by a1 phaddr
                    recordRule(equ.a1.phaddr, rule)
                    # by a2 phaddr
                    if equ.type_a2 == 'F':
                        recordRule(equ.a2_field.phaddr, rule)
                for equ in actions:
                    # don't record the action of ETH rule.
                    if equ.a1.type == 'E':
                        continue
                    # don't record the action of R/W rule
                    if triggers[0].type_eq in ['R','W']:
                        continue
                    # by a1 phaddr
                    recordRule(equ.a1.phaddr, rule)
                    ## by a2 phaddr
                    if equ.type_a2 == 'F':
                        recordRule(equ.a2_field.phaddr, rule)

        def readFlag(lines):
            ''' the third part of rule: flag. '''
            exp_format = ['phaddr','bit','eq','value']
            O_trigger = Equation()
            O_trigger.type_eq = 'O'
            for line in lines:
                if line == '--':
                    continue
                exp = dict(zip(exp_format, line.split('->')[1].split(',')))
                typ, addr = parse_paddr(exp['phaddr'])
                bits = parse_bits(exp['bit'])
                a1_Field = Field(typ, addr, bits)
                value = exp['value']
                # flag
                if '^' in value: # +1 when trigger
                    flag_type = 'counter'
                elif '|' in value: # timer
                    flag_type = 'timer'
                elif '/' in value: # random choose 0/1
                    flag_type = 'random'
                else: # O rule
                    O_action = Equation()
                    O_action.a1 = a1_Field
                    O_action.eq = '='
                    O_action.a2_value = int(value, 16)
                    rule = ([O_trigger], [O_action])
                    # (debug_level > 2) record rule raw_str
                    if globs.args.debug_level > 2: 
                        rule = rule + (line,)
                    recordRule(addr, rule)
                    continue
                new_flag = Flag(a1_Field, value)
                # (debug_level > 2) record rule raw_str
                if globs.args.debug_level > 2:
                    new_flag.debug_info = line
                try:
                    ru.flags[flag_type][addr].append(new_flag)
                except:
                    ru.flags[flag_type][addr] = [new_flag]

        def readDMA(lines):
            ''' the fourth part of rule: DMAtas. '''
            def getField(addr_str):
                addr, bit = addr_str.split(',')
                return Field(*parse_paddr(addr), parse_bits(bit))
            exp_format = ['dma_irq','memo_field','peri_field', 'size_field', 'HTIF','TCIF','GIF']
            for line in lines:
                exp = dict(zip(exp_format, line.split(';')))
                if exp['GIF'] == '':
                    gif = 'N/A'
                else:
                    gif = getField(exp['GIF'])
                new_dma = DMA(int(exp['dma_irq']),
                                  [getField(m) for m in exp['memo_field'].split('|')],
                                  getField(exp['peri_field']),
                                  getField(exp['size_field']),
                                  getField(exp['HTIF']),
                                  getField(exp['TCIF']),
                                  gif)
                try:
                    ru.dma[int(exp['dma_irq'])].append(new_dma)
                except:
                    ru.dma[int(exp['dma_irq'])] = [new_dma]

        def load_path(path): 
            ''' load file path and return content ''' 
            path = get_realpath(globs.args.config_file, path) 
            if not os.path.exists(path):
                print("[-] Rule Configure Error! File Not Exists: %s" % path)
                do_exit(-1)
            with open(path, 'r') as fp:
                return fp.read()
        
        # load rule path
        fileContent = load_path(path)
        rule_lines = fileContent.splitlines()
        i = 0

        # deal with three rule parts
        splits_index = get_indexAll(rule_lines, '==')
        readInit(rule_lines[0:splits_index[0]])
        readCA(rule_lines[splits_index[0]+1:splits_index[1]])
        readFlag(rule_lines[splits_index[1]+1:splits_index[2]])
        # (optional) DMAtas part
        if len(splits_index) > 3:
            readDMA(rule_lines[splits_index[2]+1:splits_index[3]])

    @classmethod
    def configure(ru, uc, path):
        ru.uc = uc
        # read rules
        ru.readNLPModelfromFile(uc, path)

        # # write two bits to identify data_regs_in_irq
        # hardware_write_to_receive_buffer_list(ru.data_regs, [0xA, 0xA])

        # add read/write hook
        uc.hook_add(UC_HOOK_MEM_READ, readHook,
        user_data=ru,
        begin=0x40000000, end=0x5fffffff)
        uc.hook_add(UC_HOOK_MEM_WRITE, writeHook,
        user_data=ru,
        begin=0x40000000, end=0x5fffffff)

        # add block hook
        uc.hook_add(UC_HOOK_BLOCK, blockHook)

        # add fork_point hook
        for fork_point in globs.config.fork_points:
            uc.hook_add(UC_HOOK_CODE, forkpointHook, begin=fork_point, end=fork_point)

        # Listen for interrupt return or SVC
        uc.hook_add(UC_HOOK_INTR, exceptionexitHook)

        # add beigin_point hook to place user input
        ru.beginpointHook_handler = uc.hook_add(UC_HOOK_CODE, beginpointHook, begin=globs.config.begin_point - 1, end=globs.config.begin_point|1)

        # deal O once
        deal_rule_O()