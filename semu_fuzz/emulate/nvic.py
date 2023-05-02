from .. import globs
from ..exit import do_exit
from ..utils import load_lib

from unicorn import *
from unicorn.arm_const import *
import struct
from random import choice
import os

DEBUG_NVIC = False
native_nvic = None

#------------- Some Cortex M3 specific constants -------------#

# lr when exception return
EXC_RETURN = 0xfffffff0 # lr shadow
NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG = 8 # 1000(2), theadmode when enter exception
NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG = 4  # 0100(2), sp switched when enter exception
# base address to limit hook range
ICSR_BASE = 0xE000ED04 # interrupt control and state reg
VTOR_BASE = 0xE000ED08 # vector table offset reg
ISER_BASE = 0xE000E100 # interrupt set enabled reg
ICER_BASE = 0xE000E180 # interrupt clear enabled reg
ISPR_BASE = 0xE000E200 # interrupt set pending reg
ICPR_BASE = 0xE000E280 # interrupt clear pending reg
SYSTICK_CTRL = 0xE000E010 # systick control
SYSTICK_LOAD = 0xE000E014 # systick load
SYSTICK_VAL = 0xE000E018 # systick val
SYSTICK_CALIB = 0xE000E01C # systick calibration
# about vector table
PTR_SIZE = 4 # the size of one vector
# about content in the saved stack
FRAME_SIZE = 0x20 # the size of the saved frame
saved_reg_ids = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR, UC_ARM_REG_SP] # the id of saved regs
# irq num
NUM_Reset = 1 # reset handler
NUM_NMI = 2 # no maskable interrupt
NUM_HardFault = 3 # hardware fault
NUM_SVC = 11 # super visor call
NUM_PendSV = 14 # pending super visor
NUM_SYSTICK = 15 # system tick timer

#------------- User Function of nvic.py -------------#

def nvic_configure(uc, num_vecs=256, initial_vtor=0):
    '''
    call the configure of NVIC to init nvic
    '''
    if globs.config.enable_native:
        global native_nvic
        native_nvic = load_lib(os.path.join(os.path.dirname(__file__), 'native/nvic.so'))
        native_nvic.configure(uc._uch, num_vecs, initial_vtor, globs.config.enable_systick, globs.INTERRUPT_INTERVAL)
        return
    NVIC.configure(uc, num_vecs, initial_vtor)

def send_pending(uc, irq=-1, rand=False):
    '''
    when current irq is not 'irq', pending 'irq',
    if irq is not set, pending one in order.
    if rand is True, pending a rand irq.
    '''
    if globs.config.enable_native:
        native_nvic.send_pending(uc._uch, irq)
        return
    # if irq is not set, choice one to pending
    if irq == -1:
        # if no enabled irq, just return
        if len(NVIC.enable) == 0:
            return
        # if rand is True, pending a rand irq
        if rand:
            irq = choice(NVIC.enabled)
            NVIC.last_active_index = NVIC.enabled.index(irq)
        # if rand is False, pending one in order
        else:
            index = NVIC.last_active_index + 1
            # if this irq is the final one, back to the first one 
            if index >= len(NVIC.enabled):
                index = 0
            # set the next irq
            irq = NVIC.enabled[index]
            NVIC.last_active_index = index
    # # if curr_active is not irq, send pending, to prevent repeat active
    # if NVIC.curr_active != irq: # 
    # use NVIC to set pending
    NVIC.set_pending(irq)

def nvic_get_enabled():
    '''
    get the value of enabled irq list of NVIC
    '''
    # TODO: this native function is not completed, because don't know how to use pointer from c.
    # So Please don't use it now.
    if globs.config.enable_native:
        return native_nvic.nvic_get_enabled()
    return NVIC.enabeld

def nvic_get_active():
    '''
    get the value of current active irq of NVIC
    '''
    if globs.config.enable_native:
        from ctypes import c_int16
        return c_int16(native_nvic.nvic_get_active()).value
    return NVIC.curr_active

def nvic_get_pending(irq):
    '''
    get the value of pending irq list of NVIC
    '''
    if globs.config.enable_native:
        return native_nvic.nvic_get_pending(irq)
    return NVIC.vectors[irq].pending

#------------- Hook Functions -------------#

def _nvic_tick_check(uc, address, size, user_data):
    '''
    hook when block.
    every one blocks, check_pending and active
    every INTERRUPT_INTERVAL blocks, active the tick timer irq
    '''
    NVIC.check_pending()
    block = globs.block_count % globs.INTERRUPT_INTERVAL
    if block == 0 and (NUM_SYSTICK in NVIC.enabled) and globs.config.enable_systick and nvic_get_active() != NUM_SYSTICK: # SYSTICK
        send_pending(uc, NUM_SYSTICK)

def _nvic_intr_handle(uc, intno, size):
    '''
    hook when exception
    if address in lr shadow(0xfffffff0), is exit exception. 
    elif intno == 2, is syscall.
    '''
    pc = uc.reg_read(UC_ARM_REG_PC)
    # exit_exception
    if pc >= EXC_RETURN and pc <= (EXC_RETURN|0xf):
        NVIC.exit_handler(uc, pc)
    # svc 2
    elif intno == 2:
        NVIC._enter_exception(0xb)
        # TODO: check priority
        #ifndef SKIP_CHECK_SVC_ACTIVE_INTERRUPT_PRIO
        # if(nvic.active_group_prio <= nvic.ExceptionPriority[EXCEPTION_NO_SVC]):
        #     do_exit(uc, UC_ERR_EXCEPTION)
        #endif
    else:
        # Alternatives could be breakpoints and the like, which we do not handle.
        # TODO
        do_exit(-1)
        pass

def _handler_vtor_write(uc, mem_type, address, size, value, user_data):
    '''
    hook when write vector table offset reg
    '''
    # set the value of new vtor
    NVIC.set_vtor(value)
    # log debug info
    if DEBUG_NVIC:
        print("############### Changing nvic vtor to 0x{:08x}".format(value))

def _handler_icsr_write(uc, mem_type, address, size, value, user_data):
    '''
    hook when write interrupt control and state reg
    '''
    # record new value.
    NVIC.icsr |= value
    # the action of write 1.
    if(value & (1 << 25)): # PENDSTCLR
        NVIC.remove_pending(NUM_SYSTICK, -1)
    if(value & (1 << 26)): # PENDSTSET
        NVIC.set_pending(NUM_SYSTICK)
    if(value & (1 << 27)): # PENDSVCLR
        NVIC.remove_pending(NUM_PendSV, -1)
    if(value & (1 << 28)): # PENDSVSET
        NVIC.set_pending(NUM_PendSV)
    if(value & (1 << 31)): # NMIPENDSET
        NVIC.set_pending(NUM_NMI)

def _handler_state_write(uc, mem_type, address, size, value, user_data):
    '''
    hook when write ISER/ICER/ISPR/ICPR reg
    '''
    state_type = (address - ISER_BASE) >> 7
    base_address = address & 0xFFFFF800
    # caculate the irq_range corresponding to the address
    irq_begin = ((address - base_address) & 0x1f) << 3
    irq_range = size << 3
    # find the bit with the value 1 in 'value'.
    irq_list = []
    for i in range(irq_range):
        if (value>>i)&0x1:
            irq = irq_begin + i + 0x10
            irq_list.append(irq)
    if state_type == 0: # ISER
        for irq in irq_list:
            # if this bit is 1, set it enabled.
            NVIC.set_able(irq)
            if DEBUG_NVIC:
                print("############### Setting nvic #0x{:02x}.enabled to 1".format(irq))
    elif state_type == 1: # ICER
        for irq in irq_list:
            # if this bit is 1, set it disabled.
            if irq in NVIC.enabled:
                NVIC.remove_able(irq)
                if DEBUG_NVIC:
                    print("############### Setting nvic #0x{:02x}.enabled to 0".format(irq))
    elif state_type == 2: # ISPR
        for irq in irq_list:
            # if this bit is 1, and the irq is not pending, set it pending.
            if irq not in NVIC.pending:
                NVIC.set_pending(irq)
                if DEBUG_NVIC:
                    print("############### Setting nvic #0x{:02x}.pending to 1".format(irq))
    elif state_type == 3: # ICPR
        for irq in irq_list:
            # if this bit is 1, and the irq is pending, clear its pending.
            if irq in NVIC.pending:
                NVIC.remove_pending(irq, -1)
                if DEBUG_NVIC:
                    print("############### Setting nvic #0x{:02x}.pending to 0".format(irq))

def _handler_systick_ctrl_write(uc, mem_type, address, size, value, user_data):
    '''
    hook when write systick_ctrl reg,
    SysTick is only concerned with writing the 3 lowest bits: ENABLE, TICKINT, CLKSOURCE.
    '''
    # changed bits
    change_bits = NVIC.systick['ctrl'] ^ value
    # if enable status change, able or disable systick
    if change_bits & 0x1:
        if value & 0x1:
            # start_timer(uc, NVIC.systick['timer_ind'])
            NVIC.set_able(NUM_SYSTICK)
        else:
            # stop_timer(uc, NVIC.systick['timer_ind'])
            NVIC.remove_able(NUM_SYSTICK)
    elif change_bits & 0x4:
        # reload_timer(NVIC.systick['timer_ind'])
        pass
    # record value
    NVIC.systick['ctrl'] = value  

#------------- Main Class -------------#

class VecInfo:
    '''
    vector(prio, enabled, level, pending, active)
    '''
    def __init__(self, prio=0, enabled=False, level=0, pending=False, active=False):
        self.prio = prio # default: 0
        self.enabled = enabled
        self.level = level
        self.pending = pending
        self.active = active

class NVIC():
    vectors = [] # vectors list
    block = 0 # record block nums

    @classmethod
    def configure(cls, uc, num_vecs=240, initial_vtor=0):
        cls.uc = uc
        # the init value of special regs
        cls.vtor = initial_vtor
        cls.icsr = 0
        cls.systick = {
            'ctrl': 0
        }
        # the state of nvic
        cls.little_endian = (uc.query(UC_QUERY_MODE) & UC_MODE_BIG_ENDIAN) == 0
        cls.pack_prefix = "<" if cls.little_endian else ">"
        cls.curr_active = -1 # current active vector
        cls.last_active_index = -1 # last active vector
        cls.enabled = set() # enabled set
        cls.pending = [] # pending list

        # init the state of vectors
        cls.vectors = [VecInfo() for _ in range(num_vecs)]

        # init priority of vectors
        cls.vectors[NUM_Reset].prio = -3
        cls.vectors[NUM_NMI].prio = -2
        cls.vectors[NUM_HardFault].prio = -1

        # block chook
        uc.hook_add(UC_HOOK_BLOCK, _nvic_tick_check)

        # Listen for changes to vtor base address
        uc.hook_add(UC_HOOK_MEM_WRITE, _handler_vtor_write,
                    user_data=None, begin=VTOR_BASE, end=VTOR_BASE)
        
        # Listen for changes to ICSR
        uc.hook_add(UC_HOOK_MEM_WRITE, _handler_icsr_write,
                    user_data=None, begin=ICSR_BASE, end=ICSR_BASE + 3)

        # Listen for changes to ISER/ICER/ISPR/ICPR
        uc.hook_add(UC_HOOK_MEM_WRITE, _handler_state_write,
                    user_data=None, begin=ISER_BASE, end=ICPR_BASE + int(num_vecs/8) - 1)
        
        # Listen for changes to SYSTICK_CTRL
        uc.hook_add(UC_HOOK_MEM_WRITE, _handler_systick_ctrl_write,
                    user_data=None, begin=SYSTICK_CTRL, end=SYSTICK_CTRL + 3)
            
        # Listen for interrupt return or SVC
        uc.hook_add(UC_HOOK_INTR, _nvic_intr_handle)

    @staticmethod
    def _is_exception_ret(pc):
        """
        Detect returns from an ISR by the PC value
        """
        return pc & EXC_RETURN == EXC_RETURN
    
    @classmethod
    def _is_enabled(cls, ind):
        '''
        Detect whether the irq is enabled
        '''
        # TODO: PRIMASK, BASEPRI
        if ind <= 0x10:
            return True
        elif ind in cls.enabled:
            return True
        if DEBUG_NVIC:
            print("[WARN] Interrupt #0x%02x: Pended but not enabled."%ind)
        return False
    
    @classmethod
    def _find_pending(cls):
        """
        Find the next pending interrupt to acknowledge (activate)
        """
        if len(cls.pending):
            irq = cls.pending[0]
            cls.remove_pending(irq)
            return irq
        return -1

    @classmethod
    def _push_state(cls):
        """
        when interrupt enter, 
        push r0, r1, r2, r3, r12, lr, pc, xpsr, sp to stack frame
        """
        uc = cls.uc
        saved_reg_value = []
        # 1. get saved_regs' value
        for i in range(len(saved_reg_ids)):
            saved_reg_value.append(uc.reg_read(saved_reg_ids[i]))
            if saved_reg_ids[i] == UC_ARM_REG_PC:
                saved_reg_value[i] |= 1
        
        # 2. create frame to save regs' value
        frameptralign = (saved_reg_value[-1] & 4) >> 2
        frameptr = (saved_reg_value[-1] - FRAME_SIZE) & ((~0b100) & 0xffffffff)
        # Adjust xpsr
        saved_reg_value[-2] |= (frameptralign << 9)
        
        # 3. save regs' value in frame // not include sp
        frame = struct.pack(cls.pack_prefix + 8 * "I", *tuple(saved_reg_value[:-1]))
        uc.mem_write(frameptr, frame) 

        # 4. Adjust stack pointer
        uc.reg_write(UC_ARM_REG_SP, frameptr)
    
    @classmethod
    def _pop_state(cls):
        """
        when interrupt exit,
        pop r0, r1, r2, r3, r12, lr, pc, xpsr, sp from stack frame
        """
        uc = cls.uc
        # 1. get frameptr(sp)
        frameptr = uc.reg_read(UC_ARM_REG_SP)

        # 2. read regs' value from frame
        saved_regs = uc.mem_read(frameptr, FRAME_SIZE)

        saved_regs_value = list(struct.unpack(
        cls.pack_prefix + 8 * "I", saved_regs))

        # 3. stack recovery
        sp = uc.reg_read(UC_ARM_REG_SP)
        sp += FRAME_SIZE
        xpsr_retspr = saved_reg_ids.index(UC_ARM_REG_XPSR)
        if (saved_regs_value[xpsr_retspr] & (1 << 9)) != 0:
            sp += 4
        saved_regs_value.append(sp)

        # 4. write saved_regs' value to regs
        for i in range(len(saved_reg_ids)):
            if (saved_reg_ids[i] == UC_ARM_REG_PC):
                saved_regs_value[i] |= 1
            uc.reg_write(saved_reg_ids[i], saved_regs_value[i])

    @classmethod
    def _enter_exception(cls, num):#TODO:, is_tail_chained):
        """
        Entering an exception is done when the NVIC chose
        an exception of the highest priority to be serviced
        """
        uc = cls.uc

        # Update nvic state
        assert (cls.curr_active == -1)
        vector = cls.vectors[num]
        vector.pending = False
        vector.active = True
        cls.curr_active = num

        cls._push_state()

        new_lr = EXC_RETURN

        # TODO: When the stack is SP_main, no way to know whether is in Mode_thread

        control = uc.reg_read(UC_ARM_REG_CONTROL)

        if (control & 0x2) == 0x2:
        # When the stack is SP_process, switch to SP_Main
            control ^= 0x2
            uc.reg_write(UC_ARM_REG_CONTROL, control)
            new_lr |= NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG | NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG

        # Find the ISR entry point and set it
        isr, = struct.unpack(cls.pack_prefix+"I",
                             cls.uc.mem_read(cls.vtor + num * PTR_SIZE, 4))
        if DEBUG_NVIC:
            print("[+] Interrupt #0x{:02x}: Redirecting to isr: 0x{:08x}".format(num, isr))
        cls.uc.reg_write(UC_ARM_REG_PC, isr)
        
        # Set new LR
        cls.uc.reg_write(UC_ARM_REG_LR, new_lr)

    @classmethod
    def _exit_exception(cls):
        """
        Exiting an exception happend in response to PC being
        set to an EXC_RETURN value (PC mask 0xfffffff0).
        During exception return, either the next exception has
        to be serviced (tail chaining) or the previous processor
        state (stack frame) has to be restored and user space
        operation has to be resumed.
        """
        
        # assert(cls.curr_active != -1)
        cls._pop_state()
        cls.vectors[cls.curr_active].active = False
        cls.curr_active = -1

    @classmethod
    def recalc_prios(cls):
        '''
        Re-calculate nvic interrupt prios and indicate whether
        things have changed.
        '''
        highest_pending_prio = 256
        num_active = 0
        
        highest_active_group_prio = 256
        highest_pending_irq = 0

        # for vector in cls.vectors:
        #     vector.prio
     
    @classmethod
    def exit_handler(cls, uc, addr):
        '''
        stack recovery and state recovery
        '''
        uc = cls.uc

        if DEBUG_NVIC:
            print("[*] Interrupt #0x%02x: Returning..."%cls.curr_active)

        # TODO: recals_prios();

        # Pop the current stack state
        if (addr & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) :
        # When returning to thread mode:
            if(addr & NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG):
            # When need to change stack to SP_process:
                control = uc.reg_read(UC_ARM_REG_CONTROL)
                if (control & 0x2) != 0x2:
                    control ^= 0x2
                    uc.reg_write(UC_ARM_REG_CONTROL, control)
        
        # recovery state
        if DEBUG_NVIC:
            print("[+] Interrupt #0x%02x: Return Success!"%cls.curr_active)
            print("[+] ----------------------------------")
        cls._exit_exception()
        return False

    @classmethod
    def check_pending(cls):
        '''
        get a pending vector and active it.
        '''
        if cls.curr_active == -1:
            ind = cls._find_pending()
            if ind != -1 and cls._is_enabled(ind):
                if DEBUG_NVIC:
                    print("[*] Interrupt #0x%02x: Activating..."%ind)
                try:
                    cls._enter_exception(ind)
                except UcError as e:
                    if e.errno == 6 and DEBUG_NVIC:
                        if DEBUG_NVIC:
                            print("[WARN] cannot activate interrupt #%s, because the vtor base hasn't been set."%(hex(ind)))
                    elif e.errno != 6:  
                        if DEBUG_NVIC:
                            print("[WARN] cannot activate interrupt #%s, because %s."%(hex(ind),e))
                    cls._exit_exception()
                except Exception as e:
                    if DEBUG_NVIC:
                        print("[WARN] cannot activate interrupt #%s, because %s."%(hex(ind),e))
                    cls._exit_exception()

        return False
    
    @classmethod
    def set_pending(cls, num):
        cls.pending.append(num)
        cls.vectors[num].pending = True
        # log debug information
        if DEBUG_NVIC:
            print("[+] Interrupt #0x{:02x}: Set Pend.".format(num))
    
    @classmethod
    def remove_pending(cls, num, count=1):
        while num in cls.pending and count:
            cls.pending.remove(num)
            count -= 1
        if num not in cls.pending:
            cls.vectors[num].pending = False

    @classmethod
    def set_able(cls, num):
        if num not in cls.enabled:
            cls.enabled.add(num)
            cls.vectors[num].enabled = True
    
    @classmethod
    def remove_able(cls, num):
        cls.enabled.remove(num)
        cls.vectors[num].enabled = False

    @classmethod
    def set_vtor(cls, addr):
        cls.vtor = addr