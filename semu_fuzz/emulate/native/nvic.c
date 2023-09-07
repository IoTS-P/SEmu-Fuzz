#include"nvic.h"

// #define DEBUG_NVIC

static void _set_pending(uint16_t irq){
    int i=0;
    for(i=0; nvic.pending[i]; ++i);
    nvic.pending[i] = irq;
    nvic.vectors[irq].pending = true;
#ifdef DEBUG_NVIC
    printf("[+] Interrupt #0x%02x: Set pend.\n", irq);
#endif
}

static void _set_enabled(uint16_t irq){
    int i=0;
    for(i=0; nvic.enabled[i]; ++i)if(irq==nvic.enabled[i])return;
    nvic.enabled[i] = irq;
    nvic.vectors[irq].enabled = true;
}

static uint16_t _get_list_count(uint16_t list[]){
    /* for nvic enabled and pending */
    int count=0;
    for(count=0; list[count]; ++count);
    return count;
}

/* remove [count] [irq](s) from pending list */
static void _remove_pending(uint16_t irq, uint16_t count){
    for(int i=0; nvic.pending[i] && count; ++i){
        if(irq == nvic.pending[i]){
            for (int j = i; nvic.pending[j]; ++j) {
                nvic.pending[j] = nvic.pending[j + 1];
            }
            nvic.vectors[irq].pending = false;
            --count;
        }
    }
}

/* remove irq from enabled list */
static void _remove_enabled(uint16_t irq){
    for(int i=0; nvic.enabled[i]; ++i){
        if(irq == nvic.enabled[i]){
            for (int j = i; nvic.enabled[j]; ++j) {
                nvic.enabled[j] = nvic.enabled[j + 1];
            }
            nvic.vectors[irq].enabled = false;
        }
    }
}

static bool _is_enabled(uint16_t ind){
    /* Detect whether the irq is enabled */
    uint32_t primask, basepri;
    uc_reg_read(nvic.uc, UC_ARM_REG_PRIMASK, &primask);
    if(primask & 0x1 && ind != NUM_HardFault && ind != NUM_NMI && ind != NUM_Reset)
        return false;
    uc_reg_read(nvic.uc, UC_ARM_REG_BASEPRI, &basepri);
    if(basepri != 0 && basepri < nvic.vectors[ind].prio)
        return false;
    if(ind <= 0x10)
        return true;
    for(int i=0; nvic.enabled[i]; ++i)
        if(ind == nvic.enabled[i])
            return true;
#ifdef DEBUG_NVIC
    printf("[WARN] Interrupt #0x%02x: pended but not enabled.\n", ind);
#endif
    return false;
}

/* Find the next pending interrupt to acknowledge (activate) */
static int16_t _find_pending(){
    if(nvic.pending[0] == 0)
        return 0;
    
    uint32_t curr_active;
    uint32_t min_prio = 0xffffffff;
    uint16_t min_pend = 0;

    for(int i=0; nvic.pending[i]; ++i){
        uint16_t irq = nvic.pending[i];
        uint32_t prio = nvic.vectors[irq].prio;
        if(prio < min_prio && _is_enabled(irq)){
            min_prio = prio;
            min_pend = irq;
        }
    }

    // don't interrupt when a higher or same priority interrupt active.
    curr_active = nvic_get_active();
    if(curr_active != 0 && min_prio >= nvic.vectors[curr_active].prio)
        return 0;

    if (min_pend != 0) {
        _remove_pending(min_pend, 1);
        
    }

    return min_pend;
}

void _push_state(uc_engine *uc)
{
    // 1. get saved_regs' value
    for(int i=0;i<NUM_SAVED_REGS;i++){
        uc_reg_read(uc, saved_reg_ids[i], saved_reg_ptrs[i]);
        if (saved_reg_ids[i] == UC_ARM_REG_PC){
            *saved_reg_ptrs[i] |= 1;
        }
    }

    // 2. create frame to save regs' value
    uint32_t frameptralign = (saved_regs.sp & 4) >> 2;
    uint32_t frameptr = (saved_regs.sp - FRAME_SIZE) & ((~0b100) & 0xffffffff);
    // Adjust xpsr
    saved_regs.xpsr_retspr |= (frameptralign << 9);
    
    // 3. save regs' value in frame // not include sp
    uc_mem_write(uc, frameptr, &saved_regs, FRAME_SIZE);// - sizeof(saved_regs.sp)); 

    // 4. Adjust stack pointer
    uc_reg_write(uc, UC_ARM_REG_SP, &frameptr);
}

void _pop_state(uc_engine *uc) {
    // 1. get frameptr(sp)
    uint32_t frameptr;
    uc_reg_read(uc, UC_ARM_REG_SP, &frameptr);

    // 2. read regs' value from frame
    if(uc_mem_read(uc, frameptr, &saved_regs, FRAME_SIZE) != UC_ERR_OK) {
        perror("[NVIC ERROR] pop_state: reading saved context frame failed\n");
        exit(-1);
    }

    // 3. stack recovery
    uc_reg_read(uc, UC_ARM_REG_SP, &saved_regs.sp);
    saved_regs.sp += FRAME_SIZE;
    if((saved_regs.xpsr_retspr & (1 << 9)) != 0)
    {
        saved_regs.sp += 4;
    }

    // 4. write saved_regs' value to regs
    for(int i=0;i<NUM_SAVED_REGS;i++){
        uc_reg_write(uc, saved_reg_ids[i], saved_reg_ptrs[i]);
    }
}

static bool _exit_exception(uc_engine *uc, uint32_t addr) {
    /*
     * stack recovery and state recovery
     */
    uint16_t curr_active;
    curr_active = nvic_get_active();

#ifdef DEBUG_NVIC
    printf("[*] Interrupt #0x%02x: Returning...\n", curr_active);
#endif

    // Pop the current stack state
    // When returning to thread mode:
    if (addr & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) {
        uint16_t irq = 0;
        uc_reg_write(uc, UC_ARM_REG_IPSR, &irq); // thead mode means no exception
        // When need to change stack to SP_process:
        if (addr & NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG) {
            uint32_t control;
            uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);
            if ((control & 0x2) != 0x2) {
                control ^= 0x2;
                uc_reg_write(uc, UC_ARM_REG_CONTROL, &control);
            }
        }
    }

    // pop context from psp
    _pop_state(nvic.uc);

    // update nvic state
    nvic.vectors[curr_active].active = false;

#ifdef DEBUG_NVIC
    printf("[+] Interrupt #0x%02x: Return Success!\n", curr_active);
    printf("[+] ----------------------------------\n");
#endif
    return false;
}

static void _enter_exception(uint16_t num) {
    /*
    Entering an exception is done when the NVIC chose
    an exception of the highest priority to be serviced
    */
    uc_engine* uc = nvic.uc;

    _push_state(uc);

    uint32_t new_lr = EXC_RETURN;

    uint32_t control;
    uc_reg_read(uc, UC_ARM_REG_CONTROL, &control);

    // NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG needs to be set when enter from thread mode
    if(nvic_get_active() == 0)
        new_lr |= NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG;

    if ((control & 0x2) == 0x2) {
        // When the stack is SP_process, switch to SP_Main
        control ^= 0x2;
        uc_reg_write(uc, UC_ARM_REG_CONTROL, &control);
        new_lr |= NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG;
    }

    // Find the ISR entry point and set it
    uint32_t isr = 0;
    uc_err ret = uc_mem_read(uc, nvic.vtor + num * PTR_SIZE, &isr, sizeof(isr));

    if(ret != UC_ERR_OK){
        _exit_exception(uc, EXC_RETURN);
#ifdef DEBUG_NVIC
    if(ret == 6){
        printf("[WARN] Interrupt 0x%02x: Failed to enter, because because the vtor base hasn't been set.\n", num);
    }else{
        printf("[WARN] Interrupt 0x%02x: Failed to enter, because uc_error no.%d\n", num, ret);
    }
#endif
        return;
    }
    
    uc_reg_write(uc, UC_ARM_REG_PC, &isr);
    // Set new LR
    uc_reg_write(uc, UC_ARM_REG_LR, &new_lr);

    // Update NVIC state
    nvic.vectors[num].pending = false;
    nvic.vectors[num].active = true;
    uc_reg_write(uc, UC_ARM_REG_IPSR, &num);

#ifdef DEBUG_NVIC
    printf("[+] Interrupt #0x%02x: Redirect to isr: 0x%08x\n", num, isr);
#endif
}

static void check_pending(){
    /* get a pending vector and active it. */
    uint16_t ind = _find_pending();
    if(ind !=0){
#ifdef DEBUG_NVIC
        printf("[*] Interrupt #0x%02x: Activating...\n", ind);
#endif
        _enter_exception(ind);
    }
}

/*------------- User Function of nvic.c -------------*/

// get the value of enabled irq list of NVIC
uint16_t* nvic_get_enabled() {
    return nvic.enabled;
}

// get the value of current active irq of NVIC
uint16_t nvic_get_active() {
    uint32_t curr_active;
    uc_reg_read(nvic.uc, UC_ARM_REG_IPSR, &curr_active);
    return curr_active;
}

// get the value of pending irq list of NVIC
bool nvic_get_pending(uint16_t irq) {
    return nvic.vectors[irq].pending;
}

/* when current irq is not 'irq', pending 'irq',
 * if irq is not set, pending one in order. */
void send_pending(uc_engine* uc, uint16_t irq){
    // if irq is not set, choice one in order to pending
    if(irq == 0){
        // if no enabled irq, just return
        if(!nvic.enabled[0])
            return;
        uint16_t enable_count = _get_list_count(nvic.enabled);
        int index = nvic.last_active_index + 1;
        // if this irq is the final one, back to the first one 
        if (index >= enable_count) {
            index = 0;
        }
        // set the next irq
        irq = nvic.enabled[index];
        nvic.last_active_index = index;
    }
    // use NVIC to set pending
    _set_pending(irq);
}

static void deal_systick(){
    // if systick is disabled, return
    if(!(nvic.systick.ctrl & 0x1))
        return;
    uc_engine* uc = nvic.uc;
    // reload the systick equal to decrease the value of systick!
    if(nvic.systick.val == 0){
        // reload the value of systick
        nvic.systick.val = nvic.systick.load;
        // clear count flag
        nvic.systick.ctrl &= 0xfffeffff;
        uc_mem_write(uc, SYSTICK_CTRL, &nvic.systick.ctrl, sizeof(nvic.systick.ctrl));
    }else{
        // decrease the value of systick
        nvic.systick.val -= 1;
    }
    // if value of systick is 0, active the irq
    if(nvic.systick.val == 0){
        // set count flag
        nvic.systick.ctrl |= 0x00010000;
        uc_mem_write(uc, SYSTICK_CTRL, &nvic.systick.ctrl, sizeof(nvic.systick.ctrl));
        // pending the systick irq
        if(nvic.systick.ctrl & 0x2 && nvic_get_active() != NUM_SYSTICK){
            _set_pending(NUM_SYSTICK);
        }  
    }
    uc_mem_write(uc, SYSTICK_VAL, &nvic.systick.val, sizeof(nvic.systick.val));
}

/*------------- Hook Functions -------------*/

/* check_pending and check timer every block. */
static void handler_tick_check_cb(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    // check pending list
    check_pending();
    // if systick is enabled, check the value of systick
    if(nvic.systick.ctrl & 0x1){
        deal_systick();
    }
}

static void handler_vtor_write_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    /* hook when write vector table offset reg */
    nvic.vtor = value;
#ifdef DEBUG_NVIC
    printf("############### Changing nvic vtor to 0x%08lx\n", value);
#endif
}

static void handler_icsr_write_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    /* hook when write interrupt control and state reg */
    // record new value.
    nvic.icsr |= value;
    // the action of write 1.
    if(value & (1 << 25)) // PENDSTCLR
        _remove_pending(NUM_SYSTICK, 0);
    if(value & (1 << 26)) // PENDSTSET
        _set_pending(NUM_SYSTICK);
    if(value & (1 << 27)) // PENDSVCLR
        _remove_pending(NUM_PendSV, 0);
    if(value & (1 << 28)) // PENDSVSET
        _set_pending(NUM_PendSV);
    if(value & (1 << 31)) // NMIPENDSET
        _set_pending(NUM_NMI);
}

static void handler_state_write_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    /* hook when write ISER/ICER/ISPR/ICPR reg */
    uint64_t base_address = address & 0xFFFFF800;
    // caculate the irq_range corresponding to the address
    uint16_t irq_begin = ((address - base_address) & 0x1f) << 3;
    uint16_t irq_range = size << 3;
    // find the bit with the value 1 in 'value'.
    uint16_t irq_list[MAX_VECTORS_NUM] = {0};
    uint16_t irq_list_len = 0;
    for(int i=0; i<irq_range; ++i){
        if((value >> i) & 0x1){
            irq_list[irq_list_len] = irq_begin + i + 0x10;
            ++irq_list_len;
        }
    }
    switch ((address - ISER_BASE) >> 7){
    case 0/* ISER */:
        for(int i=0; i<irq_list_len;++i){
            // if this bit is 1, set it enabled.
            _set_enabled(irq_list[i]);
#ifdef DEBUG_NVIC
            printf("############### Setting nvic #0x%02x.enabled to 1\n", irq_list[i]);
#endif
        }
        break;
    case 1/* ICER */:
        for(int i=0; i<irq_list_len;++i){
            // if this bit is 1, set it disabled.
            _remove_enabled(irq_list[i]);
#ifdef DEBUG_NVIC
            printf("############### Setting nvic #0x%02x.enabled to 0\n", irq_list[i]);
#endif
        }
        break;
    case 2/* ISPR */:
        for(int i=0; i<irq_list_len;++i){
            // if this bit is 1, set it pending.
            _set_pending(irq_list[i]);
#ifdef DEBUG_NVIC
            printf("############### Setting nvic #0x%02x.pending to 1\n", irq_list[i]);
#endif
        }
        break;
    case 3/* ICPR */:
        for(int i=0; i<irq_list_len;++i){
            // if this bit is 1, clear its pending.
            _remove_pending(irq_list[i], 0);
#ifdef DEBUG_NVIC
            printf("############### Setting nvic #0x%02x.pending to 0\n", irq_list[i]);
#endif
        }
        break;
    default:
        break;
    }
}

static void handler_nvic_ip_write_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    /* hook when write nvic interrupt priority reg, used to update priority */
    uint16_t irq = address - NVIC_IP_BASE + 0x10; // not for exception
    nvic.vectors[irq].prio = value;
#ifdef DEBUG_NVIC
        printf("############### Setting nvic #0x%02x.priority to 0x%lx\n", irq, value);
#endif
}

static void handler_systick_write_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    /* hook when write systick_ctrl/load/write reg */
    // check the written reg
    uint32_t change_bits;
    switch (address)
    {
    case SYSTICK_CTRL:
        change_bits = nvic.systick.ctrl ^ value;
        // enable or disable systick
        if (change_bits & 0x1){
            nvic.systick.val = 0;
            if(value & 0x1){
#ifdef DEBUG_NVIC
    printf("############### Enable Systick. load=%u\n", nvic.systick.load);
#endif
            }else{
#ifdef DEBUG_NVIC
    printf("############### Disable Systick.");
#endif
            }
        }
        // enable or disable systick interrupt
        if (change_bits & 0x2){
            if (!(value & 0x2))
                _remove_pending(NUM_SYSTICK, 0);
        }
        // if clksource change, reset systick val
        if (change_bits & 0x4){
            nvic.systick.val = 0;
        }
        nvic.systick.ctrl = value;
        break;
    case SYSTICK_LOAD:
        if(value < nvic.systick.load) // only when load value decrease, reset systick load
            nvic.systick.load = value - 1;
        break;
    case SYSTICK_VAL: // writing any value to systick val will reset systick val
        nvic.systick.val = 0;
        // clear countflag
        nvic.systick.ctrl &= 0xFFFEFFFF;
        break;
    default:
        break;
    }
    uc_mem_write(uc, SYSTICK_VAL, &nvic.systick.val, sizeof(nvic.systick.val));
    uc_mem_write(uc, SYSTICK_CTRL, &nvic.systick.ctrl, sizeof(nvic.systick.ctrl));
}

static void handler_systick_ctrl_readafter_cb(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data){
    // clear countflag
    nvic.systick.ctrl &= 0xFFFEFFFF;
    uc_mem_write(uc, SYSTICK_CTRL, &nvic.systick.ctrl, sizeof(nvic.systick.ctrl));
}

static void handler_nvic_intr_cb(uc_engine *uc, uint32_t intno, void *user_data){
    /*
    hook when exception
    if address in lr shadow(0xfffffff0), is exit exception. 
    elif intno == 2, is syscall.
    */
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    // exit_exception
    if (pc >= EXC_RETURN && pc <= (EXC_RETURN|0xf)) {
        _exit_exception(uc, pc);
    }
    // svc 2
    else if (intno == 2) {
        _enter_exception(0xb);
    }
    else {
        // Alternatives could be breakpoints and the like, which we do not handle.
        // TODO
        exit(-1);
    }
}

void configure(uc_engine *uc, uint16_t num_vecs, uint32_t initial_vtor, bool enable_systick, uint16_t systick_reload){
    nvic.uc = uc;
    nvic.num_vecs = num_vecs;
    // the init value of special regs
    nvic.vtor = initial_vtor;
    uc_mem_write(uc, VTOR_BASE, &initial_vtor, 4);
    nvic.icsr = 0;
    nvic.systick.load = systick_reload - 1;
    nvic.systick.val = 0;
    uc_mem_write(uc, SYSTICK_LOAD, &nvic.systick.load, sizeof(nvic.systick.load));
    uc_mem_write(uc, SYSTICK_VAL, &nvic.systick.val, sizeof(nvic.systick.val));
    // init the state of vectors
    for(int i=0; i < num_vecs; ++i){
        nvic.vectors[i].prio = 0;
        nvic.vectors[i].level = 0;
        nvic.vectors[i].enabled = false;
        nvic.vectors[i].pending = false;
        nvic.vectors[i].active = false;
    }
    // init special priority of vectors
    nvic.vectors[NUM_Reset].prio = -3;
    nvic.vectors[NUM_NMI].prio = -2;
    nvic.vectors[NUM_HardFault].prio = -1;
    nvic.vectors[NUM_PendSV].prio = 0x100; // lowest priority

    // block chook
    uc_hook handler_tick_check;
    uc_hook_add(uc, &handler_tick_check, UC_HOOK_BLOCK, handler_tick_check_cb, NULL, 1, 0);

    // Listen for changes to vtor base address
    uc_hook handler_vtor_write;
    uc_hook_add(uc, &handler_vtor_write, UC_HOOK_MEM_WRITE, handler_vtor_write_cb,NULL, VTOR_BASE, VTOR_BASE);

    // Listen for changes to ICSR
    uc_hook handler_icsr_write;
    uc_hook_add(uc, &handler_icsr_write, UC_HOOK_MEM_WRITE, handler_icsr_write_cb,NULL, ICSR_BASE, ICSR_BASE + 3);

    // Listen for changes to ISER/ICER/ISPR/ICPR
    uc_hook handler_state_write;
    uc_hook_add(uc, &handler_state_write, UC_HOOK_MEM_WRITE, handler_state_write_cb, NULL, ISER_BASE, ICPR_BASE + (int)(num_vecs/8) - 1);
        
    uc_hook handler_systick_write, handler_systick_ctrl_readafter;
    if(enable_systick){
        // Listen for changes to SYSTICK_CTRL/LOAD/VAL
        uc_hook_add(uc, &handler_systick_write, UC_HOOK_MEM_WRITE, handler_systick_write_cb, NULL, SYSTICK_CTRL, SYSTICK_VAL + 3);
        // Listen for read SYSTICK_CTRL
        uc_hook_add(uc, &handler_systick_ctrl_readafter, UC_HOOK_MEM_READ_AFTER, handler_systick_ctrl_readafter_cb, NULL, SYSTICK_CTRL, SYSTICK_VAL + 3);
    }
    // Listen for changes to NVIC_IP
    uc_hook handler_nvic_ip_write;
    uc_hook_add(uc, &handler_nvic_ip_write, UC_HOOK_MEM_WRITE, handler_nvic_ip_write_cb, NULL, NVIC_IP_BASE, NVIC_IP_BASE + (int)(num_vecs) - 1);
            
    // Listen for interrupt return or SVC
    uc_hook handler_nvic_intr;
    uc_hook_add(uc, &handler_nvic_intr, UC_HOOK_INTR, handler_nvic_intr_cb, NULL, 1, 0);
}