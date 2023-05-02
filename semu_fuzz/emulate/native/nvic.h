#include<unicorn/unicorn.h>

// special constant
#define MAX_VECTORS_NUM 300
#define MAX_PENDING_NUM 1000

#define NUM_VECS 240

// irq num
#define NUM_Reset 1 // reset handler
#define NUM_NMI 2 // no maskable interrupt
#define NUM_HardFault 3 // hardware fault
#define NUM_SVC 11 // super visor call
#define NUM_PendSV 14 // pending super visor
#define NUM_SYSTICK 15 // system tick timer
// base address to limit hook range
#define SYSTICK_CTRL 0xE000E010 // systick control
#define SYSTICK_LOAD 0xE000E014 // systick load
#define SYSTICK_VAL 0xE000E018 // systick val
#define SYSTICK_CALIB 0xE000E01C // systick calibration
#define ISER_BASE 0xE000E100 // interrupt set enabled reg
#define ICER_BASE 0xE000E180 // interrupt clear enabled reg
#define ISPR_BASE 0xE000E200 // interrupt set pending reg
#define ICPR_BASE 0xE000E280 // interrupt clear pending reg
#define ICSR_BASE 0xE000ED04 // interrupt control and state reg
#define VTOR_BASE 0xE000ED08 // vector table offset reg

#define FRAME_SIZE 0x20
#define PTR_SIZE 4
#define EXCEPTION_NO_INACTIVE 0xffffffff
#define EXC_RETURN 0xfffffff0
#define NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG 8 // 1000(2), theadmode when enter exception
#define NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG 4  // 0100(2), sp switched when enter exception
#define NUM_SAVED_REGS 9

typedef struct{
    int16_t prio; // default: 0
    uint16_t level;
    bool enabled;
    bool pending;
    bool active;
}VecInfo;

typedef struct {
    bool is_load;
    uint32_t ctrl;
    uint32_t tick_val; // the num of blocks from the next trigger
    uint32_t reload_val; // the num of blocks between two triggers
}SysTick;

typedef struct {
    VecInfo vectors[MAX_VECTORS_NUM];
    uc_engine* uc;
    SysTick systick;
    uint32_t vtor;
    uint32_t icsr;
    uint16_t num_vecs;
    int16_t curr_active; // current active vector
    int16_t last_active_index; // last active vector
    uint16_t enabled[MAX_VECTORS_NUM]; // enabled list
    uint16_t pending[MAX_PENDING_NUM]; // pending list
} NVIC;

static int saved_reg_ids[NUM_SAVED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR,
    UC_ARM_REG_SP
};
static struct {
    uint32_t r0, r1, r2, r3, r12, lr, pc_retaddr, xpsr_retspr, sp;
} saved_regs;

static uint32_t *saved_reg_ptrs[NUM_SAVED_REGS] = {
    &saved_regs.r0,
    &saved_regs.r1, &saved_regs.r2,
    &saved_regs.r3, &saved_regs.r12,
    &saved_regs.lr, &saved_regs.pc_retaddr,
    &saved_regs.xpsr_retspr, &saved_regs.sp
};

static NVIC nvic = {
    .curr_active = -1,
    .last_active_index = -1,
    .enabled = {0},
    .pending = {0}
};