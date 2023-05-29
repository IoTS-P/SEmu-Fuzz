from unicorn.arm_const import UC_ARM_REG_R0

def get_tick(uc):
    r0 = uc.reg_read(UC_ARM_REG_R0)
    uc.reg_write(UC_ARM_REG_R0, r0 + 3000)
