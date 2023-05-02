args = None
config = None
uc = None
config_dir = ""
block_count = 0
user_input = []


#-- parameters in configuration --#
DEFAULT_BASIC_BLOCK_LIMIT = 30000000

#-- parameters in emulate --#
DEFAULT_NUM_NVIC_VECS = 240 # the number of irqs in nvic vtor
INTERRUPT_INTERVAL = 1500 # the number of interrupt interval blocks
DATA_REGS_INTERVAL = 1000 # the number of blocks for data register write interval