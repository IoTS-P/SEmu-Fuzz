#--------------Class Identification------------------#

class Field:
    def __init__(self, typ, phaddr, bits):
        self.type = typ # R: receive; T: transmit;
        self.phaddr = phaddr
        self.bits = bits

class Reg:
    def __init__(self, typ, data_width, width, reset, is_eth=False):
        self.type = typ
        self.data_width = data_width # width without reservd field
        self.width = width # width with reserved field
        self.reset = reset
        self.value = reset 
        self.is_eth = is_eth

class DataReg:
    def __init__(self):
        self.r_size = 0 # the size of rxbuffer
        self.r_value = 0
        self.r_fifo = []
        self.fuzz_r_fifo = [] # all the fuzz input
        self.t_size = 0 # the size of txbuffer
        self.t_value = 0

class Equation:
    def __init__(self, interrupt=-1, dma_irq=-1):
        self.type_eq = 'A' # A: action; R, W, B, V, O... : trigger_type
        self.a1 = Field(0,0,'*')
        self.eq = '*' # = ; >;  <;  >=; <=
        self.type_a2 = 'V' # options: ['V', 'F'], V:value; F: field
        self.a2_value = '*'
        self.a2_field = Field(0,0,'*')
        self.interrupt = interrupt
        self.dma_irq = dma_irq

    def print(self):
        return ' '.join([format(self.a1.phaddr, '#04x'), str(self.a1.bits), self.eq, str(self.value),str(self.interrupt)])

class Flag:
    def __init__(self, field, value):
        self.a1 = field
        self.value = value
        self.debug_info = ''

class DMA:
    def __init__(self, dma_irq, memory_field, periphral_field, size_field, HTIF, TCIF, GIF, state=0):
        self.dma_irq = dma_irq
        self.memo_field = memory_field
        self.peri_field = periphral_field
        self.size_field = size_field
        self.HTIF = HTIF
        self.TCIF = TCIF
        self.GIF = GIF
        self.state = state # 0: disable; 1: not start yet; 2: half complete.