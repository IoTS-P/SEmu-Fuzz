from unicorn.arm_const import *
from unicorn.unicorn_const import *
from ...util import crash
from .heap_allocator import *
"""
Quick and unoptimized implementation of dynamic memory management allowing to
detect UAF, double free, heap overflow and some heap underflow issues.
"""

wilderness = 0xff000000
free_chunks = {}
allocated_chunks = {}
PAGE_SIZE = 0x4000
MALLOCED = False
Ha:Optional[HeapAllocator] = HeapAllocator

def heap_initialize(uc):
    global Ha
    global MALLOCED
    global PAGE_SIZE
    Ha = HeapAllocator(uc,wilderness,PAGE_SIZE)
    MALLOCED = True

def _malloc(uc, size):
    if not MALLOCED:
        heap_initialize(uc)
    result = Ha.malloc(size)
    return result

def _free(uc, addr):
    if not MALLOCED:
        heap_initialize(uc)
    Ha.free(addr)

def _calloc(uc, size):
    res = _malloc(uc, size)
    uc.mem_write(res, size * b'\0')
    return res

def _realloc(uc, addr, size):
    if not MALLOCED:
        heap_initialize(uc)
    tar_addr = Ha.malloc(size)
    return tar_addr

## ---------------------------------------------------------
def free(uc):
    addr = uc.reg_read(UC_ARM_REG_R0)
    print("freeing 0x{:x}".format(addr))
    if addr != 0:
        #Ha.free(addr)
        _free(uc, addr)

def calloc(uc):
    size = uc.reg_read(UC_ARM_REG_R0)
    #res = Ha.malloc(size)
    res = _calloc(uc, size)
    uc.reg_write(UC_ARM_REG_R0, res)
    print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))

def realloc(uc):
    addr = uc.reg_read(UC_ARM_REG_R0)
    size = uc.reg_read(UC_ARM_REG_R1)
    print("realloc. addr: 0x{:x}, size=0x{:x}".format(addr, size))
    res = _realloc(uc, addr, size)
    #res = Ha.malloc(size)
    uc.reg_write(UC_ARM_REG_R0, res)


def malloc(uc):
    size = uc.reg_read(UC_ARM_REG_R0)
    res = _malloc(uc, size)
    #res = Ha.malloc(size)
    uc.reg_write(UC_ARM_REG_R0, res)
    print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))
    
def memp_free(uc):
    addr = uc.reg_read(UC_ARM_REG_R1)
    _free(uc, addr)
    #Ha.free(addr)

def mem_free(uc):
    free(uc)

def mem_malloc(uc):
    # TODO: alignment guarantees
    malloc(uc)