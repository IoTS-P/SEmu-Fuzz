from unicorn import *
from typing import Optional
import os

REDZONE_SIZE = 8

DEBUG = 1
if DEBUG:
    def heap_log_to_file(message):
        return
        #print(message)
else:
    def heap_log_to_file(message):
        with open("heap_message.txt", "a") as f:
            f.write(message + "\n")

# help fuzz to get crash
def mem_trigger(uc, address, size, user_data):
    heap_log_to_file("illegal read/write/execute in code_address 0x%x" % (address))
    os.abort()

class HeapAllocator:
    def __init__(self,uc:Optional[Uc],heap_start,heap_size):
        heap_log_to_file("size:{}".format(heap_size))
        self.uc = uc
        self.heap_start = heap_start
        self.heap_size = heap_size
        self.heap_offset = heap_start
        self.free_list = list()
        self.free_size = list()
        self.using_list = list()
        self.using_size = list()
        # initialize the uc memory status 
        self.uc.mem_map(self.heap_start,self.heap_size)
        heap_log_to_file("heap mmap addr:{},size:{}".format(self.heap_start,self.heap_size))
        # initialize the heap check mechanism
        self.uc.hook_add(UC_HOOK_MEM_PROT,mem_trigger)

    def malloc(self,size):
        #heap_log_to_file("malloc size:{}".format(size))
        #1. get from free list
        chunk = self.get_from_free_list(size)
        if chunk is None:
            #2. get from big heap
            chunk = self.get_from_heap(size)
            if chunk is None:
                heap_log_to_file("error: memory is not enough,you need to mmap more size")
                return None
        return chunk
    
    def free(self,addr):
        heap_log_to_file("start free the addr:{}".format(hex(addr)))
        if addr ==0:
            heap_log_to_file("check the null pointer :{}".format(hex(addr)))
            os.abort()
        if addr in self.free_list:
            heap_log_to_file("check the double free :{}".format(hex(addr)))
            os.abort()
        # delete from using list
        size = self.delete_from_using_list(addr)
        # check heap_overflow
        input = self.uc.mem_read(addr+size,1)
        if input[0]!=0:
            heap_log_to_file("check hof")
            os.abort() 
        # add chunk to free list
        self.add_to_free_list(addr,size)
    
    def get_from_free_list(self,size):
        # just look for free_chunk_size>= size
        for i in range(len(self.free_list)):
            if(self.free_size[i]>=size):
                chunk = self.free_list[i]
                size = self.delete_from_free_list(chunk)
                self.add_to_using_list(chunk,size)
                return chunk
        return None
    
    def get_from_heap(self,size):
        # just split the heap
        if (self.heap_offset+size+REDZONE_SIZE)<= (self.heap_start+self.heap_size):
            chunk = self.heap_offset
            heap_log_to_file("malloc chunk addr:{}".format(chunk))
            self.add_to_using_list(chunk,size)
            self.heap_offset += (size+REDZONE_SIZE)
            return chunk
        else:
            heap_log_to_file("heap space is not enough!")
            return None     

    def add_to_free_list(self,addr,size):
        heap_log_to_file("add to free list!")
        self.free_list.append(addr)
        self.free_size.append(size)
        #self.lock_mem_protect(addr,size)
        return   
    
    def delete_from_free_list(self,addr):
        free_list_copy = self.free_list.copy()
        free_size_copy = self.free_size.copy()
        for i in range(len(self.free_list)):
            if self.free_list[i] == addr:
                del free_list_copy[i]
                size = free_size_copy[i]
                del free_size_copy[i]
                break
        self.free_list = free_list_copy
        self.free_size = free_size_copy
        return size

    def add_to_using_list(self,addr,size):
        self.using_list.append(addr)
        heap_log_to_file("using list append:{}".format(addr))
        self.using_size.append(size)
        #self.unlock_mem_protect(addr,size)
        return 

    def delete_from_using_list(self,addr):
        heap_log_to_file("delete from using list!")
        using_list_copy = self.using_list.copy()
        using_size_copy = self.using_size.copy()
        for i in range(len(self.using_list)):
            if self.using_list[i] == addr:
                del using_list_copy[i]
                size = using_size_copy[i]
                del using_size_copy[i]
                break
        self.using_list = using_list_copy
        self.using_size = using_size_copy
        return size
    
    def unlock_mem_protect(self,addr,size):
        #actually do nothing
        true_chunk_addr = addr
        true_chunk_size = size - REDZONE_SIZE
        red_zone_back_addr = addr + size - REDZONE_SIZE
        red_zone_back_size =  REDZONE_SIZE
        return 
    
    def lock_mem_protect(self,addr,size):
        #actually do nothing
        return 
    
    def ha_mem_check(self,addr,input):
        # caclulate the input length
        heap_log_to_file("heap_mem_write")
        heap_log_to_file("input:{}".format(input))
        length = 0
        while input[length]!=0:
            length += 1
        heap_log_to_file("length:{}".format(length))
        heap_log_to_file("address:{}".format(addr))
        heap_log_to_file("using_lsit:{}".format(self.using_list))
        heap_log_to_file("using_list len:{}".format(len(self.using_list)))
        for i in range(len(self.using_list)):
            chunk = self.using_list[i]
            heap_log_to_file("chunk addr:{}".format(chunk))
            chunk_size = self.using_size[i]
            if (addr >= chunk) and ((addr+length) <= (chunk+chunk_size-REDZONE_SIZE)):
                #self.uc.mem_write(addr,input)
                heap_log_to_file("hit!")
                return True 
        return False