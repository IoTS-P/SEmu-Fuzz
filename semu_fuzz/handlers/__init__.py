from ..exit import do_exit

from unicorn import UC_HOOK_BLOCK
import importlib

func_hooks = {}

def register_func_handler(uc, addr, size, user_data):
    global func_hooks
    if addr in func_hooks.keys():
        for hook in func_hooks[addr]:
            hook(uc)

def reset_func_handler(uc, address, func_handler="do_return"):
    global func_hooks  
    real_addr = address & 0xFFFFFFFE  # Drop the thumb bit
    # do return
    # TODO: Make this arch-independent.  Hint, use archinfo
    bxlr = b'\x70\x47'
    uc.mem_write(real_addr, bxlr)
    # func_handler
    if func_handler != "do_return":
        try:
            # Resolve the function name
            mod_name, func_name = func_handler.rsplit('.', 1)
            mod = importlib.import_module(mod_name)
            func_obj = getattr(mod, func_name)
            if real_addr not in func_hooks.keys():
                func_hooks[real_addr] = []
            func_hooks[real_addr].append(func_obj)
        except:
            print("[-] Unable to get hook function %s at address %#08x" % (func_handler, address))
            do_exit(1)
    # add func hook
    uc.hook_add(UC_HOOK_BLOCK, register_func_handler, None, real_addr, real_addr)