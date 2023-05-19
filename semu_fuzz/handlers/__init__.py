def reset_func_handler(uc, address, func_handler="do_return"):
    real_addr = address & 0xFFFFFFFE  # Drop the thumb bit
    # TODO: func_handler
    if func_handler == "do_return":
        # TODO: Make this arch-independent.  Hint, use archinfo
        bxlr = b'\x70\x47'
        uc.mem_write(real_addr, bxlr)
        return True
    else:
        raise NotImplementedError