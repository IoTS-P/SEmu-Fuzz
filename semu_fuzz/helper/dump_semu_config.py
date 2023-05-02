'''
Description: dump semu config for testcases.
Usage: semu-fuzz-helper config <base_configs.yml> [-s]
Note: This script can use to generate syms.yml, but the ida_dump_symbols.py recommend.
'''

from ..utils import merge_dict

import yaml
import angr
import argparse
import sys
import os
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

extra_bin_command = "arm-none-eabi-objcopy" #"arm-linux-gnueabihf-objcopy"
cortexm_include = os.path.join(os.path.dirname(__file__), "configs/hw/cortexm_memory.yml")

def _extra_bin(elf_path, bin_path):
    ret = os.system("%s -O binary %s %s" % (extra_bin_command, elf_path, bin_path))
    if ret != 0:
        print("[-] Extra Bin File Error! Please check the command arm-linux-gnueabihf. You can use 'sudo apt install -y gcc-arm-linux-gnueabihf' to install it.")

def _extra_syms(firmware_elfpath, yml_path):
    # Based on https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py, display_symbol_tables
    res = {}
    with open(firmware_elfpath, "rb") as f:
        elffile = ELFFile(f)
        symbol_tables = [(idx, s) for idx, s in enumerate(elffile.iter_sections())
                            if isinstance(s, SymbolTableSection)]

        if not symbol_tables and elffile.num_sections() == 0:
            logger.warning("No symbol sections...")
            return res

        for _, section in symbol_tables:
            if section['sh_entsize'] == 0:
                logger.warning("section['sh_entsize'] == 0")
                # Symbol table has no entries
                continue

            for _, symbol in enumerate(section.iter_symbols()):
                if symbol.name and "$" not in symbol.name:
                    res[symbol['st_value']] = symbol.name
    config = {}
    config['symbols'] = res
    with open(yml_path, 'w') as f:
        yaml.dump(config, f)

def _parse_entry_point(firmware_elfpath):
    with open(firmware_elfpath, "rb") as f:
        elffile = ELFFile(f)
        return elffile.header.e_entry

def _parse_sp_and_vector(bin_path):
    with open(bin_path, "rb") as f:
        bin_content = f.read()
        return int.from_bytes(bin_content[:4], 'little'), int.from_bytes(bin_content[4:8], 'little')

def _parse_memory_map(firmware_elfpath, bin_name):
    p = angr.Project(firmware_elfpath, load_options={'perform_relocations': False}) # load_options to disable some unuse output
    return {
        'flash': {
            'base_addr': p.loader.min_addr,
            'file': bin_name,
            'permissions': 'r-x',
            'size': 0x2000000
        }
    }
    # with open(firmware_elfpath, "rb") as f:
    #     text_section = elffile.get_section_by_name('.text')
    #     if text_section:
    #         text_start_addr = text_section.header.sh_addr
    #         flash_size = elffile.get_section_by_name('.text').header.p_memsz
    #     return {
    #         'flash': {
    #             'base_addr': text_start_addr,
    #             'file': bin_name,
    #             'permissions': 'r-x',
    #             'size': flash_size
    #         }
    #     }

def config(base_configs, syms):
    # dump yml with %x
    hexint_presenter = lambda dumper, data: dumper.represent_scalar('tag:yaml.org,2002:int', hex(data), style='')
    yaml.add_representer(int, hexint_presenter)
    # config all the file
    for firmware_elfpath, base_config in base_configs.items():
        print('[*] Extract Config of %s...' % firmware_elfpath, end="\t")
        try:
            config = {
                "include": []
            }
            firmware_dir = os.path.dirname(firmware_elfpath)
            firmware_elfname = os.path.basename(firmware_elfpath)
            firmware_binname = firmware_elfname.split('.',1)[0] + '.bin'
            firmware_binpath = os.path.join(firmware_dir, firmware_binname)
            yml_path = os.path.join(firmware_dir, 'syms.yml')
            config_path = os.path.join(firmware_dir, 'semu_config.yml')

            # check is elf
            is_elf = True
            with open(firmware_elfpath, "rb") as f:
                try:
                    elf_file = ELFFile(f)
                except:
                    is_elf = False
                    print("[-] Not a elf path, cannot dump all the configuration, please complete your semu_config.yml dumped by this helper.")
            
            if is_elf == True:
                # auto translate elf/axf to bin
                if not os.path.exists(firmware_binpath):
                    _extra_bin(firmware_elfpath, firmware_binpath)
                
                # auto dump syms.yml, if you need it to debug function.
                if os.path.exists(yml_path):
                    config["include"].append('./syms.yml')
                elif syms:
                    _extra_syms(firmware_elfpath, yml_path)

                # auto include arch info
                with open(firmware_elfpath, "rb") as f:
                    elffile = ELFFile(f)
                    if elffile.get_machine_arch() == 'ARM':
                        config["include"].append(os.path.relpath(cortexm_include, firmware_dir))

                # auto get some config about elf
                config["entry_point"] = _parse_entry_point(firmware_elfpath)
                config["initial_sp"], config["isr_vector"] = _parse_sp_and_vector(firmware_binpath)
                config["memory_map"] = _parse_memory_map(firmware_elfpath, firmware_binname)

            # auto get rules path relative to firmware
            config["rules"] = os.path.relpath(base_config["rules"], firmware_dir)
            
            # update config
            merge_dict(base_config, config)

            # write into config file
            with open(config_path, 'w') as f:
                yaml.dump(base_config, f)
                print("[+] Success Create SEmu Config File: %s" % config_path)
        except Exception as e:
            print("[-] Extract Config of {} Error! {}".format(firmware_elfpath, e))
            print(config)
            exit(-1)