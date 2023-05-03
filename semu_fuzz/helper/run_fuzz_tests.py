'''
Description: run afl test of testcases with nohup.
Usage: semu-fuzz-helper run <base_configs.yml> [-t <time>]
'''

import argparse
import os
import subprocess

def run(base_configs, duration):
    # dump all the file
    for firmware_elfpath, base_config in base_configs.items():
        try:
            firmware_dir = os.path.dirname(firmware_elfpath)
            firmware_elfname = os.path.basename(firmware_elfpath)
            input_path = os.path.join(os.path.dirname(__file__), '_inputs')
            base_input_path = os.path.join(firmware_dir, 'base_inputs')
            output_path = os.path.join(firmware_dir, "output")
            config_path = os.path.join(firmware_dir, 'semu_config.yml')

            print('\n[*] Check config of %s...' % firmware_elfpath)

            # check the config file
            if not os.path.exists(config_path):
                print("[-] Failed! %s not exists. Please check your path and where you run this command." % config_path)
                exit(-1)

            # choose base_inputs as seed
            if os.path.exists(base_input_path):
                input_path = base_input_path
            
            # rm the raw afl output
            if os.path.exists(output_path):
                needrm = input("[*] Find fuzz output path is not empty, remove this output? [y/N]")
                if needrm in ["y", "Y"]:
                    os.system("rm -r %s" % output_path)
                else:
                    output_path = input("[*] Please input another output name(press 'Enter' to skip this firmware): ")
                    if output_path == "":
                        print("[-] Skip %s" % firmware_elfpath)
                        continue
                    else:
                        output_path = os.path.join(firmware_dir, output_path)
            
            # exec afl-fuzz
            command = f"nohup timeout {duration}h afl-fuzz -U -m none -i {input_path} -o {output_path} -t 10000 -- semu-fuzz @@ {config_path} &"
            os.system(command)

            print('[+] Start running %s with command: %s' % (firmware_elfpath, command))
        except Exception as e:
            print("[-] Failed! {}".format(e))
            exit(-1)