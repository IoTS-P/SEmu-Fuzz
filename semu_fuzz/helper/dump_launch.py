'''
Description: dump vscode launch json for testcases.
Usage: semu-helper launch <base_configs.yml> [-a]
'''

import os
import json
import sys

default_input_path = os.path.dirname(__file__) + "/_inputs/sample1.bin"

def launch(base_configs, afl):
    # dump all the file
    for firmware_elfpath, base_config in base_configs.items():
        firmware_dir = os.path.realpath(os.path.dirname(firmware_elfpath))
        firmware_elfname = os.path.basename(firmware_elfpath)
        launch_path = os.path.join(firmware_dir, 'launch.json')
        config_path = os.path.join(firmware_dir, 'semu_config.yml')

        print('[*] Extract Launch of %s...' % firmware_elfpath, end="\t")
        # get the python bin path
        python_bin = sys.executable
        python_program = os.path.join(os.path.dirname(python_bin), 'semu-fuzz')
        fuzz_program = "/usr/local/bin/afl-fuzz"
        try:
            main_program = python_program
            if not afl:
                args = [default_input_path, config_path, "-d", "3"]
                config = {
                    "name": "SEmu-" + firmware_elfname,
                    "type": "python",
                    "request": "launch",
                    "program": python_program,
                    "console": "integratedTerminal",
                    "justMyCode": False,
                    "args": args
                }
            else:
                main_program = fuzz_program
                args = ["-U","-m","none", "-i", os.path.dirname(default_input_path),
                    "-o", os.path.join(firmware_dir, 'output_debug'),
                    "-t", "100000",
                    "--",
                    python_program, "@@", config_path]
                config = {
                    "name": "Afl-" + firmware_elfname,
                    "type": "cppdbg",
                    "request": "launch",
                    "program": fuzz_program,
                    "args": args,
                    "stopAtEntry": False,
                    "cwd": "${workspaceFolder}",
                    "environment": [],
                    "externalConsole": False,
                    "MIMode": "gdb",
                    "setupCommands": [
                        {
                            "description": "Enable pretty-printing for gdb",
                            "text": "-enable-pretty-printing",
                            "ignoreFailures": True
                        }
                    ],
                    "miDebuggerPath": "/usr/bin/gdb"
                }
            launch = json.dumps(config, indent=2)
            with open(launch_path, 'w') as f:
                f.write(launch)
                print("[+] Success Create Launch File: %s" % launch_path)
                print(f"[+] If you don't have VsCode, please use Command: {main_program} {' '.join(args)}")
        except Exception as e:
            print("[-] Failed! {}".format(e))
            print(config)
            exit(-1)