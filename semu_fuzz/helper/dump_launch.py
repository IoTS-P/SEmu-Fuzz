'''
Description: dump vscode launch json for testcases.
Usage: semu-fuzz-helper launch <base_configs.yml> [-a]
'''

import argparse
import os
import json

default_input_path = os.path.dirname(__file__) + "/_inputs/sample1.bin"

def launch(base_configs, afl):
    # dump all the file
    for firmware_elfpath, base_config in base_configs.items():
        firmware_dir = os.path.realpath(os.path.dirname(firmware_elfpath))
        firmware_elfname = os.path.basename(firmware_elfpath)
        launch_path = os.path.join(firmware_dir, 'launch.json')
        config_path = os.path.join(firmware_dir, 'semu_config.yml')

        print('[*] Extract Launch of %s...' % firmware_elfpath, end="\t")
        try:
            config = {
                "name": "SEmu-" + firmware_elfname,
                "type": "python",
                "request": "launch",
                "program": "~/.local/bin/semu-fuzz",
                "console": "integratedTerminal",
                "justMyCode": False,
                "args": [
                    default_input_path,
                    config_path,
                    "-d",
                    "3"
                ]
            }
            if afl:
                config = {
                    "name": "Afl-" + firmware_elfname,
                    "type": "cppdbg",
                    "request": "launch",
                    "program": "/usr/local/bin/afl-fuzz",
                    "args": ["-U","-m","none",
                    "-i", os.path.dirname(default_input_path),
                    "-o", os.path.join(firmware_dir, 'output_debug'),
                    "-t", "100000",
                    "--", 
                    "~/.local/bin/semu-fuzz", "@@", config_path
                    ],
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
        except Exception as e:
            print("[-] Failed! {}".format(e))
            print(config)
            exit(-1)