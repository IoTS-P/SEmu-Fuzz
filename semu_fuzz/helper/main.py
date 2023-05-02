from ..utils import yaml_load
from .dump_semu_config import config
from .stat_bb_coverage import stat
from .dump_launch import launch
from .run_fuzz_tests import run

import yaml
import argparse
import os
import json

def _parse_args():
    parser = argparse.ArgumentParser(description="semu-fuzz-helper is a command-line utility that provides additional functionality to semu-fuzz. The tool allows users to configure and launch fuzzing campaigns, as well as collect bb coverage statistics on the performance of these campaigns.")
    # Needed Parsers
    parser.add_argument('command', choices=['config', 'launch', 'stat', 'run'], help="Helper to run. (1)config: Dump semu config for testcases. (2)launch: Dump vscode launch for testcases. (3)stat: Stat BB coverage and draw image for testcases. (4)run: Run afl test of testcases with nohup.")
    parser.add_argument('base_configs', type=str, help="Simple setting of ELF/AXF files.")
    # Additional Parsers
    parser.add_argument('-a', '--afl', default=False, action="store_true", help="[for launch] If set, enable the dumping of vscode launch with AFL.")
    parser.add_argument('-s', '--syms', default=False, action="store_true", help="[for config] If set, enable symbols table extract. (This arg is not recommended. Recommend using ida_dump_symbols.py to dump syms)")
    parser.add_argument('-t', '--duration', default=24, type=int, help="[for stat and run] The duration of AFL execution, the default value is 24, which means 24 hours.")
    return parser.parse_args()


def main():
    args = _parse_args()
    # load yml
    base_configs = yaml_load(args.base_configs)
    if args.command == 'config':
        config(base_configs, args.syms)
    elif args.command == 'stat':
        stat(base_configs, args.duration)
    elif args.command == 'launch':
        launch(base_configs, args.afl)
    elif args.command == 'run':
        run(base_configs, args.duration)