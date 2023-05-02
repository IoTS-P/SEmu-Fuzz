import argparse

from semu_fuzz import globs

def _init_parser(parser):
    # Needed Parsers
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument('config_file', type=str, help="The configuration file of testcase for emulation.")

    # Additional Parsers
    parser.add_argument('-s', '--stat', default=False, action="store_true", help="Enables stat new blocks created by input file.")
    parser.add_argument('-d', '--debug_level', default=0, type=int, help="0 disable debug, max debug level is 3.")
    parser.add_argument('-l', '--instr-limit', dest='instr_limit', type=int, default=globs.DEFAULT_BASIC_BLOCK_LIMIT, help="Maximum number of instructions to execute. 0: no limit. Default: {:d}".format(globs.DEFAULT_BASIC_BLOCK_LIMIT))
    # parser.add_argument('-m', '--module', default="semu", choices=['semu', 'uemu'], help="Module to run")



def parse_args():
    parser = argparse.ArgumentParser(description="semu-fuzz is a command-line tool designed for fuzz testing that utilizes the SEmu emulator to simulate the execution of mutated input files.")

    _init_parser(parser)

    globs.args = parser.parse_args()
    return globs.args