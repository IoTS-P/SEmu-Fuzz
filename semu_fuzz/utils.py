from .exit import do_exit

from ctypes import cdll
import os

def load_lib(path):
    ''' load lib file. '''
    try:
        if not os.path.exists(path):
            print('[-] Native Load Error! File Not Exist: %s' % path)
            do_exit(1)
        c_lib = cdll.LoadLibrary(path)
    except OSError as e:
        print('[-] Native Load Error! Fail to load %s' % path, e)
        do_exit(1)
    return c_lib

def get_realpath(path, f):
    from os.path import dirname, abspath, join
    ''' Get the real path of f, related to path. '''
    if not f.startswith("/"):
        cur_dir = dirname(path)
        f = abspath(join(cur_dir, f))
    return f

def merge_dict(dct, merge_dct):
    ''' just merge the items of two dicts. '''
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

import yaml

def yaml_load(path):
    # check the path
    if not os.path.isfile(path):
        print("[-] Yaml load failed! File not exists: %s" % path)
        do_exit(1)
    # parse file in the yaml format.
    with open(path, 'rb') as fp:
        content = yaml.load(fp, Loader=yaml.FullLoader)
    return content

