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
    ''' just merge the items of two dicts. left = right. '''
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
        exit(-1)
    # parse file in the yaml format.
    with open(path, 'rb') as fp:
        content = yaml.load(fp, Loader=yaml.FullLoader)
    return content

from . import globs

def load_path(path): 
    ''' load file path and return content ''' 
    path = get_realpath(globs.args.config_file, path) 
    if not os.path.exists(path):
        print("[-] Rule Configure Error! File Not Exists: %s" % path)
        do_exit(-1)
    with open(path, 'r') as fp:
        return fp.read()

import subprocess

def run_task(command, task_id, timeout=10, text=True):
    print("[*] %05d Start Command: %s" % (task_id, command))

    try:
        result = subprocess.run(command, shell=True, check=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text)
    except subprocess.CalledProcessError as e:
        print("[-] %05d Process returned non-zero exit code: %s" % (task_id, e))
        return False
    except subprocess.TimeoutExpired:
        print("[-] %05d Process timed out. Killing process..." % task_id)
        return False

    return result

import importlib

def resolve_funcname(func_name):
    # Resolve the function name
    mod_name, func_name = func_name.rsplit('.', 1)
    mod = importlib.import_module(mod_name)
    func_obj = getattr(mod, func_name)
    return func_obj

def find_output_folders(base_path, search_key):
    result = []
    for root, dirs, files in os.walk(base_path):
        for dir in dirs:
            if dir.startswith(search_key):
                result.append(os.path.join(root, dir))
    return result

import subprocess
from .log.debug import debug_info

import subprocess

def run_task(command, task_id, timeout=10):
    print("[*] %05d Start Command: %s" % (task_id, command))

    try:
        subprocess.run(command, shell=True, check=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("[-] %05d Process returned non-zero exit code: %s" % (task_id, e))
        return False
    except subprocess.TimeoutExpired:
        print("[-] %05d Process timed out. Killing process..." % task_id)
        return False

    return True