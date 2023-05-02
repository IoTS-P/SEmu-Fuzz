from .. import globs

import shutil
import os

def log_configure(log_dirname, file_list, rmlog=True):
    '''
    get log realpath and rm the old log.
    rmlog: False if don't want to rm the old log.
    '''
    log_dir = os.path.join(globs.config_dir, log_dirname)
    # clear and create log_dir
    if not os.path.exists(log_dir):
        os.mkdir(log_dir)
    elif rmlog:
        shutil.rmtree(log_dir)
        os.mkdir(log_dir)
    # confirm file path
    for file_type, file_name in file_list.items():
        file_list[file_type] = os.path.join(log_dir, file_name)
        if rmlog: # only print when need new log.
            print("log in file: %s" % file_list[file_type])
    return file_list