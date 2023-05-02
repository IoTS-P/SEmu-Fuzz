from setuptools import setup, find_packages
from distutils.command.build import build
import os
import sys
from setuptools import setup
import subprocess

class Build(build):
    """Customized setuptools build command - builds native unicorn bindings on build."""
    def run(self):
        subprocess.run(['sudo', 'apt-get', 'update'])
        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'automake', 'gnuplot', 'gcc-arm-linux-gnueabihf', "gdb"])
        protoc_command = ["make", "-C", "semu_fuzz/emulate/native", "clean", "all"]
        if subprocess.call(protoc_command) != 0:
            sys.exit(-1)
        build.run(self)

def get_all_files(base_path, *dirs):
    files = []
    for dir in dirs:
        for maindir, subdir, file_name_list in os.walk(base_path+'/'+dir):
            subdir[:] = [d for d in subdir if not (d == "__pycache__" or "__pycache__" in os.path.join(maindir, d))]
            for filename in file_name_list:
                if filename == "__pycache__":
                    continue
                apath = os.path.join(maindir, filename)
                apath = apath.split('/', 1)[1]
                files.append(apath)
    return files

setup(
    name='semu_fuzz',
    version='0.1',
    packages=['semu_fuzz'],
    install_requires=[
        'pyyaml==6.0',
        'capstone==4.0.2',
        'angr==9.2.48',
        'unicornafl',
        'archinfo',
        'pyelftools'
    ],
    entry_points={
        'console_scripts': [
            'semu-fuzz=semu_fuzz.harness:main',
            'semu-fuzz-helper=semu_fuzz.helper.main:main',
        ]
    },
    cmdclass = {
        'build': Build
    },
    include_package_data=True,
    package_data={'semu_fuzz': get_all_files('semu_fuzz', 'emulate', "configuration", "helper", "log", "fuzz")},
)
