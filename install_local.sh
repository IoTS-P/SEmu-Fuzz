#!/bin/bash
VIRTUALENV_NAME=semu

export PATH=$PATH:~/.local/bin

# install necessary python dependence for create virtualenv
pip3 install virtualenv virtualenvwrapper cython setuptools

# setup environment variable of virtualenv
if [ -z $VIRTUALENVWRAPPER_PYTHON ]; then
    echo "export VIRTUALENVWRAPPER_PYTHON=python3" >> ~/.bashrc
fi

# setup environment variable of virtualenvwrapper
VIRTUALENVWRAPPER_PATH="$(which virtualenvwrapper.sh)"
if ! mkvirtualenv >/dev/null 2>&1; then
    echo "source ~/.local/bin/virtualenvwrapper.sh" >> ~/.bashrc
    echo "[*] Add virtualenvwrapper.sh...!"
fi
source ~/.bashrc
source "$(which virtualenvwrapper.sh)" # fix the sh error: cannot find workon/mkvirtualenv
echo "[+] Success to setup environment variable of virtualenv!"

# workon virtualenv
workon $VIRTUALENV_NAME 2>/dev/null || mkvirtualenv $VIRTUALENV_NAME --python=python3 && workon $VIRTUALENV_NAME
echo "[+] Success to workon virtualenv!"

# get afl
git config --global core.longpaths true
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus/
make || exit 1
sudo make install || exit 1
git submodule update --remote unicorn_mode || exit 1 # don't update other submodule
cd unicorn_mode/
./build_unicorn_support.sh || exit 1
# fix the libunicorn.so
cd unicornafl/unicorn/build/
sudo make install || exit 1
cd ../../../
echo "[+] Success to build AFL!"

cd ../../

# install SEmu-Fuzz
pip install . || exit 1
semu-fuzz samples/base_inputs/sample1.bin samples/semu_config.yml || exit 1
echo "Success to install SEmu-Fuzz!"