#!/bin/bash
VIRTUALENV_NAME=semu

export PATH=$PATH:~/.local/bin

# install necessary python dependence for create virtualenv
pip3 install virtualenv virtualenvwrapper cython setuptools

# fix python3.8
sudo -S apt install software-properties-common -y
sudo -S add-apt-repository ppa:deadsnakes/ppa
sudo -S apt update
sudo -S apt install python3.8 -y
sudo -S apt install python3.8-distutils -y

# fix gcc
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update

# fix cmake
# CMake 3.13.4 or higher is required to build LLVM-13 from source.
# Ubuntu 18.04 comes with cmake 3.10.2
# Install the latest cmake (as of this writing)
wget -O cmake.sh https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-Linux-x86_64.sh && \
    sudo sh ./cmake.sh --prefix=/usr/local --skip-license

# setup environment variable of virtualenv
if [ -z $VIRTUALENVWRAPPER_PYTHON ]; then
    echo "export VIRTUALENVWRAPPER_PYTHON=python3.8" >> ~/.bashrc
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
workon $VIRTUALENV_NAME 2>/dev/null || mkvirtualenv $VIRTUALENV_NAME --python=python3.8 && workon $VIRTUALENV_NAME
echo "[+] Success to workon virtualenv!"

# fix llvm for AFLplusplus
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo -S apt-key add -
echo "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-12 main" | sudo tee -a /etc/apt/sources.list
sudo -S apt-get update
sudo -S apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 12 and install the distro default if that fails
sudo -S apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo -S apt-get install -y lld llvm llvm-dev clang
sudo -S apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo -S apt-get install -y ninja-build # for QEMU mode

# get afl
git config --global core.longpaths true
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus/
make || exit 1
sudo make install || exit 1
git -C unicorn_mode submodule foreach --recursive git pull origin master || exit 1 # don't update other submodule
cd unicorn_mode/
./build_unicorn_support.sh || exit 1
# fix the libunicorn.so
cd unicornafl/unicorn/build/
sudo make install || exit 1
cd ../../../
echo "[+] Success to build AFL!"

cd ../../

# install EmuWP-Fuzz
pip install . || exit 1
semu-fuzz-helper config samples/base_configs.yml || exit 1
semu-fuzz samples/base_inputs/sample1.bin samples/semu_config.yml || exit 1
echo "Success to install EmuWP-Fuzz!"