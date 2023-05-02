from ubuntu:22.04
env LANG=C.UTF-8 LC_ALL=C.UTF-8
run apt-get update
# install necessary dependence
run apt-get install -y python3-pip automake sudo git vim clang cmake llvm wget unzip build-essential
# install gnuplot to draw stat block images
run apt-get install -y gnuplot
# install binutils-arm-none-eabi to trans ELF to BIN
run apt-get install -y binutils-arm-none-eabi
# install dependency of AFLplusplus
run apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
# try to install llvm 12 and install the distro default if that fails
run apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
run apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
# for QEMU mode of AFLplusplus
run apt-get install -y ninja-build

COPY . /SEmu-Fuzz
run mkdir /AFLplusplus
run cd / && git clone https://github.com/AFLplusplus/AFLplusplus
run cd /AFLplusplus && git submodule update --remote unicorn_mode
# run wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/4.05c.tar.gz
# run tar xvf 4.05c.tar.gz -C /AFLplusplus --strip-components 1
run make -C /AFLplusplus clean all || exit 1
run make -C /AFLplusplus install || exit 1
run cd /AFLplusplus/unicorn_mode/ && ./build_unicorn_support.sh || exit 1
# fix the libunicorn.so
run cd /AFLplusplus/unicorn_mode/unicornafl/unicorn/build && make install || exit 1
run echo "[+] Success to build AFL!"

run pip3 install /SEmu-Fuzz/.