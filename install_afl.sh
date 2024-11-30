# get afl
pushd .
git config --global core.longpaths true
git clone https://github.com/IoTS-P/AFLplusplus.git
cd AFLplusplus/
make || exit 1
sudo make install || exit 1
cd unicorn_mode/
# get unicornafl
git clone https://github.com/IoTS-P/unicornafl.git
cd unicornafl/
git clone https://github.com/IoTS-P/unicorn.git
# install fuzzemu Native Dependency
# build unicornafl
cp ../../include/config.h ./include
make clean
rm -rf build_python # this build cannot clean by make clean, so need to remove it manually
make -j1 || exit 1
cd bindings/python
pip install .
cd ../../unicorn
# fix libunicorn.so
mkdir build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j8 || exit 1
sudo make install || exit 1
cd ..
rm -rf build_python # this build cannot clean by make clean, so need to remove it manually
cd bindings/python
rm -rf prebuilt build
pip install .
echo "[+] Success to build AFL!"
popd