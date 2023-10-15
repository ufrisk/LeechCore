#!/bin/bash

rm -rf pkg_linux
mkdir pkg_linux
mkdir pkg_linux/files
touch pkg_linux/files/dummy
mkdir pkg_linux/leechcorepyc
cp -r ../includes pkg_linux/
cp -r ../leechcore pkg_linux/
cp -r ../../LeechCore-plugins*/leechcore_device_qemu pkg_linux/
cp -r ../../LeechCore-plugins*/leechcore_device_rawtcp pkg_linux/
cp -r ../../LeechCore-plugins*/leechcore_ft601_driver_linux pkg_linux/
cp    ../leechcore/leechcore_device.h pkg_linux/includes/leechcore_device.h
cp    ../LICENSE pkg_linux/
cp    *.h pkg_linux/
cp    *.c pkg_linux/



cat << 'EOF' > pkg_linux/setup.py

import subprocess
from setuptools import setup, Extension

subprocess.call(['make', 'clean'])
subprocess.call(['make'])

leechcorepyc = Extension(
    'leechcorepyc.leechcorepyc',
    sources = ['leechcorepyc.c', 'leechcorepyc_barrequest.c', 'oscompatibility.c'],
    libraries = ['usb-1.0', ':leechcore.so'],
    library_dirs = ['.'],
    define_macros = [("LINUX", "")],
    include_dirs = ["includes", "/usr/include/libusb-1.0/"],
    extra_compile_args=["-I.", "-L.", "-l:leechcore.so", "-shared", "-fPIC", "-fvisibility=hidden"],
    extra_link_args=["-Wl,-rpath,$ORIGIN", "-g", "-ldl", "-shared"],
    py_limited_api=True
    )

setup(
    name='leechcorepyc',
    version='2.16.7', # VERSION_END
    description='LeechCore for Python',
    long_description='LeechCore for Python : native extension for physical memory access',
    url='https://github.com/ufrisk/LeechCore',
    author='Ulf Frisk',
    author_email='pcileech@frizk.net',
    license='GNU General Public License v3.0',
    platforms='manylinux1_x86_64',
    python_requires='>=3.6',
    classifiers=[
		"Programming Language :: C",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
	packages=['leechcorepyc'],
	package_data={'leechcorepyc': ['leechcore.so', 'leechcore_ft601_driver_linux.so', 'leechcore_device_qemu.so', 'leechcore_device_rawtcp.so']},
    ext_modules = [leechcorepyc],
    )

EOF



cat << 'EOF' > pkg_linux/README

LeechCore for Python: please see
https://github.com/ufrisk/LeechCore
and
https://github.com/ufrisk/LeechCore/wiki/LeechCore_API_Python
EOF



cat << 'EOF' > pkg_linux/MANIFEST.in

include Makefile
include leechcorepyc.h
include oscompatibility.h
include includes/*.h
graft files
graft leechcore
graft leechcore_device_rawtcp
graft leechcore_device_sp605tcp
graft leechcore_ft601_driver_linux
global-exclude *vcxproj*
global-exclude *.so

EOF



cat << 'EOF' > pkg_linux/leechcorepyc/__init__.py
from .leechcorepyc import LeechCore

# CONSTANTS AUTO-GENERATED FROM 'leechcore.h' BELOW:
EOF
cat ../includes/leechcore.h |grep "#define LC_" |grep -v "_VERSION  " |grep -v "_FUNCTION_CALLBACK_"  >> pkg_linux/leechcorepyc/__init__.py
sed -i 's/#define //' pkg_linux/leechcorepyc/__init__.py
sed -i 's/0x/= 0x/'   pkg_linux/leechcorepyc/__init__.py
sed -i 's/\/\//#/'    pkg_linux/leechcorepyc/__init__.py



cat << 'EOF' > pkg_linux/Makefile

all:
	$(MAKE) -C leechcore
	$(MAKE) -C leechcore_ft601_driver_linux || true
	$(MAKE) -C leechcore_device_qemu || true
	$(MAKE) -C leechcore_device_rawtcp || true
	cp files/leechcore.so .
	cp files/*.so leechcorepyc/

clean:
	$(MAKE) clean -C leechcore
	$(MAKE) clean -C leechcore_ft601_driver_linux || true
	$(MAKE) clean -C leechcore_device_qemu || true
	$(MAKE) clean -C leechcore_device_rawtcp || true
	rm files/*.so || true
	rm leechcore.so || true
	rm leechcorepyc/*.so || true

EOF

#python3 setup.py sdist
#mkdir ~/tmp
#python3 setup.py bdist_wheel --bdist-dir ~/tmp/ --py-limited-api cp36 --plat-name manylinux1_x86_64
