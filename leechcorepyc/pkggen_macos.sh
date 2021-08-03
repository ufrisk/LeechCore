#!/bin/bash

rm -rf pkg_macos
mkdir pkg_macos
mkdir pkg_macos/files
touch pkg_macos/files/dummy
mkdir pkg_macos/leechcorepyc
cp -r ../includes pkg_macos/
cp -r ../leechcore pkg_macos/
cp -r ../../LeechCore-plugins*/leechcore_ft601_driver_linux pkg_macos/
cp    ../leechcore/leechcore_device.h pkg_macos/includes/leechcore_device.h
cp    ../LICENSE pkg_macos/
cp    *.h pkg_macos/
cp    *.c pkg_macos/



cat << 'EOF' > pkg_macos/setup.py

import os
import subprocess
from setuptools import setup, Extension

# Prevent the default (Apple) python3 install from building universal binaries with arm64 support
os.environ['ARCHFLAGS'] = '-arch x86_64'

subprocess.call(['make', 'clean'])
subprocess.call(['make'])

leechcorepyc = Extension(
    'leechcorepyc.leechcorepyc',
    sources = ['leechcorepyc.c', 'oscompatibility.c'],
    libraries = ['usb-1.0', 'leechcore'],
    library_dirs = ['.'],
    define_macros = [("MACOS", "")],
    include_dirs = ["includes", "/usr/local/include/libusb-1.0/"],
    extra_compile_args=["-I.", "-fPIC", "-fvisibility=hidden"],
    extra_link_args=["-g", "-ldl"],
    py_limited_api=True
    )

setup(
    name='leechcorepyc',
    version='2.6.2', # VERSION_END
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
	package_data={'leechcorepyc': ['leechcore.dylib', 'leechcore_ft601_driver_linux.dylib']},
    ext_modules = [leechcorepyc],
    )

EOF



cat << 'EOF' > pkg_macos/README

LeechCore for Python: please see
https://github.com/ufrisk/LeechCore
and
https://github.com/ufrisk/LeechCore/wiki/LeechCore_API_Python
EOF



cat << 'EOF' > pkg_macos/MANIFEST.in

include Makefile
include oscompatibility.h
include includes/*.h
graft files
graft leechcore
graft leechcore_ft601_driver_linux
global-exclude *vcxproj*
global-exclude *.dylib

EOF



cat << 'EOF' > pkg_macos/leechcorepyc/__init__.py
from .leechcorepyc import LeechCore

# CONSTANTS AUTO-GENERATED FROM 'leechcore.h' BELOW:
EOF
cat ../includes/leechcore.h |grep "#define LC_" |grep -v "_VERSION  " >> pkg_macos/leechcorepyc/__init__.py
sed -i xx 's/#define //' pkg_macos/leechcorepyc/__init__.py
sed -i xx 's/0x/= 0x/'   pkg_macos/leechcorepyc/__init__.py
sed -i xx 's/\/\//#/'    pkg_macos/leechcorepyc/__init__.py



# it's painfull to link with clang if the dylib doesn't start with "lib" prefix
# so we just link leechcore.dylib as libleechcore.dylib
cat << 'EOF' > pkg_macos/Makefile

all:
	$(MAKE) -C leechcore
	$(MAKE) -C leechcore_ft601_driver_linux || true
	cp files/leechcore.dylib leechcore.dylib
	ln -s leechcore.dylib libleechcore.dylib
	cp files/*.dylib leechcorepyc/

clean:
	$(MAKE) clean -C leechcore
	$(MAKE) clean -C leechcore_ft601_driver_linux || true
	rm files/*.dylib || true
	rm libleechcore.dylib || true
	rm leechcorepyc/*.dylib || true

EOF
