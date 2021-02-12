from distutils.core import setup, Extension

leechcore_sources = [
"../leechcore/device_file.c",
"../leechcore/device_fpga.c",
"../leechcore/device_pmem.c",
"../leechcore/device_tmd.c",
"../leechcore/device_usb3380.c",
"../leechcore/leechcore.c",
"../leechcore/leechrpcclient.c",
"../leechcore/memmap.c",
"../leechcore/oscompatibility.c",
"../leechcore/util.c",
]

leechcorepyc = Extension('leechcorepyc',
                    sources = ['leechcorepyc.c'] + leechcore_sources,
                    libraries = ['usb-1.0'],
                    define_macros = [("LINUX", "")],
                    include_dirs = ["/usr/include/libusb-1.0/"],
                    )

setup (name = 'leechcorepyc',
       version = '1.7',
       description = 'LeechCore Python bindings',
       ext_modules = [leechcorepyc])
