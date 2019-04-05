CC=gcc
CFLAGS=-I. -D LINUX -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
DEPS = leechcore.h
OBJ = oscompatibility.o leechcore.o util.o memmap.o device_file.o device_fpga.o device_hvsavedstate.o device_pmem.o device_rawtcp.o device_sp605tcp.o device_tmd.o device_usb3380.o tlp.o leechrpcclient.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcore: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o leechcore.so
	rm *.o
	mv leechcore.so ../files/ |true

clean:
	rm -f *.o
