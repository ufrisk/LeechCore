CC=gcc
CFLAGS  += -I. -D LINUX -D _GNU_SOURCE -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
LDFLAGS += -g -ldl -shared
DEPS = leechcore.h
OBJ = oscompatibility.o leechcore.o util.o memmap.o device_file.o device_fpga.o device_pmem.o device_tmd.o device_usb3380.o device_vmware.o leechrpcclient.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcore: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o leechcore.so $(LDFLAGS)
	mv leechcore.so ../files/
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
