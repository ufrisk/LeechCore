CC=gcc
CFLAGS  += -I. -D LINUX -D _GNU_SOURCE -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
#CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter
CFLAGS  += -fPIE -fPIC -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-unused-result -Wno-unused-variable -Wno-unused-value -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
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
