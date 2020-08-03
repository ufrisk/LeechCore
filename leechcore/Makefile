CC=gcc
CFLAGS  += -I. -D LINUX -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
LDFLAGS += -g -ldl -shared
DEPS = leechcore.h
OBJ = oscompatibility.o leechcore.o util.o memmap.o device_file.o device_fpga.o device_pmem.o device_tmd.o device_usb3380.o leechrpcclient.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcore: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o leechcore.so $(LDFLAGS)
	rm *.o
	mv leechcore.so ../files/
	true

clean:
	rm -f *.o
