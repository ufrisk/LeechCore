CC=gcc

CFLAGS  += -I. -D _GNU_SOURCE -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
ifeq ($(shell uname), Linux)
CFLAGS  += -D LINUX
LIB = leechcore.so
endif
ifeq ($(shell uname), Darwin)
LIB = leechcore.dylib
CFLAGS  += -D MACOS -install_name @loader_path/$(LIB)
endif

LDFLAGS += -g -ldl -shared
DEPS = leechcore.h
OBJ = oscompatibility.o leechcore.o util.o memmap.o device_file.o device_fpga.o device_pmem.o device_tmd.o device_usb3380.o leechrpcclient.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcore: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -o $(LIB) $(LDFLAGS)
	mv $(LIB) ../files/
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
