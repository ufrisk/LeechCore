CC=gcc
CFLAGS  += -I. -D LINUX -D _GNU_SOURCE -shared -fPIC -fvisibility=hidden -pthread `pkg-config libusb-1.0 --libs --cflags`
# DEBUG FLAGS BELOW
# export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:detect_invalid_pointer_pairs=2
# CFLAGS  += -g -O0 -Wextra -Wno-unused-parameter -Wno-cast-function-type
# CFLAGS  += -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer -fsanitize=undefined -fsanitize=bounds-strict -fsanitize=float-divide-by-zero -fsanitize=float-cast-overflow
# CFLAGS  += -fsanitize=pointer-compare -fsanitize=pointer-subtract -fanalyzer
# DEBUG FLAGS ABOVE
CFLAGS  += -fPIE -fPIC -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-multichar -Wno-unused-result -Wno-unused-variable -Wno-unused-value -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
LDFLAGS += -g -ldl -shared
DEPS = leechcore.h
OBJ = oscompatibility.o leechcore.o util.o memmap.o device_file.o device_fpga.o device_pmem.o device_tmd.o device_usb3380.o device_vmm.o device_vmware.o leechrpcclient.o ob/ob_core.o ob/ob_map.o ob/ob_set.o ob/ob_bytequeue.o

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
