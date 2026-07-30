CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-variable -I../leechcore -I../includes -D LINUX -D _GNU_SOURCE

.PHONY: all clean linux-codegen-check

all: device_fpga_read_policy_test device_fpga_session_linux_test \
	linux-codegen-check

SESSION_CFLAGS = $(CFLAGS) -Wno-unused-parameter \
	-Wno-stringop-truncation \
	$(shell pkg-config libusb-1.0 --cflags)
SESSION_LDLIBS = $(shell pkg-config libusb-1.0 --libs) -ldl

device_fpga_read_policy_test: device_fpga_read_policy_test.c ../leechcore/device_fpga_read_policy.c ../leechcore/device_fpga_read_policy.h
	$(CC) $(CFLAGS) -o $@ device_fpga_read_policy_test.c ../leechcore/device_fpga_read_policy.c

device_fpga_session_linux_test: device_fpga_session_linux_test.c \
	../leechcore/device_fpga_session.c \
	../leechcore/device_fpga_session.h \
	../leechcore/oscompatibility.c
	$(CC) $(SESSION_CFLAGS) -pthread -o $@ \
		device_fpga_session_linux_test.c \
		../leechcore/device_fpga_session.c \
		../leechcore/oscompatibility.c \
		$(SESSION_LDLIBS)

linux-codegen-check:
	bash ./check_linux_fpga_session_codegen.sh

clean:
	rm -f device_fpga_read_policy_test device_fpga_session_linux_test
