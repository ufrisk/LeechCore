CC=gcc
CFLAGS  += -I. -I../includes/ -D LINUX -D _GNU_SOURCE -fPIC -fvisibility=hidden -pthread
CFLAGS  += -fPIE -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O1
CFLAGS  += -Wall -Wno-multichar -Wno-unused-result -Wno-unused-variable -Wno-unused-value -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
endif
LDFLAGS +=-Wl,-rpath,'$$ORIGIN' -ldl -L. -l:leechcore.so -Wl,-z,noexecstack
DEPS = leechagent.h
OBJ = oscompatibility.o leechagent.o leechrpcshared.o leechagent_rpc.o leechrpcserver.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechagent: $(OBJ)
	cp ../files/leechcore.so . || cp ../../LeechCore*/files/leechcore.so . || true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	mv leechagent ../files/ |true
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
