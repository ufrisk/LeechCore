CC=gcc
CFLAGS= -I. -I../includes -L. -l:leechcore.so -shared -fPIC -fvisibility=hidden `pkg-config python3 --libs --cflags`

ifeq ($(shell uname), Linux)
CFLAGS  += -D LINUX
LIB = leechcore.so
endif
ifeq ($(shell uname), Darwin)
CFLAGS  += -D MACOS
LIB = leechcore.dylib
endif

LDFLAGS= -Wl,-rpath,'$$ORIGIN' -g -ldl -shared
DEPS = 
OBJ = leechcorepyc.o oscompatibility.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcorepyc: $(OBJ)
	cp ../files/$(LIB) . || true
	$(CC) -o $@ $^ $(CFLAGS) -o $(LIB) $(LDFLAGS)
	mv $(LIB) ../files/ || true
	rm -f *.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f *.so || true
