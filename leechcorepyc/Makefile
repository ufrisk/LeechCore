CC=gcc
CFLAGS= -I. -I../includes -D LINUX  -L. -l:leechcore.so -shared -fPIC -fvisibility=hidden `pkg-config python3 --libs --cflags`
LDFLAGS= -Wl,-rpath,'$$ORIGIN' -g -ldl -shared
DEPS = 
OBJ = leechcorepyc.o leechcorepyc_barrequest.o oscompatibility.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

leechcorepyc: $(OBJ)
	cp ../files/leechcore.so . || true
	$(CC) -o $@ $^ $(CFLAGS) -o leechcorepyc.so $(LDFLAGS)
	mv leechcorepyc.so ../files/ || true
	rm -f *.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f *.so || true
