CFLAGS=-fPIC -Wall
LDFLAGS=-shared -ldl

all: qmuxd_wrapper.so

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

qmuxd_wrapper.so: qmuxd_wrapper.o
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	@rm -f qmuxd_wrapper.so *.o
