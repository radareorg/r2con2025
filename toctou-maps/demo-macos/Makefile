CC=clang
CFLAGS=-O2 -Wall

all: libdemo.dylib libdemo.new host_reload host_redlopen reader trunc
	$(MAKE) run-sigbus

libdemo.dylib: libv1.c
	$(CC) -dynamiclib -fPIC -o $@ $< -install_name @rpath/libdemo.dylib

libdemo.new: libv2.c
	$(CC) -dynamiclib -fPIC -o $@ $< -install_name @rpath/libdemo.dylib

host_reload: host_reload.c
	$(CC) $(CFLAGS) -o $@ $<

host_redlopen: host_redlopen.c
	$(CC) $(CFLAGS) -o $@ $<

reader: sigbus_reader.c
	$(CC) $(CFLAGS) -o $@ $<

trunc: sigbus_truncate.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f host_reload host_redlopen reader trunc libdemo.dylib libdemo.new /tmp/mm.bin

run-sigbus:
	dd if=/dev/zero of=/tmp/mm.bin bs=1k count=64
	./reader /tmp/mm.bin & echo $$! > /tmp/reader.pid
	sleep 1; ./trunc /tmp/mm.bin || true

run-rename-reload: all
	# XXX this is not a valid demo
	DYLD_PRINT_LIBRARIES=1 ./host_reload & \
	sleep 3; mv libdemo.new libdemo.dylib

run-redlopen: all
	# XXX this is not a valid demo
	DYLD_PRINT_LIBRARIES=1 ./host_redlopen & \
	sleep 3; mv libdemo.new libdemo.dylib

try-inplace:
	python3 inplace_write.py || true
