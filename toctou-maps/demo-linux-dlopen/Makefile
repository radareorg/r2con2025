all:
	gcc -shared -fPIC libv1.c -o libdemo.so
	gcc -shared -fPIC libv2.c -o libdemo.new
	gcc host2.c -o host2 -L. -ldemo
	LD_LIBRARY_PATH=$$PWD ./host2

clean:
	rm -f host2
	rm -f libdemo.so
	rm -f libdemo.new
