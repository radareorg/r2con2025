all:
	dd if=/dev/zero of=/tmp/mm.bin bs=1k count=64
	gcc -O2 reader.c -o reader
	gcc -O2 writer.c -o writer
	valgrind ./reader /tmp/mm.bin &
	./writer /tmp/mm.bin   
clean:
	rm -f reader writer
