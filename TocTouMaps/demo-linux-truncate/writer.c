#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "usage: %s file\n", argv[0]);
		return 1;
	}
	const char *path = argv[1];

	sleep (1);
	int fd = open (path, O_WRONLY);
	if (fd < 0) {
		perror ("open");
		return 1;
	}

	// truncate the file while the reader is using the mmaped version of it
	if (ftruncate (fd, 0) < 0) {
		perror ("ftruncate");
		return 1;
	}

	const char *msg = "hello\n";
	if (write (fd, msg, strlen (msg)) < 0) {
		perror ("write");
		return 1;
	}
	fsync (fd);
	close (fd);
	return 0;
}
