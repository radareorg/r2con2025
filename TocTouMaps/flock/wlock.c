// writer_flock.c
#include <sys/file.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "usage: %s file\n", argv[0]);
		return 1;
	}
	int fd = open (argv[1], O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror ("open");
		return 1;
	}
	if (flock (fd, LOCK_EX) < 0) {
		perror ("flock");
		return 1;
	}
	ftruncate (fd, 0);
	const char *msg = "coherent write\n";
	write (fd, msg, strlen (msg));
	fsync (fd);
	flock (fd, LOCK_UN);
	close (fd);
	return 0;
}
