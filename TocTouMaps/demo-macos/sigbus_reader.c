#define _DARWIN_C_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void on_sigbus(int sig) {
	(void)sig;
	write (2, "SIGBUS (macOS)\n", 15);
	_exit (1);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "usage: %s file\n", argv[0]);
		return 1;
	}
	signal (SIGBUS, on_sigbus);

	int fd = open (argv[1], O_RDONLY);
	if (fd < 0) {
		perror ("open");
		return 1;
	}

	struct stat st;
	if (fstat (fd, &st) < 0) {
		perror ("fstat");
		return 1;
	}
	size_t sz = st.st_size? (size_t)st.st_size: 4096;

	char *p = mmap (NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		perror ("mmap");
		return 1;
	}
	close (fd);

	for (;;) {
		volatile unsigned long sum = 0;
		for (size_t i = 0; i < sz; i += 4096) {
			sum += p[i];
		}
		sum += p[sz - 1]; // forcem accés al final
		usleep (100000);
	}
}
