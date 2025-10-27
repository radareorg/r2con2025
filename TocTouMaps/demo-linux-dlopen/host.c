// host.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef void(*hello_t)(void);

int main() {
	void *h = dlopen ("./libdemo.so", RTLD_LAZY);
	if (!h) {
		puts (dlerror ());
		return 1;
	}
	sleep (3);
	hello_t hello = (hello_t)dlsym (h, "hello");
	for (int i = 0; i < 100; i++) {
		hello ();
		sleep (1);
	}
	return 0;
}
