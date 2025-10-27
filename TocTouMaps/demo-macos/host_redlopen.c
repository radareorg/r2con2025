#define _DARWIN_C_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef void(*hello_t)(void);

int main() {
	for (int i = 0; i < 8; i++) {
		void *h = dlopen ("./libdemo.dylib", RTLD_NOW);
		if (!h) {
			fprintf (stderr, "dlopen: %s\n", dlerror ());
			return 1;
		}
		hello_t hello = (hello_t)dlsym (h, "hello");
		if (!hello) {
			fprintf (stderr, "dlsym: %s\n", dlerror ());
			return 1;
		}
		hello ();
		dlclose (h);
		sleep (1);
	}
	return 0;
}
