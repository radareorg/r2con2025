#define _DARWIN_C_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef void(*hello_t)(void);

static void *openlib(const char *path, hello_t *out) {
	void *h = dlopen (path, RTLD_NOW);
	if (!h) {
		fprintf (stderr, "dlopen: %s\n", dlerror ());
		return NULL;
	}
	*out = (hello_t)dlsym (h, "hello");
	if (!*out) {
		fprintf (stderr, "dlsym: %s\n", dlerror ());
		dlclose (h);
		return NULL;
	}
	return h;
}

int main() {
	hello_t hello = NULL;
	void *h = openlib ("./libdemo.dylib", &hello);
	if (!h) {
		return 1;
	}

	for (int i = 0; i < 10; i++) {
		hello ();
		if (i == 4) { // mig camí: re-carrega
			dlclose (h);
			h = openlib ("./libdemo.dylib", &hello);
			if (!h) {
				return 1;
			}
		}
		sleep (1);
	}
	dlclose (h);
	return 0;
}
