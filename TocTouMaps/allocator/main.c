#include <stdio.h>
#include <string.h>
#include "myheap.inc.c"

int main() {
	char *a = my_malloc (4);
	strcpy (a, "hello WORLD");
	printf ("%s\n", a);
	my_free (a);
	return 0;
}
