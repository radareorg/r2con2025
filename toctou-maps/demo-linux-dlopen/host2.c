#include <unistd.h>
extern void hello(void);
int main() {
	while (1) {
		hello ();
		sleep (1);
	}
}
