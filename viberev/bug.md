# Stack Overflow

This is a simple stack overflow demonstration program.

It is a simple test program employed to evaluate Decai's performance across
various models. As you observe, a local buffer variable is filled using an
unbounded string copy which may end up overflowing the stack frame.

Modern compilers replace strcpy with a specific version that, at compile time,
prevents stack return address overwriting. If the stack frame is overwritten,
the canary will trigger an error, halting execution and preventing a potential
code execution exploit.

```c
$ cat stack-overflow/bug.c 

#include <string.h>

int main(int argc, char **argv) {
	char buf[32];
	strcpy (buf, argv[1]);
	return 0;
}
```

But it's helpful to see which recommendations and test different programs that
you can use using Decai to get the correct the compilation of the initial program.

```c
$ r2 buffer-overflow/a.out
[0x100003f58]> decai -d
int main(int argc, char **argv, char **envp) {
    char buffer[32];
    int result = 0;
    
    if (argc > 1 && argv[1] != NULL) {
        strcpy(buffer, argv[1]);
    }
    
    return result;
}
```
