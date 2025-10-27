```console
[0x001383c0]> iic
|- buffer:
|  |- strcat
|  |- memcpy
|  |- vsprintf
|  |- vsnprintf
|- console:
|  |- puts
|  |- fflush
|- dir:
|  |- getcwd
|- eeprom:
|  |- eeprom_read
|  |- eeprom_write
|  |- eeprom_create
|  |- eeprom_destroy
|  |- eeprom_unprepare
|  |- eeprom_prepare
|- environment:
|  |- getenv
|- error:
|  |- perror
|  |- abort
|- exec:
|  |- system
|- file:
|  |- fseek
|  |- unlink
|  |- open
|  |- fread
|- format:
|  |- printf
|  |- snprintf
|  |- sprintf
|  |- sscanf
|- global:
|  |- qsort
|  |- asctime
|  |- strerror
|  |- strtok
|  |- gethostbyname
|  |- localtime
|  |- srand48
|- heap:
|  |- free
|  |- malloc
|- io:
|  |- recv
|  |- read
|  |- open
|  |- write
|- math:
|  |- atan
|  |- sqrt
|  |- exp
|  |- pow
|  |- ceil
|  |- atan2
|  |- floor
|- network:
|  |- recv
|  |- listen
|  |- bind
|  |- setsockopt
|  |- select
|  |- connect
|  |- accept
|  |- send
|- process:
|  |- exit
|- random:
|  |- srand48
|  |- srand
|- signal:
|  |- signal
|  |- sigaction
|- string:
|  |- strtol
|  |- strtok
|  |- strcpy
|  |- strstr
|  |- strncat
|  |- strlen
|  |- strncpy
|  |- strrchr
|  |- strchr
|- thread:
|  |- pthread_exit
|  |- pthread_join
|  |- fork
|  |- pthread_cancel
|  |- pthread_create
|- time:
|  |- nanosleep
|  |- gmtime
|  |- usleep
|  |- time
|- unsafe:
|  |- strtok
```
