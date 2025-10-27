import os, errno
fd = os.open("libdemo.dylib", os.O_WRONLY)
try:
    os.pwrite(fd, b"X"*16, 0)
    print("WRITE OK (sorprenent!)")
except OSError as e:
    # esperable: [Errno 16] Text file busy (resource busy)
    print("WRITE FAILED:", e)
os.close(fd)
