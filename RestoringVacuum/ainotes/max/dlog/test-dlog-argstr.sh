#!/bin/sh
# this line requires r2 from git. this bug was affecting arm32
r2 -qc 's 0x00130ee0;af;afs void dlog_print(int,int,char*,char*);e emu.str=true;s 0x003ab730;pd 10~dlog_print' /tmp/max
