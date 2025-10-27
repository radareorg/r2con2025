#!/bin/sh
r2 -e scr.color=0 -AA -qc 'pdc@@F' ../libmmfv4l2.so.0 \
	> allfuncs.txt
exit 0
cat allfuncs.txt | mai -p openai -m gpt-5-mini \
	'recreate the full implementation of all these functions written in pseudocode using high level C code that can be recompiled and add useful comments and readable variable names, removing unnecessary boilerplate' \
	> allfuncs.c

