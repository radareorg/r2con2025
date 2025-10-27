#!/bin/sh
r2 -AA -qc 'pdc@@F' ../libmmfrvcsensor.so.0 \
	| tee allfuncs.txt \
	| mai -p openai -m gpt-5-mini \
	'recreate the full implementation of all these functions written in pseudocode using high level C code that can be recompiled and add useful comments and readable variable names, removing unnecessary boilerplate' \
	> allfuncs.c

