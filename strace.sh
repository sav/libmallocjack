#!/bin/sh
strace -E LD_PRELOAD=./libmallocjack.so ./test-ld > /tmp/test.log
