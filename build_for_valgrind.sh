#!/bin/bash
make clean
CC=gcc \
CFLAGS="-std=c2x -O0 -g -DSSH_CHATTER_USE_GC=0 -I lib/headers -I/usr/include -I/usr/include/libssh -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -Wall -Wextra -fno-omit-frame-pointer -Wno-error=format-truncation -Wno-error=all -MMD -MP" \
COMMON_LDFLAGS="-lpthread -ldl -lcurl -lm -lcrypto -lc" \
LDFLAGS="-lpthread -ldl -lcurl -lm -lcrypto -lc -lssh" \
ENABLE_GC=0 \
make "$@"
