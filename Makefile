ENABLE_GC ?= 1

CC := gcc
CFLAGS = -std=c2x -Ofast \
	        -Werror \
-Wno-error=deprecated-declarations -DSSH_CHATTER_USE_GC=$(ENABLE_GC) -I lib/headers -I/usr/include -I/usr/include/libssh \
				-D_DEFAULT_SOURCE \
				-D_XOPEN_SOURCE=700 \
        -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
        -fno-omit-frame-pointer -fstack-protector-strong -fno-common \
        -fPIC \
        -g \
	-D_FORTIFY_SOURCE=2 \
	-march=native \
	-flto=$(shell nproc) \
	-fomit-frame-pointer \
	-fno-signed-zeros \
	-funroll-loops \
	-fuse-linker-plugin \
	-falign-functions=32 \
	-falign-loops=32 \
	-ftree-vectorize \
	-fno-math-errno \
	-fmerge-all-constants \
	-fipa-pta \
	-fdevirtualize-at-ltrans \
	-fpeel-loops \
	-fweb \
	-fdata-sections \
       	-ffunction-sections \
	-fno-asynchronous-unwind-tables \
	-fstrict-aliasing \
	-fno-trapping-math \
	-fstrict-overflow \
        -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free \
        -fmerge-all-constants \
        -fipa-pure-const \
        -fipa-cp-clone \
        -floop-nest-optimize \
        -fgraphite-identity -floop-interchange -floop-strip-mine -floop-block \
        -fno-semantic-interposition \
        -MMD -MP \

    COMMON_LDFLAGS = \
        -lpthread -ldl -lcurl -lm -lcrypto -lc \
        -flto=$(shell nproc) -fuse-linker-plugin \
        -Wl,-Ofast \
        -Wl,--sort-common \
        -Wl,-z,relro \
        -Wl,-z,now \
        -Wl,-Bsymbolic \
        -Wl,--gc-sections \
        -Wl,--as-needed \
        -Wl,--strip-all \
        -Wl,--relax \
        -Wl,--no-undefined \
        -Wl,--warn-execstack \
        -Wl,-z,noexecstack \
        -Wl,-z,separate-code
	
LDFLAGS = $(COMMON_LDFLAGS) -lssh

TARGET := ssh-chatter
SHARED_TARGET := libssh_chatter_backend.so
SRC := main.c lib/host.c lib/client.c lib/webssh_client.c lib/translator.c \
       lib/translation_helpers.c lib/ssh_chatter_backend.c lib/user_data.c \
       lib/matrix_client.c lib/security_layer.c lib/memory_manager.c \
       lib/ssh_chatter_sync.c
OBJ := $(SRC:.c=.o)
SHARED_SRC := lib/translator.c lib/translation_helpers.c lib/ssh_chatter_backend.c lib/memory_manager.c
SHARED_OBJ := $(SHARED_SRC:.c=.o)
DEP := $(OBJ:.o=.d)

.PHONY: all clean run

all: $(TARGET) $(SHARED_TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SHARED_TARGET): $(SHARED_OBJ)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(COMMON_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) $(SHARED_TARGET) $(DEP)

-include $(DEP)

ifeq ($(ENABLE_GC),1)
COMMON_LDFLAGS += -lgc
endif
