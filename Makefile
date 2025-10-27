CC := cc
CFLAGS = -std=c2x -Ofast \
        -Ilib/headers \
        -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
        -fno-omit-frame-pointer -fstack-protector-strong -fno-common \
        -fPIC \
        -g -lgc \
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
	-fstrict-overflow \
	-fno-trapping-math \
        -DGC_THREADS \
        -DPARALLEL_MARK \
        -DNO_DEBUGGING \
        -DUSE_MMAP \
        -DUSE_MUNMAP \
        -DGC_LARGE_ALLOC \
        -DGC_ATOMIC_UNCOLLECTABLE \
        -DGC_ENABLE_INCREMENTAL \
        -DGC_TIME_LIMIT=50 \
        -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free \
        -fmerge-all-constants \
        -fipa-pure-const \
        -fipa-cp-clone \
        -floop-nest-optimize \
        -fgraphite-identity -floop-interchange -floop-strip-mine -floop-block \
        -fno-semantic-interposition \
        -MMD -MP \

    COMMON_LDFLAGS = \
        -lpthread -ldl -lcurl -lm -lgc \
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
       lib/translation_helpers.c lib/ssh_chatter_backend.c lib/user_data.c
OBJ := $(SRC:.c=.o)
SHARED_SRC := lib/translator.c lib/translation_helpers.c lib/ssh_chatter_backend.c
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
