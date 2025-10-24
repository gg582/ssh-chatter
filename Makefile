CC := cc
CFLAGS = -std=c2x -Ofast \
        -Ilib/headers \
        -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
        -fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
        -fsanitize-address-use-after-scope \
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
	-fstrict-overflow \
	-fno-trapping-math
COMMON_LDFLAGS = -fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
        -lpthread -ldl -lcurl
LDFLAGS = $(COMMON_LDFLAGS) -lssh

TARGET := ssh-chatter
SHARED_TARGET := libssh_chatter_backend.so
SRC := main.c lib/host.c lib/client.c lib/webssh_client.c lib/translator.c \
       lib/translation_helpers.c lib/ssh_chatter_backend.c lib/user_data.c
OBJ := $(SRC:.c=.o)
SHARED_SRC := lib/translator.c lib/translation_helpers.c lib/ssh_chatter_backend.c
SHARED_OBJ := $(SHARED_SRC:.c=.o)

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
	rm -f $(OBJ) $(TARGET) $(SHARED_TARGET)
