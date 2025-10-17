CC := cc
CFLAGS = -std=c2x -O1 \
        -Ilib/headers \
        -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
        -fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
        -fsanitize-address-use-after-scope \
        -fno-omit-frame-pointer -fstack-protector-strong -fno-common \
        -fPIC \
        -g
COMMON_LDFLAGS = -fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
        -lpthread -ldl -lcurl
LDFLAGS = $(COMMON_LDFLAGS) -lssh

TARGET := ssh-chatter
SHARED_TARGET := libssh_chatter_backend.so
SRC := main.c lib/host.c lib/client.c lib/webssh_client.c lib/translator.c \
       lib/translation_helpers.c lib/ssh_chatter_backend.c
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
