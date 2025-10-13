CC := cc
CFLAGS := -std=c11 -Wall -Wextra -Werror -Ilib/headers
LDFLAGS := -lpthread
TARGET := ssh-chatter
SRC := main.c lib/host.c lib/stubs/libssh_stub.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
