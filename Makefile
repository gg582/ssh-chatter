CC := cc
CFLAGS := -std=c2x -Wall -Wextra -Werror -Ilib/headers -fsanitize=address,leak
LDFLAGS := -lpthread -lssh -ldl
TARGET := ssh-chatter
SRC := main.c lib/host.c
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
