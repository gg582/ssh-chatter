CC := cc
CFLAGS = -std=c2x -O1 \
	-Ilib/headers \
	-Wall -Wextra -Werror -Wshadow -Wformat=2 -Wundef -Wconversion -Wdouble-promotion \
	-fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
	-fsanitize-address-use-after-scope \
	-fno-omit-frame-pointer -fstack-protector-strong -fno-common \
	-g
LDFLAGS = -fsanitize=address,leak,undefined,shift,bounds,float-divide-by-zero,vptr \
	-lpthread -lssh -ldl

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
