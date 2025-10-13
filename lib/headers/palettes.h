#ifndef PALETTES_H
#define PALETTES_H

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#include <stddef.h>
#include <stdio.h>

static inline int ansi_256(char *buffer, size_t buffer_len, unsigned int color_code) {
  if (buffer_len == 0) {
    return 0;
  }
  return snprintf(buffer, buffer_len, "\033[38;5;%um", color_code);
}

#endif
