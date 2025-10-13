#ifndef PALETTES_H
#define PALETTES_H

#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_RED        "\033[31m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_WHITE      "\033[37m"
#define ANSI_GREY       "\033[90m"
#define ANSI_DEFAULT    "\033[39m"

#define ANSI_BG_BLACK   "\033[40m"
#define ANSI_BG_RED     "\033[41m"
#define ANSI_BG_GREEN   "\033[42m"
#define ANSI_BG_YELLOW  "\033[43m"
#define ANSI_BG_BLUE    "\033[44m"
#define ANSI_BG_MAGENTA "\033[45m"
#define ANSI_BG_CYAN    "\033[46m"
#define ANSI_BG_WHITE   "\033[47m"
#define ANSI_BG_GREY    "\033[100m"
#define ANSI_BG_DEFAULT "\033[49m"
#include <stddef.h>
#include <stdio.h>

static inline int ansi_256(char *buffer, size_t buffer_len, unsigned int color_code) {
  if (buffer_len == 0) {
    return 0;
  }
  return snprintf(buffer, buffer_len, "\033[38;5;%um", color_code);
}

#endif
