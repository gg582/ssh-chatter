#ifndef SSH_CHATTER_HUMANIZED_H
#define SSH_CHATTER_HUMANIZED_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

static inline void humanized_log_error(const char *section, const char *message, int error_code) {
  if (section == NULL || section[0] == '\0') {
    section = "unknown";
  }

  int resolved_error = error_code;
  if (resolved_error == 0) {
    resolved_error = errno;
  }

  const char *fallback = message;
  if (fallback == NULL || fallback[0] == '\0') {
    fallback = strerror(resolved_error);
    if (fallback == NULL || fallback[0] == '\0') {
      fallback = "Unknown error";
    }
  }

  fprintf(stderr, "[%s] %s (code: %d)\n", section, fallback, resolved_error);
}

#endif
