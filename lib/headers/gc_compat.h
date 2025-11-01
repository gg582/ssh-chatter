#ifndef SSH_CHATTER_GC_COMPAT_H
#define SSH_CHATTER_GC_COMPAT_H

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

static inline void GC_INIT(void) {
  /* No-op when not using a garbage collector. */
}

static inline void *GC_MALLOC(size_t size) {
  if (size == 0U) {
    size = 1U;
  }
  void *ptr = malloc(size);
  if (ptr == NULL) {
    errno = ENOMEM;
  }
  return ptr;
}

static inline void *GC_REALLOC(void *ptr, size_t size) {
  if (size == 0U) {
    size = 1U;
  }
  void *result = realloc(ptr, size);
  if (result == NULL) {
    errno = ENOMEM;
  }
  return result;
}

static inline void GC_FREE(void *ptr) {
  free(ptr);
}

#endif /* SSH_CHATTER_GC_COMPAT_H */
