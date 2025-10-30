  if (len == 0U || t_len == 0U) {
    return GC_MALLOC(0U);
  }

  if (len > SIZE_MAX / t_len) {
    errno = ENOMEM;
    return NULL;
  }

  size_t total = len * t_len;
  void *calloc_mem = GC_MALLOC(total);
  if (calloc_mem == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  memset(calloc_mem, 0, total);
