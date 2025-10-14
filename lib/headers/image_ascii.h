#ifndef SSH_CHATTER_IMAGE_ASCII_H
#define SSH_CHATTER_IMAGE_ASCII_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ascii_palette {
  const char *name;
  const char *characters;
  bool use_color;
} ascii_palette_t;

typedef struct ascii_art {
  char **lines;
  size_t line_count;
} ascii_art_t;

const ascii_palette_t *ascii_palette_default(void);
const ascii_palette_t *ascii_palette_find(const char *name);
void ascii_palette_list(char *buffer, size_t buffer_len);

bool image_to_ascii(const char *path, const ascii_palette_t *palette, ascii_art_t *out);
void ascii_art_free(ascii_art_t *art);

#endif  // SSH_CHATTER_IMAGE_ASCII_H
