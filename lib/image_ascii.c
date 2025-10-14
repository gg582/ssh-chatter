#include "headers/image_ascii.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "headers/palettes.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_GIF
#define STBI_NO_PSD
#define STBI_NO_PIC
#define STBI_NO_PNM
#include "stb_image.h"

static const ascii_palette_t kAsciiPalettes[] = {
    {.name = "color", .characters = " .:-=+*#%@", .use_color = true},
    {.name = "mono", .characters = " .:-=+*#%@", .use_color = false},
};

static size_t palette_count(void) {
  return sizeof(kAsciiPalettes) / sizeof(kAsciiPalettes[0]);
}

const ascii_palette_t *ascii_palette_default(void) {
  return &kAsciiPalettes[0];
}

const ascii_palette_t *ascii_palette_find(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return ascii_palette_default();
  }

  for (size_t idx = 0; idx < palette_count(); ++idx) {
    if (strcasecmp(kAsciiPalettes[idx].name, name) == 0) {
      return &kAsciiPalettes[idx];
    }
  }

  return NULL;
}

void ascii_palette_list(char *buffer, size_t buffer_len) {
  if (buffer == NULL || buffer_len == 0U) {
    return;
  }

  size_t written = 0U;
  int result = snprintf(buffer, buffer_len, "Available palettes: ");
  if (result < 0) {
    buffer[0] = '\0';
    return;
  }

  written = (size_t)result;
  if (written >= buffer_len) {
    buffer[buffer_len - 1U] = '\0';
    return;
  }

  for (size_t idx = 0; idx < palette_count(); ++idx) {
    const ascii_palette_t *palette = &kAsciiPalettes[idx];
    result = snprintf(buffer + written, buffer_len - written, "%s%s", idx == 0 ? "" : ", ",
                      palette->name);
    if (result < 0) {
      buffer[0] = '\0';
      return;
    }
    written += (size_t)result;
    if (written >= buffer_len) {
      buffer[buffer_len - 1U] = '\0';
      return;
    }
  }
}

static unsigned char clamp_channel(int value) {
  if (value < 0) {
    return 0;
  }
  if (value > 255) {
    return 255;
  }
  return (unsigned char)value;
}

static char select_character(const ascii_palette_t *palette, double brightness) {
  const char *characters = palette->characters;
  size_t length = strlen(characters);
  if (length == 0U) {
    return '#';
  }

  if (brightness < 0.0) {
    brightness = 0.0;
  }
  if (brightness > 255.0) {
    brightness = 255.0;
  }

  double scale = brightness / 255.0;
  size_t index = (size_t)(scale * (double)(length - 1U));
  if (index >= length) {
    index = length - 1U;
  }
  return characters[index];
}

bool image_to_ascii(const char *path, const ascii_palette_t *palette, ascii_art_t *out) {
  if (out != NULL) {
    out->lines = NULL;
    out->line_count = 0U;
  }

  if (path == NULL || path[0] == '\0' || palette == NULL || out == NULL) {
    errno = EINVAL;
    return false;
  }

  int width = 0;
  int height = 0;
  int channels = 0;
  stbi_uc *pixels = stbi_load(path, &width, &height, &channels, 0);
  if (pixels == NULL) {
    return false;
  }

  if (width <= 0 || height <= 0) {
    stbi_image_free(pixels);
    errno = EINVAL;
    return false;
  }

  const size_t max_width = 80U;
  size_t output_width = (size_t)width;
  if (output_width == 0U) {
    output_width = 1U;
  }
  if (output_width > max_width) {
    output_width = max_width;
  }

  double x_step = (double)width / (double)output_width;
  if (x_step < 1.0) {
    x_step = 1.0;
  }
  double y_step = x_step * 0.5;
  if (y_step < 1.0) {
    y_step = 1.0;
  }

  size_t max_lines = (size_t)((double)height / y_step) + 2U;
  if (max_lines == 0U) {
    max_lines = 1U;
  }

  char **lines = calloc(max_lines, sizeof(char *));
  if (lines == NULL) {
    stbi_image_free(pixels);
    return false;
  }

  size_t produced = 0U;
  for (double y = 0.0; y < (double)height && produced < max_lines; y += y_step) {
    size_t line_capacity = palette->use_color ? (output_width * 32U + strlen(ANSI_RESET) + 1U)
                                              : (output_width + 1U);
    char *line = calloc(line_capacity, sizeof(char));
    if (line == NULL) {
      ascii_art_t partial = {.lines = lines, .line_count = produced};
      ascii_art_free(&partial);
      stbi_image_free(pixels);
      return false;
    }

    double x = 0.0;
    size_t cursor = 0U;
    for (size_t column = 0; column < output_width; ++column) {
      int sample_x = (int)x;
      int sample_y = (int)y;
      if (sample_x >= width) {
        sample_x = width - 1;
      }
      if (sample_y >= height) {
        sample_y = height - 1;
      }
      size_t pixel_index = ((size_t)sample_y * (size_t)width + (size_t)sample_x) * (size_t)channels;
      unsigned char red = 0;
      unsigned char green = 0;
      unsigned char blue = 0;
      unsigned char alpha = 255;

      if (channels >= 3) {
        red = pixels[pixel_index];
        green = pixels[pixel_index + 1U];
        blue = pixels[pixel_index + 2U];
        if (channels >= 4) {
          alpha = pixels[pixel_index + 3U];
        }
      } else if (channels == 2) {
        unsigned char value = pixels[pixel_index];
        red = value;
        green = value;
        blue = value;
        alpha = pixels[pixel_index + 1U];
      } else if (channels == 1) {
        unsigned char value = pixels[pixel_index];
        red = value;
        green = value;
        blue = value;
      }

      if (alpha < 255) {
        double a = (double)alpha / 255.0;
        red = clamp_channel((int)((double)red * a + 255.0 * (1.0 - a)));
        green = clamp_channel((int)((double)green * a + 255.0 * (1.0 - a)));
        blue = clamp_channel((int)((double)blue * a + 255.0 * (1.0 - a)));
      }

      double brightness = 0.2126 * (double)red + 0.7152 * (double)green + 0.0722 * (double)blue;
      char ch = select_character(palette, brightness);

      if (palette->use_color) {
        int written = snprintf(line + cursor, line_capacity - cursor, "\033[38;2;%u;%u;%um%c",
                               red, green, blue, ch);
        if (written < 0) {
          line[cursor] = '\0';
          break;
        }
        cursor += (size_t)written;
        if (cursor >= line_capacity) {
          cursor = line_capacity - 1U;
          line[cursor] = '\0';
          break;
        }
      } else {
        if (cursor + 1U >= line_capacity) {
          break;
        }
        line[cursor++] = ch;
        line[cursor] = '\0';
      }

      x += x_step;
    }

    if (palette->use_color) {
      size_t remaining = line_capacity - cursor;
      if (remaining > 0U) {
        snprintf(line + cursor, remaining, "%s", ANSI_RESET);
      }
    }

    lines[produced] = line;
    ++produced;
  }

  stbi_image_free(pixels);

  out->lines = lines;
  out->line_count = produced;
  return true;
}

void ascii_art_free(ascii_art_t *art) {
  if (art == NULL || art->lines == NULL) {
    return;
  }

  for (size_t idx = 0; idx < art->line_count; ++idx) {
    free(art->lines[idx]);
    art->lines[idx] = NULL;
  }
  free(art->lines);
  art->lines = NULL;
  art->line_count = 0U;
}
