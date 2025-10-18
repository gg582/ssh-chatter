#include "headers/translation_helpers.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

bool translation_prepare_text(const char *message, char *sanitized, size_t sanitized_len,
                              translation_placeholder_t *placeholders, size_t *placeholder_count) {
  if (message == NULL || sanitized == NULL || sanitized_len == 0U || placeholders == NULL || placeholder_count == NULL) {
    return false;
  }

  size_t out_idx = 0U;
  size_t stored = 0U;

  for (size_t idx = 0U; message[idx] != '\0';) {
    unsigned char ch = (unsigned char)message[idx];
    if (ch == '\033') {
      if (stored >= SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS) {
        return false;
      }

      size_t seq_start = idx;
      ++idx;
      if (message[idx] != '\0' && message[idx] == '[') {
        ++idx;
        while (message[idx] != '\0') {
          unsigned char seq_char = (unsigned char)message[idx++];
          if (seq_char >= '@' && seq_char <= '~') {
            break;
          }
        }
      } else if (message[idx] != '\0') {
        ++idx;
      }
      size_t seq_end = idx;
      if (seq_end <= seq_start) {
        seq_end = seq_start + 1U;
      }
      size_t sequence_len = seq_end - seq_start;
      if (sequence_len >= SSH_CHATTER_PLACEHOLDER_SEQUENCE_LEN) {
        return false;
      }

      memcpy(placeholders[stored].sequence, message + seq_start, sequence_len);
      placeholders[stored].sequence[sequence_len] = '\0';
      int written = snprintf(placeholders[stored].placeholder, sizeof(placeholders[stored].placeholder), "[[ANSI%zu]]",
                             stored);
      if (written < 0 || (size_t)written >= sizeof(placeholders[stored].placeholder)) {
        return false;
      }

      if (out_idx + (size_t)written >= sanitized_len) {
        return false;
      }

      memcpy(sanitized + out_idx, placeholders[stored].placeholder, (size_t)written);
      out_idx += (size_t)written;
      ++stored;
    } else {
      if (out_idx + 1U >= sanitized_len) {
        return false;
      }
      sanitized[out_idx++] = (char)ch;
      ++idx;
    }
  }

  if (out_idx >= sanitized_len) {
    sanitized[sanitized_len - 1U] = '\0';
    return false;
  }

  sanitized[out_idx] = '\0';
  *placeholder_count = stored;
  return true;
}

bool translation_restore_text(const char *translated, char *output, size_t output_len,
                              const translation_placeholder_t *placeholders, size_t placeholder_count) {
  if (translated == NULL || output == NULL || output_len == 0U) {
    return false;
  }

  size_t out_idx = 0U;
  size_t idx = 0U;
  const size_t input_len = strlen(translated);

  while (idx < input_len) {
    bool replaced = false;
    for (size_t token = 0U; token < placeholder_count; ++token) {
      const size_t placeholder_len = strlen(placeholders[token].placeholder);
      if (placeholder_len == 0U) {
        continue;
      }
      if (strncmp(translated + idx, placeholders[token].placeholder, placeholder_len) == 0) {
        const size_t sequence_len = strlen(placeholders[token].sequence);
        if (out_idx + sequence_len >= output_len) {
          if (output_len > 0U) {
            output[output_len - 1U] = '\0';
          }
          return false;
        }
        memcpy(output + out_idx, placeholders[token].sequence, sequence_len);
        out_idx += sequence_len;
        idx += placeholder_len;
        replaced = true;
        break;
      }
    }
    if (replaced) {
      continue;
    }
    if (out_idx + 1U >= output_len) {
      if (output_len > 0U) {
        output[output_len - 1U] = '\0';
      }
      return false;
    }
    output[out_idx++] = translated[idx++];
  }

  if (out_idx >= output_len) {
    output[output_len - 1U] = '\0';
  } else {
    output[out_idx] = '\0';
  }

  return true;
}

bool translation_strip_no_translate_prefix(const char *message, char *stripped, size_t stripped_len) {
  if (stripped != NULL && stripped_len > 0U) {
    stripped[0] = '\0';
  }

  if (message == NULL || stripped == NULL || stripped_len == 0U) {
    return false;
  }

  if (message[0] != '@') {
    return false;
  }

  char first = message[1];
  char second = message[2];
  if (!((first == 'n' || first == 'N') && (second == 't' || second == 'T'))) {
    return false;
  }

  char trailing = message[3];
  if (trailing != '\0' && !isspace((unsigned char)trailing)) {
    return false;
  }

  const char *body = message + 3;
  while (*body != '\0' && isspace((unsigned char)*body)) {
    ++body;
  }

  snprintf(stripped, stripped_len, "%s", body);
  return true;
}
