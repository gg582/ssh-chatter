#include "headers/translator.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRANSLATOR_MAX_RESPONSE 65536
#define TRANSLATOR_DEFAULT_BASE_URL "https://api.openai.com/v1"

typedef struct translator_buffer {
  char *data;
  size_t length;
} translator_buffer_t;

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_curl_initialised = false;

void translator_global_init(void) {
  pthread_mutex_lock(&g_init_mutex);
  if (!g_curl_initialised) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {
      g_curl_initialised = true;
    }
  }
  pthread_mutex_unlock(&g_init_mutex);
}

static size_t translator_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  const size_t total = size * nmemb;
  translator_buffer_t *buffer = (translator_buffer_t *)userp;
  if (buffer == NULL) {
    return 0U;
  }

  if (total == 0U) {
    return 0U;
  }

  if (buffer->length + total + 1U > TRANSLATOR_MAX_RESPONSE) {
    return 0U;
  }

  char *resized = realloc(buffer->data, buffer->length + total + 1U);
  if (resized == NULL) {
    return 0U;
  }

  buffer->data = resized;
  memcpy(buffer->data + buffer->length, contents, total);
  buffer->length += total;
  buffer->data[buffer->length] = '\0';
  return total;
}

static char *translator_escape_string(const char *input) {
  if (input == NULL) {
    return NULL;
  }

  size_t required = 1U; // null terminator
  for (const unsigned char *cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
    switch (*cursor) {
      case '\\':
      case '"':
        required += 2U;
        break;
      case '\n':
      case '\r':
      case '\t':
        required += 2U;
        break;
      default:
        required += 1U;
        break;
    }
  }

  char *escaped = malloc(required);
  if (escaped == NULL) {
    return NULL;
  }

  size_t offset = 0U;
  for (const unsigned char *cursor = (const unsigned char *)input; *cursor != '\0'; ++cursor) {
    switch (*cursor) {
      case '\\':
      case '"':
        escaped[offset++] = '\\';
        escaped[offset++] = (char)*cursor;
        break;
      case '\n':
        escaped[offset++] = '\\';
        escaped[offset++] = 'n';
        break;
      case '\r':
        escaped[offset++] = '\\';
        escaped[offset++] = 'r';
        break;
      case '\t':
        escaped[offset++] = '\\';
        escaped[offset++] = 't';
        break;
      default:
        escaped[offset++] = (char)*cursor;
        break;
    }
  }

  escaped[offset] = '\0';
  return escaped;
}

static char *translator_extract_payload_text(const char *response) {
  if (response == NULL) {
    return NULL;
  }

  const char *type_marker = "\"type\":\"output_text\"";
  const char *type_pos = strstr(response, type_marker);
  if (type_pos == NULL) {
    return NULL;
  }

  const char *text_marker = "\"text\":\"";
  const char *text_pos = strstr(type_pos, text_marker);
  if (text_pos == NULL) {
    return NULL;
  }

  text_pos += strlen(text_marker);
  size_t capacity = strlen(text_pos) + 1U;
  char *payload = malloc(capacity);
  if (payload == NULL) {
    return NULL;
  }

  size_t out_idx = 0U;
  bool escape = false;
  for (const char *cursor = text_pos; *cursor != '\0'; ++cursor) {
    const char ch = *cursor;
    if (!escape && ch == '\\') {
      escape = true;
      continue;
    }
    if (!escape && ch == '"') {
      break;
    }

    char decoded = ch;
    if (escape) {
      switch (ch) {
        case 'n':
          decoded = '\n';
          break;
        case 'r':
          decoded = '\r';
          break;
        case 't':
          decoded = '\t';
          break;
        case '\\':
          decoded = '\\';
          break;
        case '"':
          decoded = '"';
          break;
        default:
          decoded = ch;
          break;
      }
      escape = false;
    }

    payload[out_idx++] = decoded;
  }

  payload[out_idx] = '\0';
  return payload;
}

static bool translator_extract_json_value(const char *json, const char *key, char *dest, size_t dest_len) {
  if (json == NULL || key == NULL || dest == NULL || dest_len == 0U) {
    return false;
  }

  const char *key_pos = strstr(json, key);
  if (key_pos == NULL) {
    dest[0] = '\0';
    return false;
  }

  key_pos += strlen(key);
  while (*key_pos != '\0' && *key_pos != '"') {
    ++key_pos;
  }
  if (*key_pos != '"') {
    dest[0] = '\0';
    return false;
  }

  ++key_pos;
  size_t offset = 0U;
  bool escape = false;
  for (const char *cursor = key_pos; *cursor != '\0'; ++cursor) {
    char ch = *cursor;
    if (!escape && ch == '\\') {
      escape = true;
      continue;
    }
    if (!escape && ch == '"') {
      break;
    }

    char decoded = ch;
    if (escape) {
      switch (ch) {
        case 'n':
          decoded = '\n';
          break;
        case 'r':
          decoded = '\r';
          break;
        case 't':
          decoded = '\t';
          break;
        case '\\':
          decoded = '\\';
          break;
        case '"':
          decoded = '"';
          break;
        default:
          decoded = ch;
          break;
      }
      escape = false;
    }

    if (offset + 1U < dest_len) {
      dest[offset++] = decoded;
    }
  }

  if (offset >= dest_len) {
    dest[dest_len - 1U] = '\0';
  } else {
    dest[offset] = '\0';
  }

  return true;
}

static char *translator_build_url(void) {
  const char *base = getenv("OPENAI_API_BASE");
  if (base == NULL || base[0] == '\0') {
    base = getenv("OPENAI_BASE_URL");
  }
  if (base == NULL || base[0] == '\0') {
    base = TRANSLATOR_DEFAULT_BASE_URL;
  }

  size_t base_len = strlen(base);
  const char *path = "responses";
  bool append_slash = base_len == 0U || base[base_len - 1U] != '/';
  size_t total = base_len + (append_slash ? 1U : 0U) + strlen(path) + 1U;

  char *url = malloc(total);
  if (url == NULL) {
    return NULL;
  }

  if (append_slash) {
    snprintf(url, total, "%s/%s", base, path);
  } else {
    snprintf(url, total, "%s%s", base, path);
  }

  return url;
}

bool translator_translate(const char *text, const char *target_language, char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len) {
  if (text == NULL || target_language == NULL || translation == NULL || translation_len == 0U) {
    return false;
  }

  translator_global_init();

  const char *api_key = getenv("OPENAI_API_KEY");
  if (api_key == NULL || api_key[0] == '\0') {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    return false;
  }

  bool success = false;
  char *escaped_text = translator_escape_string(text);
  char *escaped_target = translator_escape_string(target_language);
  char *api_url = translator_build_url();
  if (escaped_text == NULL || escaped_target == NULL || api_url == NULL) {
    goto cleanup;
  }

  static const char body_prefix[] = "{\"model\":\"gpt-4o-mini\",\"input\":[";
  static const char body_system[] =
      "{\"role\":\"system\",\"content\":[{\"type\":\"text\",\"text\":\"You are a translation engine that detects the source language of text and translates it to a requested target language. Preserve tokens like [[ANSI0]] unchanged.\"}]},";
  static const char body_suffix[] = "]}";
  static const char body_format[] =
      "%s%s"
      "{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"Target language: %s\nRespond only with a JSON object containing keys detected_language and translation.\nText: %s\"}]}"
      "%s";

  int computed = snprintf(NULL, 0, body_format, body_prefix, body_system, escaped_target, escaped_text, body_suffix);
  if (computed < 0) {
    goto cleanup;
  }

  size_t body_len = (size_t)computed + 1U;
  char *body = malloc(body_len);
  if (body == NULL) {
    goto cleanup;
  }
  int written = snprintf(body, body_len, body_format, body_prefix, body_system, escaped_target, escaped_text, body_suffix);
  if (written < 0 || (size_t)written >= body_len) {
    free(body);
    body = NULL;
    goto cleanup;
  }

  translator_buffer_t buffer = {0};
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (headers == NULL) {
    goto cleanup_headers;
  }
  size_t auth_len = strlen(api_key) + strlen("Authorization: Bearer ") + 1U;
  char *auth_header = malloc(auth_len);
  if (auth_header == NULL) {
    goto cleanup_headers;
  }
  snprintf(auth_header, auth_len, "Authorization: Bearer %s", api_key);
  headers = curl_slist_append(headers, auth_header);
  free(auth_header);
  if (headers == NULL) {
    goto cleanup_headers;
  }

  headers = curl_slist_append(headers, "OpenAI-Beta: assistants=v2");
  if (headers == NULL) {
    goto cleanup_headers;
  }

  curl_easy_setopt(curl, CURLOPT_URL, api_url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, translator_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

  CURLcode result = curl_easy_perform(curl);
  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

  if (result != CURLE_OK || status < 200L || status >= 300L || buffer.data == NULL) {
    goto cleanup_headers;
  }

  char *payload = translator_extract_payload_text(buffer.data);
  if (payload == NULL) {
    goto cleanup_headers;
  }

  if (detected_language != NULL && detected_len > 0U) {
    detected_language[0] = '\0';
  }

  char detected[64];
  char translated[TRANSLATOR_MAX_RESPONSE];
  detected[0] = '\0';
  translated[0] = '\0';

  (void)translator_extract_json_value(payload, "\"detected_language\"", detected, sizeof(detected));
  if (!translator_extract_json_value(payload, "\"translation\"", translated, sizeof(translated))) {
    free(payload);
    goto cleanup_headers;
  }

  if (detected_language != NULL && detected_len > 0U) {
    snprintf(detected_language, detected_len, "%s", detected);
  }

  snprintf(translation, translation_len, "%s", translated);
  success = true;
  free(payload);

cleanup_headers:
  curl_slist_free_all(headers);
  free(buffer.data);
  free(body);
cleanup:
  free(escaped_text);
  free(escaped_target);
  free(api_url);
  curl_easy_cleanup(curl);
  return success;
}

