#include "headers/translator.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define TRANSLATOR_MAX_RESPONSE 65536
#define TRANSLATOR_DEFAULT_BASE_URL "https://generativelanguage.googleapis.com/v1beta"
#define TRANSLATOR_DEFAULT_MODEL "gemini-2.5-flash"

typedef struct translator_buffer {
  char *data;
  size_t length;
} translator_buffer_t;

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_error_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_curl_initialised = false;
static char g_last_error[256] = "";

static void translator_set_error(const char *fmt, ...) {
  pthread_mutex_lock(&g_error_mutex);
  if (fmt == NULL) {
    g_last_error[0] = '\0';
  } else {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_last_error, sizeof(g_last_error), fmt, args);
    va_end(args);
  }
  pthread_mutex_unlock(&g_error_mutex);
}

const char *translator_last_error(void) {
  static _Thread_local char snapshot[256];
  pthread_mutex_lock(&g_error_mutex);
  snprintf(snapshot, sizeof(snapshot), "%s", g_last_error);
  pthread_mutex_unlock(&g_error_mutex);
  return snapshot;
}

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

static const char *translator_skip_whitespace(const char *cursor) {
  if (cursor == NULL) {
    return NULL;
  }

  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  return cursor;
}

static char *translator_extract_payload_text(const char *response) {
  if (response == NULL) {
    return NULL;
  }

  const char *candidates_marker = "\"candidates\"";
  const char *candidates_pos = strstr(response, candidates_marker);
  if (candidates_pos == NULL) {
    return NULL;
  }

  const char *text_marker = "\"text\"";
  const char *text_pos = strstr(candidates_pos, text_marker);
  while (text_pos != NULL) {
    text_pos += strlen(text_marker);
    text_pos = translator_skip_whitespace(text_pos);
    if (text_pos == NULL || *text_pos != ':') {
      text_pos = strstr(text_pos, text_marker);
      continue;
    }

    ++text_pos;
    text_pos = translator_skip_whitespace(text_pos);
    if (text_pos == NULL || *text_pos != '"') {
      text_pos = strstr(text_pos, text_marker);
      continue;
    }

    ++text_pos;
    break;
  }

  if (text_pos == NULL) {
    const char *error_marker = "\"message\":\"";
    const char *error_pos = strstr(response, error_marker);
    if (error_pos != NULL) {
      fprintf(stderr, "API Error Message Found in Response.\n");
    }
    return NULL;
  }

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
  const char *base = getenv("GEMINI_API_BASE");
  if (base == NULL || base[0] == '\0') {
    base = getenv("GEMINI_BASE_URL");
  }
  if (base == NULL || base[0] == '\0') {
    base = TRANSLATOR_DEFAULT_BASE_URL;
  }

  const char *model = getenv("GEMINI_MODEL");
  if (model == NULL || model[0] == '\0') {
    model = TRANSLATOR_DEFAULT_MODEL;
  }

  size_t base_len = strlen(base);
  bool base_has_slash = (base_len > 0U && base[base_len - 1U] == '/');
  const char *models_prefix = "models/";
  size_t models_prefix_len = strlen(models_prefix);
  size_t model_len = strlen(model);
  const char *generate_suffix = ":generateContent";
  const char *api_key = getenv("GEMINI_API_KEY");
  if (api_key == NULL || api_key[0] == '\0') {
    return NULL;
  }

  size_t total = base_len + (base_has_slash ? 0U : 1U) + models_prefix_len + model_len + strlen(generate_suffix) + strlen("?key=") + strlen(api_key) + 1U;

  char *url = malloc(total);
  if (url == NULL) {
    return NULL;
  }

  snprintf(url, total, "%s%s%s%s%s?key=%s", base, base_has_slash ? "" : "/", models_prefix, model, generate_suffix, api_key);
  return url;
}

bool translator_translate(const char *text, const char *target_language, char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len) {
  if (text == NULL || target_language == NULL || translation == NULL || translation_len == 0U) {
    return false;
  }

  translator_global_init();

  translator_set_error(NULL);

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    translator_set_error("Failed to initialise CURL.");
    return false;
  }

  bool success = false;
  char *escaped_text = translator_escape_string(text);
  char *escaped_target = translator_escape_string(target_language);
  char *api_url = translator_build_url();
  if (escaped_text == NULL || escaped_target == NULL || api_url == NULL) {
    if (api_url == NULL) {
      const char *api_key = getenv("GEMINI_API_KEY");
      if (api_key == NULL || api_key[0] == '\0') {
        translator_set_error("GEMINI_API_KEY is not configured.");
      } else {
        translator_set_error("Failed to build Gemini API URL.");
      }
    } else {
      translator_set_error("Failed to prepare translation request payload.");
    }
    goto cleanup;
  }

  static const char body_format[] =
      "{"
        "\"system_instruction\":{"
          "\"parts\":[{\"text\":\"You are a translation engine that detects the source language of text and translates it to a requested target language. Preserve tokens like [[ANSI0]] unchanged. Respond only with a JSON object containing keys detected_language and translation.\"}]"
        "},"
        "\"contents\":["
          "{"
            "\"role\":\"user\","
            "\"parts\":["
              "{\"text\":\"Target language: %s\\nText: %s\"}"
            "]"
          "}"
        "],"
        "\"generationConfig\":{\"responseMimeType\":\"application/json\"}"
      "}";

  int computed = snprintf(NULL, 0, body_format, escaped_target, escaped_text);
  if (computed < 0) {
    goto cleanup;
  }

  size_t body_len = (size_t)computed + 1U;
  char *body = malloc(body_len);
  if (body == NULL) {
    goto cleanup;
  }
  int written = snprintf(body, body_len, body_format, escaped_target, escaped_text);
  if (written < 0 || (size_t)written >= body_len) {
    free(body);
    body = NULL;
    goto cleanup;
  }

  translator_buffer_t buffer = {0};
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  const char *api_key_header = getenv("GEMINI_API_KEY");
  if (api_key_header != NULL && api_key_header[0] != '\0') {
    size_t header_len = strlen("x-goog-api-key: ") + strlen(api_key_header) + 1U;
    char *header_value = malloc(header_len);
    if (header_value != NULL) {
      snprintf(header_value, header_len, "x-goog-api-key: %s", api_key_header);
      headers = curl_slist_append(headers, header_value);
      free(header_value);
    }
  }
  if (headers == NULL) {
    translator_set_error("Failed to prepare Gemini request headers.");
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

  if (result != CURLE_OK) {
    translator_set_error("Failed to contact Gemini API: %s", curl_easy_strerror(result));
    goto cleanup_headers;
  }

  if (status < 200L || status >= 300L || buffer.data == NULL) {
    char message[128];
    message[0] = '\0';
    if (buffer.data != NULL) {
      (void)translator_extract_json_value(buffer.data, "\"message\"", message, sizeof(message));
    }
    if (message[0] != '\0') {
      translator_set_error("Gemini API %ld: %s", status, message);
    } else if (status != 0L) {
      translator_set_error("Gemini API returned HTTP %ld.", status);
    } else {
      translator_set_error("Gemini API returned an empty response.");
    }
    goto cleanup_headers;
  }

  char *payload = translator_extract_payload_text(buffer.data);
  if (payload == NULL) {
    translator_set_error("Unable to parse Gemini translation payload.");
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
    translator_set_error("Gemini response did not contain a translation field.");
    goto cleanup_headers;
  }

  if (detected_language != NULL && detected_len > 0U) {
    snprintf(detected_language, detected_len, "%s", detected);
  }

  snprintf(translation, translation_len, "%s", translated);
  success = true;
  translator_set_error(NULL);
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

