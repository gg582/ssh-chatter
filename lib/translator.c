#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "headers/translator.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define TRANSLATOR_MAX_RESPONSE 65536
#define TRANSLATOR_DEFAULT_BASE_URL "https://generativelanguage.googleapis.com/v1beta"
#define TRANSLATOR_DEFAULT_MODEL "gemini-2.5"

typedef struct translator_buffer {
  char *data;
  size_t length;
} translator_buffer_t;

typedef enum translator_provider {
  TRANSLATOR_PROVIDER_GEMINI,
  TRANSLATOR_PROVIDER_OPENROUTER,
  TRANSLATOR_PROVIDER_OPENAI,
} translator_provider_t;

typedef struct translator_candidate {
  translator_provider_t provider;
  const char *model;
  const char *api_key;
  const char *api_key_name;
} translator_candidate_t;

static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_error_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_rate_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_curl_initialised = false;
static char g_last_error[256] = "";
static struct timespec g_next_allowed_request = {0, 0};

#define TRANSLATOR_RATE_LIMIT_INTERVAL_NS 800000000L
#define TRANSLATOR_RATE_LIMIT_PENALTY_NS 3000000000L

static struct timespec translator_timespec_now(void) {
  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);
  return now;
}

static int translator_timespec_compare(const struct timespec *a, const struct timespec *b) {
  if (a == NULL || b == NULL) {
    return 0;
  }

  if (a->tv_sec != b->tv_sec) {
    return (a->tv_sec < b->tv_sec) ? -1 : 1;
  }

  if (a->tv_nsec != b->tv_nsec) {
    return (a->tv_nsec < b->tv_nsec) ? -1 : 1;
  }

  return 0;
}

static struct timespec translator_timespec_add_ns(const struct timespec *base, long nanoseconds) {
  struct timespec result = {0, 0};
  if (base != NULL) {
    result = *base;
  }

  long seconds = nanoseconds / 1000000000L;
  long remainder = nanoseconds % 1000000000L;
  if (remainder < 0) {
    --seconds;
    remainder += 1000000000L;
  }

  result.tv_sec += seconds;
  result.tv_nsec += remainder;
  if (result.tv_nsec >= 1000000000L) {
    ++result.tv_sec;
    result.tv_nsec -= 1000000000L;
  }

  if (result.tv_nsec < 0) {
    --result.tv_sec;
    result.tv_nsec += 1000000000L;
  }

  if (result.tv_sec < 0) {
    result.tv_sec = 0;
    result.tv_nsec = 0;
  }

  return result;
}

static struct timespec translator_timespec_diff(const struct timespec *end, const struct timespec *start) {
  struct timespec result = {0, 0};
  if (end == NULL || start == NULL) {
    return result;
  }

  if (translator_timespec_compare(end, start) <= 0) {
    return result;
  }

  result.tv_sec = end->tv_sec - start->tv_sec;
  result.tv_nsec = end->tv_nsec - start->tv_nsec;
  if (result.tv_nsec < 0) {
    --result.tv_sec;
    result.tv_nsec += 1000000000L;
  }

  if (result.tv_sec < 0) {
    result.tv_sec = 0;
    result.tv_nsec = 0;
  }

  return result;
}

static void translator_rate_limit_wait(void) {
  for (;;) {
    pthread_mutex_lock(&g_rate_mutex);
    struct timespec now = translator_timespec_now();
    if (g_next_allowed_request.tv_sec == 0 && g_next_allowed_request.tv_nsec == 0) {
      g_next_allowed_request = translator_timespec_add_ns(&now, TRANSLATOR_RATE_LIMIT_INTERVAL_NS);
      pthread_mutex_unlock(&g_rate_mutex);
      return;
    }

    if (translator_timespec_compare(&now, &g_next_allowed_request) >= 0) {
      g_next_allowed_request = translator_timespec_add_ns(&now, TRANSLATOR_RATE_LIMIT_INTERVAL_NS);
      pthread_mutex_unlock(&g_rate_mutex);
      return;
    }

    struct timespec wait_time = translator_timespec_diff(&g_next_allowed_request, &now);
    pthread_mutex_unlock(&g_rate_mutex);
    nanosleep(&wait_time, NULL);
  }
}

static void translator_rate_limit_penalise_until(const struct timespec *until) {
  if (until == NULL) {
    return;
  }

  pthread_mutex_lock(&g_rate_mutex);
  if (translator_timespec_compare(until, &g_next_allowed_request) > 0) {
    g_next_allowed_request = *until;
  }
  pthread_mutex_unlock(&g_rate_mutex);
}

static void translator_rate_limit_penalize(long status) {
  if (status != 429L) {
    return;
  }

  struct timespec now = translator_timespec_now();
  struct timespec penalty_until = translator_timespec_add_ns(&now, TRANSLATOR_RATE_LIMIT_PENALTY_NS);
  translator_rate_limit_penalise_until(&penalty_until);
}

static size_t translator_utf8_encode(uint32_t codepoint, char *output, size_t max_len) {
  if (output == NULL || max_len == 0U) {
    return 0U;
  }

  if (codepoint <= 0x7FU) {
    if (max_len < 1U) {
      return 0U;
    }
    output[0] = (char)codepoint;
    return 1U;
  }

  if (codepoint <= 0x7FFU) {
    if (max_len < 2U) {
      return 0U;
    }
    output[0] = (char)(0xC0 | (codepoint >> 6));
    output[1] = (char)(0x80 | (codepoint & 0x3FU));
    return 2U;
  }

  if (codepoint <= 0xFFFFU) {
    if (max_len < 3U) {
      return 0U;
    }
    output[0] = (char)(0xE0 | (codepoint >> 12));
    output[1] = (char)(0x80 | ((codepoint >> 6) & 0x3FU));
    output[2] = (char)(0x80 | (codepoint & 0x3FU));
    return 3U;
  }

  if (codepoint <= 0x10FFFFU) {
    if (max_len < 4U) {
      return 0U;
    }
    output[0] = (char)(0xF0 | (codepoint >> 18));
    output[1] = (char)(0x80 | ((codepoint >> 12) & 0x3FU));
    output[2] = (char)(0x80 | ((codepoint >> 6) & 0x3FU));
    output[3] = (char)(0x80 | (codepoint & 0x3FU));
    return 4U;
  }

  return 0U;
}

static bool translator_parse_hex4(const char *input, uint32_t *value) {
  if (input == NULL || value == NULL) {
    return false;
  }

  uint32_t result = 0U;
  for (size_t idx = 0U; idx < 4U; ++idx) {
    char ch = input[idx];
    if (ch == '\0') {
      return false;
    }
    result <<= 4U;
    if (ch >= '0' && ch <= '9') {
      result |= (uint32_t)(ch - '0');
    } else if (ch >= 'a' && ch <= 'f') {
      result |= (uint32_t)(10 + (ch - 'a'));
    } else if (ch >= 'A' && ch <= 'F') {
      result |= (uint32_t)(10 + (ch - 'A'));
    } else {
      return false;
    }
  }

  *value = result;
  return true;
}

static bool translator_decode_json_string(const char *input, char *output, size_t output_len, const char **end_out) {
  if (input == NULL || output == NULL || output_len == 0U) {
    return false;
  }

  size_t out_idx = 0U;
  const char *cursor = input;

  while (*cursor != '\0') {
    char ch = *cursor++;
    if (ch == '"') {
      if (out_idx >= output_len) {
        output[output_len - 1U] = '\0';
      } else {
        output[out_idx] = '\0';
      }
      if (end_out != NULL) {
        *end_out = cursor;
      }
      return true;
    }

    if (ch == '\\') {
      char next = *cursor++;
      if (next == '\0') {
        break;
      }

      switch (next) {
        case '"':
        case '\\':
        case '/':
        case 'b':
        case 'f':
        case 'n':
        case 'r':
        case 't': {
          char decoded = next;
          switch (next) {
            case 'b':
              decoded = '\b';
              break;
            case 'f':
              decoded = '\f';
              break;
            case 'n':
              decoded = '\n';
              break;
            case 'r':
              decoded = '\r';
              break;
            case 't':
              decoded = '\t';
              break;
            default:
              break;
          }

          if (out_idx + 1U >= output_len) {
            return false;
          }
          output[out_idx++] = decoded;
          break;
        }
        case 'u': {
          uint32_t codepoint = 0U;
          if (!translator_parse_hex4(cursor, &codepoint)) {
            return false;
          }
          cursor += 4U;

          if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
            if (cursor[0] == '\\' && cursor[1] == 'u') {
              uint32_t low = 0U;
              if (!translator_parse_hex4(cursor + 2U, &low)) {
                return false;
              }
              cursor += 6U;
              if (low >= 0xDC00U && low <= 0xDFFFU) {
                codepoint = 0x10000U + (((codepoint - 0xD800U) << 10U) | (low - 0xDC00U));
              } else {
                codepoint = 0xFFFD;
              }
            } else {
              codepoint = 0xFFFD;
            }
          } else if (codepoint >= 0xDC00U && codepoint <= 0xDFFFU) {
            codepoint = 0xFFFD;
          }

          char encoded[4];
          size_t encoded_len = translator_utf8_encode(codepoint, encoded, sizeof(encoded));
          if (encoded_len == 0U || out_idx + encoded_len >= output_len) {
            return false;
          }
          memcpy(output + out_idx, encoded, encoded_len);
          out_idx += encoded_len;
          break;
        }
        default:
          if (out_idx + 1U >= output_len) {
            return false;
          }
          output[out_idx++] = next;
          break;
      }
      continue;
    }

    if (out_idx + 1U >= output_len) {
      return false;
    }
    output[out_idx++] = ch;
  }

  return false;
}

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

  const char *text_marker = "\"text\"";
  const size_t text_marker_len = strlen(text_marker);
  const char *cursor = response;
  char *latest_payload = NULL;

  while ((cursor = strstr(cursor, text_marker)) != NULL) {
    const char *value_start = cursor + text_marker_len;
    value_start = translator_skip_whitespace(value_start);
    if (value_start == NULL || *value_start != ':') {
      cursor += text_marker_len;
      continue;
    }

    ++value_start;
    value_start = translator_skip_whitespace(value_start);
    if (value_start == NULL || *value_start != '"') {
      cursor += text_marker_len;
      continue;
    }

    ++value_start;

    size_t capacity = strlen(value_start) + 1U;
    char *candidate = malloc(capacity);
    if (candidate == NULL) {
      free(latest_payload);
      return NULL;
    }

    const char *after_string = NULL;
    if (!translator_decode_json_string(value_start, candidate, capacity, &after_string)) {
      free(candidate);
      free(latest_payload);
      return NULL;
    }

    if (candidate[0] == '{' && strstr(candidate, "\"translation\"") != NULL) {
      free(latest_payload);
      latest_payload = candidate;
    } else {
      free(candidate);
    }

    if (after_string == NULL) {
      break;
    }

    cursor = after_string;
  }

  if (latest_payload == NULL) {
    const char *error_marker = "\"message\":\"";
    const char *error_pos = strstr(response, error_marker);
    if (error_pos != NULL) {
      fprintf(stderr, "API Error Message Found in Response.\n");
    }
  }

  return latest_payload;
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
  const char *after_value = NULL;
  if (!translator_decode_json_string(key_pos, dest, dest_len, &after_value)) {
    dest[0] = '\0';
    return false;
  }

  return true;
}

static bool translator_string_contains_case_insensitive(const char *haystack, const char *needle) {
  if (haystack == NULL || needle == NULL || *needle == '\0') {
    return false;
  }

  size_t haystack_len = strlen(haystack);
  size_t needle_len = strlen(needle);
  if (needle_len > haystack_len) {
    return false;
  }

  for (size_t idx = 0U; idx + needle_len <= haystack_len; ++idx) {
    size_t matched = 0U;
    while (matched < needle_len && tolower((unsigned char)haystack[idx + matched]) ==
                                    tolower((unsigned char)needle[matched])) {
      ++matched;
    }
    if (matched == needle_len) {
      return true;
    }
  }

  return false;
}

static char *translator_build_gemini_url(const char *base, const char *model, const char *api_key, bool stream_mode) {
  if (api_key == NULL || api_key[0] == '\0') {
    return NULL;
  }

  if (base == NULL || base[0] == '\0') {
    base = TRANSLATOR_DEFAULT_BASE_URL;
  }

  if (model == NULL || model[0] == '\0') {
    model = TRANSLATOR_DEFAULT_MODEL;
  }

  size_t base_len = strlen(base);
  bool base_has_slash = (base_len > 0U && base[base_len - 1U] == '/');
  const char *models_prefix = "models/";
  size_t models_prefix_len = strlen(models_prefix);
  size_t model_len = strlen(model);
  const char *suffix = stream_mode ? ":streamGenerateContent" : ":generateContent";
  const char *query_prefix = stream_mode ? "?alt=sse&key=" : "?key=";

  size_t total = base_len + (base_has_slash ? 0U : 1U) + models_prefix_len + model_len + strlen(suffix) + strlen(query_prefix) +
                 strlen(api_key) + 1U;

  char *url = malloc(total);
  if (url == NULL) {
    return NULL;
  }

  snprintf(url, total, "%s%s%s%s%s%s%s", base, base_has_slash ? "" : "/", models_prefix, model, suffix, query_prefix, api_key);
  return url;
}

static CURLcode translator_issue_gemini_request(CURL *curl, const char *url, const char *api_key, const char *body,
                                                bool stream_mode, translator_buffer_t *buffer, long *status) {
  if (curl == NULL || url == NULL || body == NULL || buffer == NULL) {
    return CURLE_FAILED_INIT;
  }

  buffer->data = NULL;
  buffer->length = 0U;

  long local_status = 0L;
  long *status_out = status != NULL ? status : &local_status;

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (stream_mode) {
    headers = curl_slist_append(headers, "Accept: text/event-stream");
  }

  if (api_key != NULL && api_key[0] != '\0') {
    size_t header_len = strlen("x-goog-api-key: ") + strlen(api_key) + 1U;
    char *header_value = malloc(header_len);
    if (header_value != NULL) {
      snprintf(header_value, header_len, "x-goog-api-key: %s", api_key);
      headers = curl_slist_append(headers, header_value);
      free(header_value);
    }
  }

  translator_rate_limit_wait();
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, translator_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

  CURLcode result = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status_out);
  translator_rate_limit_penalize(*status_out);

  curl_slist_free_all(headers);
  return result;
}

static bool translator_handle_payload(const char *response, char *translation, size_t translation_len,
                                      char *detected_language, size_t detected_len) {
  if (response == NULL || translation == NULL || translation_len == 0U) {
    return false;
  }

  char *payload = translator_extract_payload_text(response);
  if (payload == NULL) {
    translator_set_error("Unable to parse Gemini translation payload.");
    return false;
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
    return false;
  }

  if (detected_language != NULL && detected_len > 0U) {
    snprintf(detected_language, detected_len, "%s", detected);
  }

  snprintf(translation, translation_len, "%s", translated);
  translator_set_error(NULL);
  free(payload);
  return true;
}

static bool translator_extract_chat_content(const char *response, char *content, size_t content_len) {
  if (response == NULL || content == NULL || content_len == 0U) {
    return false;
  }

  const char *assistant = strstr(response, "\"role\":\"assistant\"");
  const char *search_start = assistant != NULL ? assistant : response;
  const char *content_key = "\"content\":\"";
  const char *content_pos = strstr(search_start, content_key);
  if (content_pos == NULL) {
    return false;
  }

  content_pos += strlen(content_key);
  const char *after_value = NULL;
  if (!translator_decode_json_string(content_pos, content, content_len, &after_value)) {
    return false;
  }

  return true;
}

static bool translator_handle_chat_payload(const char *response, char *translation, size_t translation_len,
                                           char *detected_language, size_t detected_len) {
  if (response == NULL || translation == NULL || translation_len == 0U) {
    return false;
  }

  char content[TRANSLATOR_MAX_RESPONSE];
  content[0] = '\0';
  if (!translator_extract_chat_content(response, content, sizeof(content))) {
    translator_set_error("Chat completion response did not contain assistant content.");
    return false;
  }

  if (detected_language != NULL && detected_len > 0U) {
    detected_language[0] = '\0';
    (void)translator_extract_json_value(content, "\"detected_language\"", detected_language, detected_len);
  }

  if (!translator_extract_json_value(content, "\"translation\"", translation, translation_len)) {
    translator_set_error("Chat completion response did not include a translation field.");
    return false;
  }

  translator_set_error(NULL);
  return true;
}

static CURLcode translator_issue_json_post(CURL *curl, const char *url, const char *body, const char *auth_header_name,
                                           const char *auth_header_value, const char *const *extra_headers,
                                           translator_buffer_t *buffer, long *status) {
  if (curl == NULL || url == NULL || body == NULL || buffer == NULL) {
    return CURLE_FAILED_INIT;
  }

  buffer->data = NULL;
  buffer->length = 0U;

  long local_status = 0L;
  long *status_out = status != NULL ? status : &local_status;

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  if (auth_header_name != NULL && auth_header_value != NULL) {
    size_t header_len = strlen(auth_header_name) + 2U + strlen(auth_header_value) + 1U;
    char *header_value = malloc(header_len);
    if (header_value != NULL) {
      snprintf(header_value, header_len, "%s: %s", auth_header_name, auth_header_value);
      headers = curl_slist_append(headers, header_value);
      free(header_value);
    }
  }

  if (extra_headers != NULL) {
    for (size_t idx = 0U; extra_headers[idx] != NULL; ++idx) {
      headers = curl_slist_append(headers, extra_headers[idx]);
    }
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, translator_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

  CURLcode result = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status_out);

  curl_slist_free_all(headers);
  return result;
}

static bool translator_candidate_configure(translator_candidate_t *candidate, translator_provider_t provider,
                                           const char *model) {
  if (candidate == NULL) {
    return false;
  }

  const char *api_key = NULL;
  const char *api_key_name = NULL;

  switch (provider) {
    case TRANSLATOR_PROVIDER_GEMINI:
      api_key = getenv("GEMINI_API_KEY");
      api_key_name = "GEMINI_API_KEY";
      break;
    case TRANSLATOR_PROVIDER_OPENROUTER:
      api_key = getenv("OPENROUTER_API_KEY");
      api_key_name = "OPENROUTER_API_KEY";
      break;
    case TRANSLATOR_PROVIDER_OPENAI:
      api_key = getenv("CHATGPT_API_KEY");
      api_key_name = "CHATGPT_API_KEY";
      if (api_key == NULL || api_key[0] == '\0') {
        api_key = getenv("OPENAI_API_KEY");
        api_key_name = "OPENAI_API_KEY";
      }
      break;
  }

  if (api_key == NULL || api_key[0] == '\0') {
    return false;
  }

  candidate->provider = provider;
  candidate->model = model;
  candidate->api_key = api_key;
  candidate->api_key_name = api_key_name;
  return true;
}

static bool translator_candidate_is_duplicate(const translator_candidate_t *candidates, size_t count,
                                              translator_provider_t provider, const char *model) {
  if (candidates == NULL) {
    return false;
  }

  for (size_t idx = 0U; idx < count; ++idx) {
    const char *existing_model = candidates[idx].model != NULL ? candidates[idx].model : "";
    const char *candidate_model = model != NULL ? model : "";
    if (candidates[idx].provider == provider && strcmp(existing_model, candidate_model) == 0) {
      return true;
    }
  }

  return false;
}

static bool translator_try_gemini(const translator_candidate_t *candidate, const char *text,
                                  const char *target_language, char *translation, size_t translation_len,
                                  char *detected_language, size_t detected_len, bool *retryable) {
  if (retryable != NULL) {
    *retryable = false;
  }

  if (candidate == NULL) {
    translator_set_error("Gemini provider is not configured.");
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *api_key = candidate->api_key;
  if (api_key == NULL || api_key[0] == '\0') {
    translator_set_error("GEMINI_API_KEY is not configured.");
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *base = getenv("GEMINI_API_BASE");
  if (base == NULL || base[0] == '\0') {
    base = getenv("GEMINI_BASE_URL");
  }

  const char *model_name = candidate->model != NULL && candidate->model[0] != '\0' ? candidate->model : TRANSLATOR_DEFAULT_MODEL;

  char *escaped_text = translator_escape_string(text);
  char *escaped_target = translator_escape_string(target_language);
  if (escaped_text == NULL || escaped_target == NULL) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  char *api_url = translator_build_gemini_url(base, model_name, api_key, false);
  char *stream_url = translator_build_gemini_url(base, model_name, api_key, true);
  if (api_url == NULL && stream_url == NULL) {
    translator_set_error("Failed to build Gemini API URL.");
    free(escaped_text);
    free(escaped_target);
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  static const char body_format[] =
      "{" \
      "\"system_instruction\":{" \
        "\"parts\":[{\"text\":\"You are a translation engine that detects the source language of text and translates it to a requested target language. Preserve tokens like [[ANSI0]] or [[SEG00]] unchanged. Respond only with a JSON object containing keys detected_language and translation.\"}]" \
      "}," \
      "\"contents\":[" \
        "{" \
          "\"role\":\"user\"," \
          "\"parts\":[" \
            "{\"text\":\"Target language: %s\\nText: %s\"}" \
          "]" \
        "}" \
      "]," \
      "\"generationConfig\":{\"responseMimeType\":\"application/json\"}" \
      "}";

  int computed = snprintf(NULL, 0, body_format, escaped_target, escaped_text);
  if (computed < 0) {
    free(escaped_text);
    free(escaped_target);
    free(api_url);
    free(stream_url);
    translator_set_error("Failed to prepare translation request payload.");
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  size_t body_len = (size_t)computed + 1U;
  char *body = malloc(body_len);
  if (body == NULL) {
    free(escaped_text);
    free(escaped_target);
    free(api_url);
    free(stream_url);
    translator_set_error("Failed to prepare translation request payload.");
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  int written = snprintf(body, body_len, body_format, escaped_target, escaped_text);
  free(escaped_text);
  free(escaped_target);
  if (written < 0 || (size_t)written >= body_len) {
    free(body);
    free(api_url);
    free(stream_url);
    translator_set_error("Failed to prepare translation request payload.");
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    free(body);
    free(api_url);
    free(stream_url);
    translator_set_error("Failed to initialise CURL.");
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  translator_buffer_t buffer = {0};
  translator_buffer_t stream_buffer = {0};
  bool success = false;
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  if (stream_url != NULL) {
    long stream_status = 0L;
    CURLcode stream_result = translator_issue_gemini_request(curl, stream_url, api_key, body, true, &stream_buffer, &stream_status);
    if (stream_result == CURLE_OK && stream_status >= 200L && stream_status < 300L && stream_buffer.data != NULL) {
      if (translator_handle_payload(stream_buffer.data, translation, translation_len, detected_language, detected_len)) {
        success = true;
      }
    }
  }

  if (!success && api_url != NULL) {
    translator_set_error(NULL);
    long status = 0L;
    CURLcode result = translator_issue_gemini_request(curl, api_url, api_key, body, false, &buffer, &status);
    if (result != CURLE_OK) {
      translator_set_error("Failed to contact Gemini API: %s", curl_easy_strerror(result));
      if (retryable != NULL) {
        *retryable = true;
      }
    } else if (status < 200L || status >= 300L || buffer.data == NULL) {
      char message[256];
      message[0] = '\0';
      if (buffer.data != NULL) {
        (void)translator_extract_json_value(buffer.data, "\"message\"", message, sizeof(message));
      }
      if (status == 429L || status == 404L ||
          translator_string_contains_case_insensitive(message, "quota") ||
          translator_string_contains_case_insensitive(message, "not found")) {
        if (retryable != NULL) {
          *retryable = true;
        }
      }
      if (message[0] != '\0') {
        translator_set_error("Gemini (%s) HTTP %ld: %s", model_name, status, message);
      } else if (status != 0L) {
        translator_set_error("Gemini (%s) returned HTTP %ld.", model_name, status);
      } else {
        translator_set_error("Gemini (%s) returned an empty response.", model_name);
      }
    } else if (translator_handle_payload(buffer.data, translation, translation_len, detected_language, detected_len)) {
      success = true;
    }
  }

  free(stream_buffer.data);
  free(buffer.data);
  free(body);
  free(api_url);
  free(stream_url);
  curl_easy_cleanup(curl);

  return success;
}

static bool translator_try_openrouter(const translator_candidate_t *candidate, const char *text,
                                      const char *target_language, char *translation, size_t translation_len,
                                      char *detected_language, size_t detected_len, bool *retryable) {
  if (retryable != NULL) {
    *retryable = false;
  }

  if (candidate == NULL) {
    translator_set_error("OpenRouter provider is not configured.");
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *api_key = candidate->api_key;
  const char *key_name = candidate->api_key_name != NULL ? candidate->api_key_name : "OPENROUTER_API_KEY";
  if (api_key == NULL || api_key[0] == '\0') {
    translator_set_error("%s is not configured.", key_name);
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *model_name = candidate->model != NULL && candidate->model[0] != '\0' ? candidate->model : "google/gemini-2.5";

  char *escaped_text = translator_escape_string(text);
  char *escaped_target = translator_escape_string(target_language);
  const char *system_prompt =
      "You are a translation engine that detects the source language of text and translates it to a requested target language. "
      "Preserve tokens like [[ANSI0]] or [[SEG00]] unchanged. Respond only with a JSON object containing keys detected_language "
      "and translation.";
  char *escaped_system = translator_escape_string(system_prompt);
  if (escaped_text == NULL || escaped_target == NULL || escaped_system == NULL) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  static const char chat_format[] =
      "{" \
        "\"model\":\"%s\"," \
        "\"messages\":[" \
          "{\"role\":\"system\",\"content\":\"%s\"}," \
          "{\"role\":\"user\",\"content\":\"Target language: %s\\nText: %s\"}" \
        "]," \
        "\"temperature\":0" \
      "}";

  int computed = snprintf(NULL, 0, chat_format, model_name, escaped_system, escaped_target, escaped_text);
  if (computed < 0) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  size_t body_len = (size_t)computed + 1U;
  char *body = malloc(body_len);
  if (body == NULL) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  snprintf(body, body_len, chat_format, model_name, escaped_system, escaped_target, escaped_text);
  free(escaped_text);
  free(escaped_target);
  free(escaped_system);

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    free(body);
    translator_set_error("Failed to initialise CURL.");
    if (retryable != NULL) {
      *retryable = false;
    }
    return false;
  }

  translator_buffer_t buffer = {0};
  bool success = false;
  long status = 0L;
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  size_t auth_len = strlen("Bearer ") + strlen(api_key) + 1U;
  char *auth_value = malloc(auth_len);
  if (auth_value != NULL) {
    snprintf(auth_value, auth_len, "Bearer %s", api_key);
  }

  const char *site_url = getenv("OPENROUTER_SITE_URL");
  if (site_url == NULL || site_url[0] == '\0') {
    site_url = "https://github.com/yj-an/ssh-chatter";
  }
  const char *site_name = getenv("OPENROUTER_SITE_NAME");
  if (site_name == NULL || site_name[0] == '\0') {
    site_name = "ssh-chatter translator";
  }

  char referer_header[256];
  char title_header[256];
  referer_header[0] = '\0';
  title_header[0] = '\0';
  (void)snprintf(referer_header, sizeof(referer_header), "HTTP-Referer: %s", site_url);
  (void)snprintf(title_header, sizeof(title_header), "X-Title: %s", site_name);

  const char *extra_headers[3];
  size_t header_count = 0U;
  if (referer_header[0] != '\0') {
    extra_headers[header_count++] = referer_header;
  }
  if (title_header[0] != '\0') {
    extra_headers[header_count++] = title_header;
  }
  extra_headers[header_count] = NULL;

  const char *const *header_list = header_count > 0U ? extra_headers : NULL;

  CURLcode result = translator_issue_json_post(curl, "https://openrouter.ai/api/v1/chat/completions", body, "Authorization",
                                               auth_value, header_list, &buffer, &status);
  free(auth_value);

  if (result != CURLE_OK) {
    translator_set_error("Failed to contact OpenRouter API: %s", curl_easy_strerror(result));
    if (retryable != NULL) {
      *retryable = true;
    }
  } else if (status < 200L || status >= 300L || buffer.data == NULL) {
    char message[256];
    message[0] = '\0';
    if (buffer.data != NULL) {
      (void)translator_extract_json_value(buffer.data, "\"message\"", message, sizeof(message));
      if (message[0] == '\0') {
        (void)translator_extract_json_value(buffer.data, "\"error\":{\"message\"", message, sizeof(message));
      }
    }

    bool should_retry = status == 429L || status == 503L || status == 401L || status == 403L;
    if (!should_retry && status == 400L) {
      if (translator_string_contains_case_insensitive(message, "quota") ||
          translator_string_contains_case_insensitive(message, "limit") ||
          translator_string_contains_case_insensitive(message, "model") ||
          translator_string_contains_case_insensitive(message, "overload") ||
          translator_string_contains_case_insensitive(message, "unavailable") ||
          translator_string_contains_case_insensitive(message, "try again")) {
        should_retry = true;
      }
    }

    if (retryable != NULL && should_retry) {
      *retryable = true;
    }

    if (message[0] != '\0') {
      translator_set_error("OpenRouter (%s) HTTP %ld: %s", model_name, status, message);
    } else if (status != 0L) {
      translator_set_error("OpenRouter (%s) returned HTTP %ld.", model_name, status);
    } else {
      translator_set_error("OpenRouter (%s) returned an empty response.", model_name);
    }
  } else if (translator_handle_chat_payload(buffer.data, translation, translation_len, detected_language, detected_len)) {
    success = true;
  }

  free(buffer.data);
  free(body);
  curl_easy_cleanup(curl);

  return success;
}

static bool translator_try_chatgpt(const translator_candidate_t *candidate, const char *text,
                                   const char *target_language, char *translation, size_t translation_len,
                                   char *detected_language, size_t detected_len, bool *retryable) {
  if (retryable != NULL) {
    *retryable = false;
  }

  if (candidate == NULL) {
    translator_set_error("OpenAI provider is not configured.");
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *api_key = candidate->api_key;
  const char *key_name = candidate->api_key_name != NULL ? candidate->api_key_name : "OPENAI_API_KEY";
  if (api_key == NULL || api_key[0] == '\0') {
    translator_set_error("%s is not configured.", key_name);
    if (retryable != NULL) {
      *retryable = true;
    }
    return false;
  }

  const char *model_name = candidate->model != NULL && candidate->model[0] != '\0' ? candidate->model : "gpt-5";

  char *escaped_text = translator_escape_string(text);
  char *escaped_target = translator_escape_string(target_language);
  const char *system_prompt =
      "You are a translation engine that detects the source language of text and translates it to a requested target language. "
      "Preserve tokens like [[ANSI0]] or [[SEG00]] unchanged. Respond only with a JSON object containing keys detected_language "
      "and translation.";
  char *escaped_system = translator_escape_string(system_prompt);
  if (escaped_text == NULL || escaped_target == NULL || escaped_system == NULL) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    return false;
  }

  static const char chat_format[] =
      "{" \
        "\"model\":\"%s\"," \
        "\"messages\":[" \
          "{\"role\":\"system\",\"content\":\"%s\"}," \
          "{\"role\":\"user\",\"content\":\"Target language: %s\\nText: %s\"}" \
        "]," \
        "\"temperature\":0" \
      "}";

  int computed = snprintf(NULL, 0, chat_format, model_name, escaped_system, escaped_target, escaped_text);
  if (computed < 0) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    return false;
  }

  size_t body_len = (size_t)computed + 1U;
  char *body = malloc(body_len);
  if (body == NULL) {
    translator_set_error("Failed to prepare translation request payload.");
    free(escaped_text);
    free(escaped_target);
    free(escaped_system);
    return false;
  }

  snprintf(body, body_len, chat_format, model_name, escaped_system, escaped_target, escaped_text);
  free(escaped_text);
  free(escaped_target);
  free(escaped_system);

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    free(body);
    translator_set_error("Failed to initialise CURL.");
    return false;
  }

  translator_buffer_t buffer = {0};
  bool success = false;
  long status = 0L;
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  size_t auth_len = strlen("Bearer ") + strlen(api_key) + 1U;
  char *auth_value = malloc(auth_len);
  if (auth_value != NULL) {
    snprintf(auth_value, auth_len, "Bearer %s", api_key);
  }

  CURLcode result = translator_issue_json_post(curl, "https://api.openai.com/v1/chat/completions", body, "Authorization",
                                               auth_value, NULL, &buffer, &status);
  free(auth_value);

  if (result != CURLE_OK) {
    translator_set_error("Failed to contact ChatGPT API: %s", curl_easy_strerror(result));
    if (retryable != NULL) {
      *retryable = true;
    }
  } else if (status < 200L || status >= 300L || buffer.data == NULL) {
    if (status == 429L || status == 503L || status == 500L || status == 401L || status == 403L) {
      if (retryable != NULL) {
        *retryable = true;
      }
    }
    translator_set_error("ChatGPT (%s) returned HTTP %ld.", model_name, status);
  } else if (translator_handle_chat_payload(buffer.data, translation, translation_len, detected_language, detected_len)) {
    success = true;
  }

  free(buffer.data);
  free(body);
  curl_easy_cleanup(curl);

  return success;
}

static size_t translator_prepare_candidates(translator_candidate_t *candidates, size_t capacity) {
  if (candidates == NULL || capacity == 0U) {
    return 0U;
  }

  size_t count = 0U;
  const char *env_model = getenv("GEMINI_MODEL");
  if (env_model != NULL && env_model[0] != '\0' && count < capacity) {
    if (!translator_candidate_is_duplicate(candidates, count, TRANSLATOR_PROVIDER_GEMINI, env_model) &&
        translator_candidate_configure(&candidates[count], TRANSLATOR_PROVIDER_GEMINI, env_model)) {
      ++count;
    }
  }

  static const struct {
    translator_provider_t provider;
    const char *model;
  } defaults[] = {
      {TRANSLATOR_PROVIDER_GEMINI, "gemini-2.5"},
      {TRANSLATOR_PROVIDER_GEMINI, "gemini-2.5-lite"},
      {TRANSLATOR_PROVIDER_OPENROUTER, "openai/gpt-oss-20b:free"},
      {TRANSLATOR_PROVIDER_OPENROUTER, "deepseek/deepseek-r1-0528-qwen3-8b:free"},
      {TRANSLATOR_PROVIDER_OPENAI, "gpt-5"},
  };

  for (size_t idx = 0U; idx < sizeof(defaults) / sizeof(defaults[0]) && count < capacity; ++idx) {
    if (translator_candidate_is_duplicate(candidates, count, defaults[idx].provider, defaults[idx].model)) {
      continue;
    }
    if (translator_candidate_configure(&candidates[count], defaults[idx].provider, defaults[idx].model)) {
      ++count;
    }
  }

  return count;
}

bool translator_translate(const char *text, const char *target_language, char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len) {
  if (text == NULL || target_language == NULL || translation == NULL || translation_len == 0U) {
    return false;
  }

  translator_global_init();

  translator_set_error(NULL);

  translator_candidate_t candidates[8];
  size_t candidate_count = translator_prepare_candidates(candidates, sizeof(candidates) / sizeof(candidates[0]));
  if (candidate_count == 0U) {
    translator_set_error(
        "No translation providers are configured. Set GEMINI_API_KEY, OPENROUTER_API_KEY, or OPENAI_API_KEY.");
    return false;
  }

  for (size_t idx = 0U; idx < candidate_count; ++idx) {
    bool retryable = false;
    bool success = false;
    switch (candidates[idx].provider) {
      case TRANSLATOR_PROVIDER_GEMINI:
        success = translator_try_gemini(&candidates[idx], text, target_language, translation, translation_len,
                                        detected_language, detected_len, &retryable);
        break;
      case TRANSLATOR_PROVIDER_OPENROUTER:
        success = translator_try_openrouter(&candidates[idx], text, target_language, translation, translation_len,
                                            detected_language, detected_len, &retryable);
        break;
      case TRANSLATOR_PROVIDER_OPENAI:
        success = translator_try_chatgpt(&candidates[idx], text, target_language, translation, translation_len,
                                         detected_language, detected_len, &retryable);
        break;
    }

    if (success) {
      return true;
    }

    if (!retryable) {
      break;
    }
  }

  return false;
}

