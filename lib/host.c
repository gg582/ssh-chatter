#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "host.h"
#include <libssh/libssh.h>
#include "client.h"
#include "webssh_client.h"
#include "translator.h"
#include "translation_helpers.h"

#include <curl/curl.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <libgen.h>
#include <limits.h>
#include <wchar.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "humanized/humanized.h"

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif

#define ANSI_CLEAR_LINE "\033[2K"
#define ANSI_INSERT_LINE "\033[1L"

#define SSH_CHATTER_MESSAGE_BOX_MAX_LINES 32U
#define SSH_CHATTER_MESSAGE_BOX_PADDING 2U
#define SSH_CHATTER_IMAGE_PREVIEW_WIDTH 48U
#define SSH_CHATTER_IMAGE_PREVIEW_HEIGHT 48U
#define SSH_CHATTER_IMAGE_PREVIEW_LINE_LEN 128U
#define SSH_CHATTER_BBS_DEFAULT_TAG "general"
#define SSH_CHATTER_BBS_TERMINATOR ">/__BBS_END>"
#define SSH_CHATTER_ASCIIART_TERMINATOR ">/__ARTWORK_END>"
#define SSH_CHATTER_BBS_EDITOR_BODY_DIVIDER "----------Body---------------"
#define SSH_CHATTER_BBS_EDITOR_END_DIVIDER "----------End-----------------"
#define SSH_CHATTER_RSS_REFRESH_SECONDS 180U
#define SSH_CHATTER_RSS_SLEEP_CHUNK_SECONDS 5U
#define SSH_CHATTER_RSS_USER_AGENT "ssh-chatter/rss"
#define SSH_CHATTER_RSS_BREAKING_PREFIX "[BREAKING NEWS]"
#define SSH_CHATTER_TETROMINO_SIZE 4
#define SSH_CHATTER_HANDSHAKE_RETRY_LIMIT ((unsigned int)INT_MAX)
#define SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS_DISPLAY \
  "rsa-sha2-512, rsa-sha2-256, ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256"
#define SSH_CHATTER_SUPPORTED_KEX_ALGORITHMS                                                     \
  "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,"       \
  "ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,"      \
  "diffie-hellman-group14-sha1"
#define SSH_CHATTER_BIRTHDAY_WINDOW_SECONDS (7 * 24 * 60 * 60)

static const char *const SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS[] = {
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
};

typedef struct host_key_definition {
  const char *algorithm;
  const char *filename;
  ssh_bind_options_e option;
  bool requires_import;
} host_key_definition_t;

static const size_t SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS_COUNT =
    sizeof(SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS) /
    sizeof(SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS[0]);
#define SESSION_CHANNEL_TIMEOUT (-2)
#define SSH_CHATTER_CHANNEL_RECOVERY_LIMIT ((unsigned int)INT_MAX)
#define SSH_CHATTER_CHANNEL_RECOVERY_DELAY_NS 200000000L
#define SSH_CHATTER_CHANNEL_WRITE_TIMEOUT_MS 200
#define SSH_CHATTER_CHANNEL_WRITE_MAX_STALLS 30U
#define SSH_CHATTER_CHANNEL_WRITE_CHUNK 1024U
#define SSH_CHATTER_CHANNEL_WRITE_BACKOFF_NS 20000000L
#define SSH_CHATTER_TRANSLATION_SEGMENT_GUARD 32U
#define SSH_CHATTER_TRANSLATION_BATCH_DELAY_NS 150000000L
#define SSH_CHATTER_JOIN_RAPID_WINDOW_NS 60000000000LL
#define SSH_CHATTER_JOIN_IP_THRESHOLD 6U
#define SSH_CHATTER_JOIN_NAME_THRESHOLD 6U
#define SSH_CHATTER_SUSPICIOUS_EVENT_WINDOW_NS 300000000000LL
#define SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD 2U
#define SSH_CHATTER_CLAMAV_SCAN_INTERVAL_SECONDS (5 * 60 * 60)
#define SSH_CHATTER_CLAMAV_SLEEP_CHUNK_SECONDS 30U
#define SSH_CHATTER_BBS_WATCHDOG_SLEEP_SECONDS 5U
#define SSH_CHATTER_CLAMAV_OUTPUT_LIMIT 512U
#define SSH_CHATTER_BBS_REVIEW_INTERVAL_SECONDS 120U
#define ELIZA_MEMORY_MAGIC 0x454C5A41U
#define ELIZA_MEMORY_VERSION 1U
#define SSH_CHATTER_ELIZA_CONTEXT_LIMIT 3U
#define SSH_CHATTER_ELIZA_CONTEXT_BUFFER (SSH_CHATTER_MESSAGE_LIMIT * 4U)
#define SSH_CHATTER_ELIZA_HISTORY_LIMIT 6U
#define SSH_CHATTER_ELIZA_HISTORY_WINDOW 12U
#define SSH_CHATTER_ELIZA_BBS_CONTEXT_LIMIT 3U
#define SSH_CHATTER_ELIZA_BBS_PREVIEW_LEN 160U
#define SSH_CHATTER_ELIZA_PROMPT_BUFFER ((SSH_CHATTER_ELIZA_CONTEXT_BUFFER * 2U) + (SSH_CHATTER_MESSAGE_LIMIT * 3U))
#define SSH_CHATTER_ELIZA_TOKEN_LIMIT 16U

static size_t host_column_reset_sequence_length(const char *text);
static bool host_contains_column_reset(const char *text);
static void host_strip_column_reset(char *text);

#define ALPHA_TOTAL_DISTANCE_LY 4.24
#define ALPHA_LY_TO_KM 9460730472580.8
#define ALPHA_LY_TO_AU 63241.077
#define ALPHA_SPEED_OF_LIGHT_MPS 299792458.0
#define ALPHA_NAV_WIDTH 60
#define ALPHA_NAV_HEIGHT 60
#define ALPHA_NAV_MARGIN 6
#define ALPHA_THRUST_DELTA 0.45
#define ALPHA_THRUST_POSITION_STEP 0.5
#define ALPHA_GRAVITY_DAMPING 0.97
#define ALPHA_GRAVITY_MIN_DISTANCE 2.5
#define ALPHA_GRAVITY_MAX_ACCEL 0.30
#define ALPHA_NAV_MAX_SPEED 1.20
#define ALPHA_BLACK_HOLE_MU 1800.0
#define ALPHA_STAR_MU 360.0
#define ALPHA_PLANET_MU 65.0
#define ALPHA_DEBRIS_MU 12.0
#define ALPHA_MIN_WAYPOINTS 3U

static const char *const kAlphaWaystationNames[] = {
    "Relay Lyra",
    "Depot Carina",
    "Refuel Vesper",
    "Outpost Helion",
};

#define TELNET_IAC 255
#define TELNET_CMD_SE 240
#define TELNET_CMD_NOP 241
#define TELNET_CMD_DM 242
#define TELNET_CMD_BREAK 243
#define TELNET_CMD_WILL 251
#define TELNET_CMD_WONT 252
#define TELNET_CMD_DO 253
#define TELNET_CMD_DONT 254
#define TELNET_CMD_SB 250
#define TELNET_OPT_ECHO 1
#define TELNET_OPT_SUPPRESS_GO_AHEAD 3
#define TELNET_OPT_STATUS 5
#define TELNET_OPT_TERMINAL_TYPE 24
#define TELNET_OPT_NAWS 31
#define TELNET_OPT_TERMINAL_SPEED 32
#define TELNET_OPT_LINEMODE 34

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

static const char kTranslationQuotaNotice[] =
    "⚠️ Translation quota exhausted. Translation features are temporarily disabled.";
static const char kTranslationQuotaSystemMessage[] =
    "Translation quota exhausted. Translation has been disabled. Try again later.";

static const char *const kSessionCommandNames[] = {
    "asciiart",      "audio",       "ban",          "banlist",     "bbs",
    "birthday",      "block",       "chat",         "chat-spacing", "color",
    "connected",     "date",        "delete-msg",   "elect",       "eliza",
    "eliza-chat",    "exit",        "files",        "game",        "gemini",
    "gemini-unfreeze","getos",      "grant",        "help",        "image",
    "kick",          "mode",        "motd",         "nick",        "os",
    "pair",          "palette",     "pardon",       "pm",          "poke",
    "poll",          "reply",       "revoke",       "rss",         "search",
    "set-target-lang","set-trans-lang","showstatus", "soulmate",    "status",
    "suspend!",      "systemcolor", "today",        "translate",   "translate-scope",
    "unblock",       "users",       "video",        "vote",        "vote-single",
    "weather",
};
#define SSH_CHATTER_COMMAND_COUNT (sizeof(kSessionCommandNames) / sizeof(kSessionCommandNames[0]))

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif

typedef struct {
  char question_en[256];
  char question_ko[256];
  char question_ru[256];
  char question_zh[256];
  char answer[64];
} captcha_prompt_t;

typedef enum {
  CAPTCHA_NAME_LANGUAGE_KOREAN,
  CAPTCHA_NAME_LANGUAGE_ENGLISH,
  CAPTCHA_NAME_LANGUAGE_RUSSIAN,
  CAPTCHA_NAME_LANGUAGE_CHINESE_TRADITIONAL,
  CAPTCHA_NAME_LANGUAGE_COUNT,
} captcha_name_language_t;

typedef struct {
  const char *text;
  captcha_name_language_t language;
} captcha_name_entry_t;

typedef struct {
  const char *ko;
  const char *en;
  const char *ru;
  const char *zh;
} captcha_language_phrase_t;

typedef struct {
  const char *const *names;
  size_t name_count;
} captcha_language_name_list_t;

typedef enum {
  HOST_SECURITY_SCAN_CLEAN = 0,
  HOST_SECURITY_SCAN_BLOCKED,
  HOST_SECURITY_SCAN_ERROR,
} host_security_scan_result_t;

static const captcha_language_phrase_t CAPTCHA_LANGUAGE_PHRASES[CAPTCHA_NAME_LANGUAGE_COUNT] = {
    [CAPTCHA_NAME_LANGUAGE_KOREAN] = {
        .ko = "한국어 이름",
        .en = "Korean names",
        .ru = "корейских имён",
        .zh = "韓文名字",
    },
    [CAPTCHA_NAME_LANGUAGE_ENGLISH] = {
        .ko = "영어 이름",
        .en = "English names",
        .ru = "английских имён",
        .zh = "英文名字",
    },
    [CAPTCHA_NAME_LANGUAGE_RUSSIAN] = {
        .ko = "러시아어 이름",
        .en = "Russian names",
        .ru = "русских имён",
        .zh = "俄文名字",
    },
    [CAPTCHA_NAME_LANGUAGE_CHINESE_TRADITIONAL] = {
        .ko = "중국어 이름",
        .en = "Chinese names",
        .ru = "китайских имён",
        .zh = "中文姓名",
    },
};

#define CAPTCHA_NAME_LIST_MIN ((size_t)4U)
#define CAPTCHA_NAME_LIST_MAX ((size_t)8U)
#define CAPTCHA_LANGUAGE_POOL_MAX ((size_t)16U)

static const char *const CAPTCHA_NAME_POOL_KO[] = {
    "민수", "지영", "서준", "민아", "하준", "수빈", "지후", "서연", "윤우", "다은",
};

static const char *const CAPTCHA_NAME_POOL_EN[] = {
    "Alice", "Oliver", "Grace", "Sophie", "John", "Ethan", "Mia", "Lucas", "Emma", "Noah",
};

static const char *const CAPTCHA_NAME_POOL_RU[] = {
    "Андрей", "Ольга", "Дмитрий", "Екатерина", "Наталья", "Сергей", "Иван", "Мария", "Алексей", "Юлия",
};

static const char *const CAPTCHA_NAME_POOL_ZH[] = {
    "張偉", "陳美玲", "劉德華", "王麗君", "林嘉慧", "李小龍", "趙雅芝", "黃志強", "鄭秀文", "周杰倫",
};

static const captcha_language_name_list_t CAPTCHA_LANGUAGE_NAME_LISTS[CAPTCHA_NAME_LANGUAGE_COUNT] = {
    [CAPTCHA_NAME_LANGUAGE_KOREAN] = {CAPTCHA_NAME_POOL_KO, sizeof(CAPTCHA_NAME_POOL_KO) / sizeof(CAPTCHA_NAME_POOL_KO[0])},
    [CAPTCHA_NAME_LANGUAGE_ENGLISH] = {CAPTCHA_NAME_POOL_EN, sizeof(CAPTCHA_NAME_POOL_EN) / sizeof(CAPTCHA_NAME_POOL_EN[0])},
    [CAPTCHA_NAME_LANGUAGE_RUSSIAN] = {CAPTCHA_NAME_POOL_RU, sizeof(CAPTCHA_NAME_POOL_RU) / sizeof(CAPTCHA_NAME_POOL_RU[0])},
    [CAPTCHA_NAME_LANGUAGE_CHINESE_TRADITIONAL] = {CAPTCHA_NAME_POOL_ZH, sizeof(CAPTCHA_NAME_POOL_ZH) / sizeof(CAPTCHA_NAME_POOL_ZH[0])},
};

static unsigned session_prng_next(unsigned *state) {
  if (state == NULL) {
    return 0U;
  }

  *state = (*state * 1664525U) + 1013904223U;
  return *state;
}

static size_t session_pick_unique_name_index(unsigned *state, size_t limit, bool used[], size_t used_capacity) {
  if (limit == 0U || used == NULL || used_capacity < limit) {
    return 0U;
  }

  for (size_t attempt = 0U; attempt < (limit * 2U); ++attempt) {
    const size_t candidate = (size_t)(session_prng_next(state) % limit);
    if (!used[candidate]) {
      used[candidate] = true;
      return candidate;
    }
  }

  for (size_t idx = 0U; idx < limit; ++idx) {
    if (!used[idx]) {
      used[idx] = true;
      return idx;
    }
  }

  return (size_t)(session_prng_next(state) % limit);
}

static void session_shuffle_captcha_entries(captcha_name_entry_t *entries, size_t count, unsigned *state) {
  if (entries == NULL || state == NULL || count < 2U) {
    return;
  }

  for (size_t remaining = count; remaining > 1U; --remaining) {
    const size_t swap_idx = (size_t)(session_prng_next(state) % remaining);
    const size_t current = remaining - 1U;
    const captcha_name_entry_t temp = entries[current];
    entries[current] = entries[swap_idx];
    entries[swap_idx] = temp;
  }
}

static void session_format_decimal(double value, char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return;
  }

  const int written = snprintf(buffer, length, "%.2f", value);
  if (written < 0) {
    buffer[0] = '\0';
    return;
  }

  char *const dot = strchr(buffer, '.');
  if (dot == NULL) {
    return;
  }

  char *end = buffer + (size_t)written;
  if (end > buffer) {
    --end;
  }
  while (end > dot && *end == '0') {
    *end = '\0';
    --end;
  }
  if (end == dot) {
    *end = '\0';
  }
}

static size_t session_count_target_names(const captcha_name_entry_t *names, size_t name_count,
                                         captcha_name_language_t target) {
  if (names == NULL) {
    return 0U;
  }

  size_t total = 0U;
  for (size_t idx = 0U; idx < name_count; ++idx) {
    if (names[idx].language == target) {
      ++total;
    }
  }

  return total;
}

static void session_join_name_list(const captcha_name_entry_t *names, size_t name_count, char *buffer, size_t buffer_length) {
  if (buffer == NULL || buffer_length == 0U) {
    return;
  }

  buffer[0] = '\0';
  size_t written = 0U;
  for (size_t idx = 0U; idx < name_count; ++idx) {
    const char *name = (names != NULL && names[idx].text != NULL) ? names[idx].text : NULL;
    if (name == NULL) {
      continue;
    }

    int append = 0;
    if (written > 0U) {
      append = snprintf(buffer + written, buffer_length - written, ", %s", name);
    } else {
      append = snprintf(buffer + written, buffer_length - written, "%s", name);
    }
    if (append < 0) {
      buffer[buffer_length - 1U] = '\0';
      return;
    }

    size_t appended = (size_t)append;
    if (appended >= buffer_length - written) {
      buffer[buffer_length - 1U] = '\0';
      return;
    }

    written += appended;
  }
}

static bool session_fill_name_count_prompt(captcha_prompt_t *prompt, unsigned *state) {
  if (prompt == NULL || state == NULL) {
    return false;
  }

  captcha_name_entry_t generated[CAPTCHA_NAME_LIST_MAX];
  bool used_names[CAPTCHA_NAME_LANGUAGE_COUNT][CAPTCHA_LANGUAGE_POOL_MAX];
  memset(used_names, 0, sizeof(used_names));

  const captcha_name_language_t target =
      (captcha_name_language_t)(session_prng_next(state) % (unsigned)CAPTCHA_NAME_LANGUAGE_COUNT);
  const captcha_language_name_list_t *const target_pool = &CAPTCHA_LANGUAGE_NAME_LISTS[target];
  if (target_pool->names == NULL || target_pool->name_count == 0U) {
    return false;
  }

  const size_t list_range = CAPTCHA_NAME_LIST_MAX - CAPTCHA_NAME_LIST_MIN + (size_t)1U;
  const size_t list_offset = (size_t)(session_prng_next(state) % list_range);
  const size_t desired_count = CAPTCHA_NAME_LIST_MIN + list_offset;

  size_t max_target = target_pool->name_count;
  if (max_target > desired_count) {
    max_target = desired_count;
  }
  const size_t target_range = max_target + (size_t)1U;
  size_t target_count = (size_t)(session_prng_next(state) % target_range);
  if (target_count > desired_count) {
    target_count = desired_count;
  }

  size_t generated_count = 0U;
  while (generated_count < target_count && generated_count < CAPTCHA_NAME_LIST_MAX) {
    const size_t index =
        session_pick_unique_name_index(state, target_pool->name_count, used_names[target], CAPTCHA_LANGUAGE_POOL_MAX);
    generated[generated_count].text = target_pool->names[index];
    generated[generated_count].language = target;
    ++generated_count;
  }

  size_t safety = CAPTCHA_NAME_LIST_MAX * (size_t)4U;
  while (generated_count < desired_count && generated_count < CAPTCHA_NAME_LIST_MAX && safety > 0U) {
    --safety;
    if (CAPTCHA_NAME_LANGUAGE_COUNT <= 1U) {
      break;
    }

    unsigned raw_language = session_prng_next(state);
    captcha_name_language_t language =
        (captcha_name_language_t)(raw_language % (unsigned)(CAPTCHA_NAME_LANGUAGE_COUNT - 1U));
    if (language >= target) {
      language = (captcha_name_language_t)((unsigned)language + 1U);
    }

    const captcha_language_name_list_t *const pool = &CAPTCHA_LANGUAGE_NAME_LISTS[language];
    if (pool->names == NULL || pool->name_count == 0U) {
      continue;
    }

    const size_t index =
        session_pick_unique_name_index(state, pool->name_count, used_names[language], CAPTCHA_LANGUAGE_POOL_MAX);
    generated[generated_count].text = pool->names[index];
    generated[generated_count].language = language;
    ++generated_count;
  }

  if (generated_count == 0U) {
    return false;
  }

  session_shuffle_captcha_entries(generated, generated_count, state);

  char name_list[256];
  session_join_name_list(generated, generated_count, name_list, sizeof(name_list));

  const captcha_language_phrase_t *const phrases = &CAPTCHA_LANGUAGE_PHRASES[target];
  const size_t answer_count = session_count_target_names(generated, generated_count, target);

  snprintf(prompt->question_ko, sizeof(prompt->question_ko),
           "다음 이름 목록에서 %s은(는) 몇 개입니까? 목록: %s", phrases->ko, name_list);
  snprintf(prompt->question_en, sizeof(prompt->question_en),
           "In the following list of names, how many %s are there? List: %s", phrases->en, name_list);
  snprintf(prompt->question_ru, sizeof(prompt->question_ru),
           "Сколько %s в следующем списке? Список: %s", phrases->ru, name_list);
  snprintf(prompt->question_zh, sizeof(prompt->question_zh),
           "在以下名字列表中，有多少個%s？名單：%s", phrases->zh, name_list);
  snprintf(prompt->answer, sizeof(prompt->answer), "%zu", answer_count);

  return true;
}

static void session_fill_comparison_prompt(captcha_prompt_t *prompt, unsigned *state) {
  if (prompt == NULL) {
    return;
  }

  unsigned first_raw = 311U;
  unsigned second_raw = 390U;
  if (state != NULL) {
    first_raw = 100U + (session_prng_next(state) % 900U);
    second_raw = 100U + (session_prng_next(state) % 900U);
    if (first_raw == second_raw) {
      const unsigned offset = (unsigned)(((second_raw - 100U) + 1U) % 900U);
      second_raw = 100U + offset;
    }
  }

  const double first_value = (double)first_raw / 100.0;
  const double second_value = (double)second_raw / 100.0;

  char first_text[32];
  char second_text[32];
  session_format_decimal(first_value, first_text, sizeof(first_text));
  session_format_decimal(second_value, second_text, sizeof(second_text));

  snprintf(prompt->question_en, sizeof(prompt->question_en), "Which number is larger, %s or %s?", first_text, second_text);
  snprintf(prompt->question_ko, sizeof(prompt->question_ko), "%s와 %s 중 어떤 게 더 큰가요?", first_text, second_text);
  snprintf(prompt->question_ru, sizeof(prompt->question_ru), "Какое число больше: %s или %s?", first_text, second_text);
  snprintf(prompt->question_zh, sizeof(prompt->question_zh), "%s 和 %s 中哪一個數字較大？", first_text, second_text);

  const char *const answer_text = (first_value > second_value) ? first_text : second_text;
  snprintf(prompt->answer, sizeof(prompt->answer), "%s", answer_text);
}

static bool string_contains_case_insensitive(const char *haystack, const char *needle) {
  if (haystack == NULL || needle == NULL || *needle == '\0') {
    return false;
  }

  const size_t haystack_length = strlen(haystack);
  const size_t needle_length = strlen(needle);
  if (needle_length == 0U || haystack_length < needle_length) {
    return false;
  }

  for (size_t idx = 0; idx <= haystack_length - needle_length; ++idx) {
    size_t matched = 0U;
    while (matched < needle_length) {
      const unsigned char hay = (unsigned char)haystack[idx + matched];
      const unsigned char nee = (unsigned char)needle[matched];
      if (tolower(hay) != tolower(nee)) {
        break;
      }
      ++matched;
    }
    if (matched == needle_length) {
      return true;
    }
  }

  return false;
}

static bool host_is_leap_year(int year) {
  if (year <= 0) {
    return false;
  }

  if ((year % 4) != 0) {
    return false;
  }
  if ((year % 100) != 0) {
    return true;
  }
  return (year % 400) == 0;
}

static struct timespec timespec_diff(const struct timespec *end, const struct timespec *start) {
  struct timespec result = {0, 0};
  if (end == NULL || start == NULL) {
    return result;
  }

  time_t sec = end->tv_sec - start->tv_sec;
  long nsec = end->tv_nsec - start->tv_nsec;
  if (nsec < 0) {
    --sec;
    nsec += 1000000000L;
  }
  if (sec < 0) {
    sec = 0;
    nsec = 0;
  }
  result.tv_sec = sec;
  result.tv_nsec = nsec;
  return result;
}

static bool host_listener_attempt_recover(host_t *host, ssh_bind bind_handle, const char *address,
                                          const char *bind_port) {
  if (host == NULL || bind_handle == NULL) {
    return false;
  }

  printf("[listener] attempting in-place recovery on %s:%s after socket error\n", address, bind_port);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
  ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);
  if (ssh_bind_listen(bind_handle) == SSH_OK) {
    host->listener.inplace_recoveries += 1U;
    printf("[listener] listener recovered without restart (total in-place recoveries: %u)\n",
           host->listener.inplace_recoveries);
    return true;
  }

  const char *error_message = ssh_get_error(bind_handle);
  if (error_message == NULL || error_message[0] == '\0') {
    error_message = "unknown error";
  }
  printf("[listener] in-place recovery failed: %s\n", error_message);
  return false;
}

static bool host_join_key_path(const char *directory, const char *filename, char *buffer, size_t buffer_len) {
  if (directory == NULL || filename == NULL || buffer == NULL || buffer_len == 0U) {
    return false;
  }

  const size_t dir_len = strlen(directory);
  const bool needs_separator = dir_len > 0U && directory[dir_len - 1U] != '/';
  const int written = snprintf(buffer, buffer_len, "%s%s%s", directory, needs_separator ? "/" : "",
                               filename);
  if (written < 0 || (size_t)written >= buffer_len) {
    return false;
  }

  return true;
}

static bool host_bind_algorithm_is_rsa(const char *algorithm) {
  return algorithm != NULL && strcmp(algorithm, "ssh-rsa") == 0;
}

static void host_bind_append_single_algorithm(char *buffer, size_t buffer_len, size_t *current_len,
                                              const char *algorithm) {
  if (buffer == NULL || current_len == NULL || algorithm == NULL || algorithm[0] == '\0' || buffer_len == 0U) {
    return;
  }

  const size_t usable_length = buffer_len - 1U;
  if (*current_len > usable_length) {
    *current_len = usable_length;
    buffer[usable_length] = '\0';
    return;
  }

  if (*current_len > 0U) {
    if (*current_len >= usable_length) {
      buffer[usable_length] = '\0';
      return;
    }
    buffer[*current_len] = ',';
    ++(*current_len);
  }

  size_t remaining = usable_length - *current_len;
  if (remaining == 0U) {
    buffer[*current_len] = '\0';
    return;
  }

  size_t algorithm_length = strlen(algorithm);
  if (algorithm_length > remaining) {
    algorithm_length = remaining;
  }

  memcpy(buffer + *current_len, algorithm, algorithm_length);
  *current_len += algorithm_length;
  buffer[*current_len] = '\0';
}

static void host_bind_append_algorithm(char *buffer, size_t buffer_len, size_t *current_len,
                                       const char *algorithm) {
  if (buffer == NULL || current_len == NULL || algorithm == NULL || algorithm[0] == '\0' || buffer_len == 0U) {
    return;
  }

  if (host_bind_algorithm_is_rsa(algorithm)) {
    host_bind_append_single_algorithm(buffer, buffer_len, current_len, "rsa-sha2-512");
    host_bind_append_single_algorithm(buffer, buffer_len, current_len, "rsa-sha2-256");
  }

  host_bind_append_single_algorithm(buffer, buffer_len, current_len, algorithm);
}

static bool host_bind_import_key(ssh_bind bind_handle, const char *algorithm, const char *key_path) {
  if (bind_handle == NULL || algorithm == NULL || key_path == NULL) {
    return false;
  }

  ssh_key imported_key = NULL;
  if (ssh_pki_import_privkey_file(key_path, NULL, NULL, NULL, &imported_key) != SSH_OK || imported_key == NULL) {
    char message[256];
    snprintf(message, sizeof(message), "failed to import %s host key", algorithm);
    humanized_log_error("host", message, errno != 0 ? errno : EIO);
    if (imported_key != NULL) {
      ssh_key_free(imported_key);
    }
    return false;
  }

  errno = 0;
  const int import_result = ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_IMPORT_KEY, imported_key);
  ssh_key_free(imported_key);
  if (import_result != SSH_OK) {
    const char *error_message = ssh_get_error(bind_handle);
    char message[256];
    snprintf(message, sizeof(message), "failed to register %s host key", algorithm);
    humanized_log_error("host", error_message != NULL ? error_message : message, errno != 0 ? errno : EIO);
    return false;
  }

  return true;
}

static bool host_bind_load_key(ssh_bind bind_handle, const host_key_definition_t *definition,
                               const char *key_path) {
  if (bind_handle == NULL || definition == NULL || key_path == NULL) {
    return false;
  }

  bool require_import = definition->requires_import;
  if (!require_import) {
    errno = 0;
    const int set_result = ssh_bind_options_set(bind_handle, definition->option, key_path);
    if (set_result == SSH_OK) {
      return true;
    }

    const char *error_message = ssh_get_error(bind_handle);
    const bool unsupported_option =
        (error_message != NULL && strstr(error_message, "Unknown ssh option") != NULL) || errno == ENOTSUP;
    if (!unsupported_option) {
      char message[256];
      snprintf(message, sizeof(message), "failed to load %s host key", definition->algorithm);
      humanized_log_error("host", error_message != NULL ? error_message : message, errno != 0 ? errno : EIO);
      return false;
    }
    require_import = true;
  }

  if (require_import && !definition->requires_import) {
    printf("[listener] importing %s host key due to limited libssh support\n", definition->algorithm);
  }

  return host_bind_import_key(bind_handle, definition->algorithm, key_path);
}

static void host_bind_set_optional_string(ssh_bind bind_handle, ssh_bind_options_e option, const char *value,
                                          const char *label) {
  if (bind_handle == NULL || value == NULL || value[0] == '\0') {
    return;
  }

  errno = 0;
  if (ssh_bind_options_set(bind_handle, option, value) == SSH_OK) {
    return;
  }

  const char *error_message = ssh_get_error(bind_handle);
  const bool unsupported_option =
      (error_message != NULL && strstr(error_message, "Unknown ssh option") != NULL) || errno == ENOTSUP;
  if (unsupported_option) {
    return;
  }

  char message[256];
  snprintf(message, sizeof(message), "%s", label != NULL ? label : "failed to configure listener option");
  humanized_log_error("host", error_message != NULL ? error_message : message, errno != 0 ? errno : EIO);
}

static struct timespec timespec_add_ms(const struct timespec *start, long milliseconds) {
  struct timespec result = {0, 0};
  if (start != NULL) {
    result = *start;
  }

  long seconds = milliseconds / 1000L;
  long remaining_ms = milliseconds % 1000L;
  result.tv_sec += seconds;
  result.tv_nsec += remaining_ms * 1000000L;
  if (result.tv_nsec >= 1000000000L) {
    result.tv_sec += result.tv_nsec / 1000000000L;
    result.tv_nsec %= 1000000000L;
  }
  return result;
}

static int timespec_compare(const struct timespec *lhs, const struct timespec *rhs) {
  if (lhs == NULL || rhs == NULL) {
    return 0;
  }
  if (lhs->tv_sec < rhs->tv_sec) {
    return -1;
  }
  if (lhs->tv_sec > rhs->tv_sec) {
    return 1;
  }
  if (lhs->tv_nsec < rhs->tv_nsec) {
    return -1;
  }
  if (lhs->tv_nsec > rhs->tv_nsec) {
    return 1;
  }
  return 0;
}

static bool host_try_load_motd_from_path(host_t *host, const char *path);

static struct timespec host_stat_mtime(const struct stat *info) {
  struct timespec result = {0, 0};
  if (info == NULL) {
    return result;
  }

#if defined(__APPLE__)
  result.tv_sec = info->st_mtimespec.tv_sec;
  result.tv_nsec = info->st_mtimespec.tv_nsec;
#elif defined(_BSD_SOURCE) || defined(_SVID_SOURCE) || defined(__USE_XOPEN2K8)
  result.tv_sec = info->st_mtim.tv_sec;
  result.tv_nsec = info->st_mtim.tv_nsec;
#else
  result.tv_sec = info->st_mtime;
  result.tv_nsec = 0;
#endif

  if (result.tv_sec < 0) {
    result.tv_sec = 0;
  }
  if (result.tv_nsec < 0) {
    result.tv_nsec = 0;
  }
  return result;
}

static void host_maybe_reload_motd_from_file(host_t *host) {
  if (host == NULL) {
    return;
  }

  char stored_path[PATH_MAX];
  stored_path[0] = '\0';
  struct timespec last_loaded = {0, 0};
  bool had_file = false;

  pthread_mutex_lock(&host->lock);
  if (host->motd_path[0] != '\0') {
    snprintf(stored_path, sizeof(stored_path), "%s", host->motd_path);
    last_loaded = host->motd_last_modified;
    had_file = host->motd_has_file;
  }
  pthread_mutex_unlock(&host->lock);

  if (stored_path[0] == '\0') {
    return;
  }

  char resolved_path[PATH_MAX];
  resolved_path[0] = '\0';

  if (stored_path[0] == '~' && (stored_path[1] == '\0' || stored_path[1] == '/')) {
    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0') {
      int expanded = snprintf(resolved_path, sizeof(resolved_path), "%s%s", home, stored_path + 1);
      if (expanded <= 0 || (size_t)expanded >= sizeof(resolved_path)) {
        resolved_path[0] = '\0';
      }
    }
  }

  const char *path_to_try = resolved_path[0] != '\0' ? resolved_path : stored_path;

  struct stat file_info;
  if (stat(path_to_try, &file_info) != 0 || !S_ISREG(file_info.st_mode)) {
    if (!had_file) {
      (void)host_try_load_motd_from_path(host, path_to_try);
    }
    if (had_file) {
      pthread_mutex_lock(&host->lock);
      if (host->motd_has_file && strncmp(host->motd_path, stored_path, sizeof(host->motd_path)) == 0) {
        host->motd_has_file = false;
        host->motd_last_modified.tv_sec = 0;
        host->motd_last_modified.tv_nsec = 0L;
      }
      pthread_mutex_unlock(&host->lock);
    }
    return;
  }

  struct timespec modified = host_stat_mtime(&file_info);

  if (had_file && modified.tv_sec == last_loaded.tv_sec && modified.tv_nsec == last_loaded.tv_nsec) {
    return;
  }

  (void)host_try_load_motd_from_path(host, path_to_try);
}

static unsigned session_simple_hash(const char *text) {
  unsigned hash = 5381U;
  if (text == NULL) {
    return hash;
  }

  for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
    hash = (hash * 33U) ^ *cursor;
  }
  return hash;
}

static void session_build_captcha_prompt(session_ctx_t *ctx, captcha_prompt_t *prompt) {
  if (prompt == NULL) {
    return;
  }

  memset(prompt, 0, sizeof(*prompt));

  unsigned basis = session_simple_hash(ctx != NULL ? ctx->user.name : "user");
  basis ^= session_simple_hash(ctx != NULL ? ctx->client_ip : "ip");

  unsigned entropy = 0U;
  struct timespec now = {0, 0};
  if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
    uint64_t now_sec = (uint64_t)now.tv_sec;
    entropy ^= (unsigned)now_sec;
    entropy ^= (unsigned)(now_sec >> 32);
    entropy ^= (unsigned)now.tv_nsec;
  } else {
    uint64_t fallback = (uint64_t)time(NULL);
    entropy ^= (unsigned)fallback;
    entropy ^= (unsigned)(fallback >> 32);
  }

  host_t *host = (ctx != NULL) ? ctx->owner : NULL;
  if (host != NULL) {
    pthread_mutex_lock(&host->lock);
    uint64_t nonce = ++host->captcha_nonce;
    pthread_mutex_unlock(&host->lock);
    entropy ^= (unsigned)nonce;
    entropy ^= (unsigned)(nonce >> 32);
  }

  basis ^= entropy;

  const unsigned variant_seed = basis ^ (basis >> 16U) ^ (entropy << 1U);
  unsigned prng_state = variant_seed | 1U;

  if ((variant_seed & 1U) == 0U) {
    session_fill_comparison_prompt(prompt, &prng_state);
    return;
  }

  if (!session_fill_name_count_prompt(prompt, &prng_state)) {
    session_fill_comparison_prompt(prompt, &prng_state);
  }
}

typedef struct {
  const char *name;
  const char *code;
} color_entry_t;

static const color_entry_t USER_COLOR_MAP[] = {
  {"black", ANSI_BLACK},          {"red", ANSI_RED},
  {"green", ANSI_GREEN},          {"yellow", ANSI_YELLOW},
  {"blue", ANSI_BLUE},           {"magenta", ANSI_MAGENTA},
  {"cyan", ANSI_CYAN},           {"white", ANSI_WHITE},
  {"default", ANSI_DEFAULT},

  {"bright-black", ANSI_BRIGHT_BLACK},   {"bright-red", ANSI_BRIGHT_RED},
  {"bright-green", ANSI_BRIGHT_GREEN}, {"bright-yellow", ANSI_BRIGHT_YELLOW},
  {"bright-blue", ANSI_BRIGHT_BLUE},   {"bright-magenta", ANSI_BRIGHT_MAGENTA},
  {"bright-cyan", ANSI_BRIGHT_CYAN},   {"bright-white", ANSI_BRIGHT_WHITE},
};

static const color_entry_t HIGHLIGHT_COLOR_MAP[] = {
  {"black", ANSI_BG_BLACK},       {"red", ANSI_BG_RED},
  {"green", ANSI_BG_GREEN},       {"yellow", ANSI_BG_YELLOW},
  {"blue", ANSI_BG_BLUE},        {"magenta", ANSI_BG_MAGENTA},
  {"cyan", ANSI_BG_CYAN},        {"white", ANSI_BG_WHITE},
  {"default", ANSI_BG_DEFAULT},

  {"bright-black", ANSI_BG_BRIGHT_BLACK}, {"bright-red", ANSI_BG_BRIGHT_RED},
  {"bright-green", ANSI_BG_BRIGHT_GREEN}, {"bright-yellow", ANSI_BG_BRIGHT_YELLOW},
  {"bright-blue", ANSI_BG_BRIGHT_BLUE},  {"bright-magenta", ANSI_BG_BRIGHT_MAGENTA},
  {"bright-cyan", ANSI_BG_BRIGHT_CYAN},  {"bright-white", ANSI_BG_BRIGHT_WHITE},
};

typedef struct palette_descriptor {
  const char *name;
  const char *description;
  const char *user_color_name;
  const char *user_highlight_name;
  bool user_is_bold;
  const char *system_fg_name;
  const char *system_bg_name;
  const char *system_highlight_name;
  bool system_is_bold;
} palette_descriptor_t;

static const palette_descriptor_t PALETTE_DEFINITIONS[] = {
  {"windows", "High contrast palette reminiscent of Windows", "cyan", "blue", true, "white", "blue", "yellow", true},
  {"gnu-linux", "Modern, elegant, and free. the universal rhythm of your workflow.", "bright-green", "black", true, "blue", "black", "bright-yellow", true},
  {"macos", "Precision in silence. Minimalist contemporary unix.", "bright-white", "black", false, "bright-blue", "black", "white", false},
  {"freebsd", "Rigid and graceful BSD. The biggest 'True UNIX'", "bright-red", "black", false, "red", "black", "bright-white", false},
  {"solaris", "Ancient sun of enterprise UNIX: Sun, Machine, nostalgia.", "bright-yellow", "black", true, "bright-red", "black", "bright-white", true},
  {"openbsd-fortress", "Security through simplicity. calm blue walls over disciplined darkness.", "bright-blue", "black", false, "bright-white", "black", "cyan", false},
  {"netbsd-universal", "Runs on anything. Maybe your fridge, too?", "bright-cyan", "black", false, "bright-white", "black", "bright-yellow", false},

  {"moe", "Soft magenta accents with playful highlights", "bright-magenta", "white", true, "white", "bright-magenta", "cyan", true},
  {"neon-genesis-evangelion", "Sho-nen yo Shin-wa ni nare--", "bright-red", "white", true, "white", "bright-magenta", "blue", true},
  {"megami", "Japanese anime goddess cliché", "bright-white", "black", false, "bright-yellow", "blue", "cyan", false},

  {"clean", "Balanced neutral palette", "default", "default", false, "white", "default", "default", false},
  {"adwaita", "Bright background inspired by GNOME Adwaita", "blue", "default", false, "blue", "bright-white", "white", true},

  {"80shacker", "Bright monochrome green inspired by old CRT", "bright-green", "default", true, "bright-green", "default", "default", true},
  {"plato", "Bright monochrome yellow inspired by old Amber CRT", "yellow", "default", false, "yellow", "default", "default", false},
  {"atarist", "Sharp paper-white monochrome for high-res work", "bright-white", "black", true, "bright-white", "black", "black", false},
  {"win95bsod", "High-contrast blue screen of death style", "bright-white", "blue", true, "bright-white", "blue", "cyan", true},
  {"chn-hanzi", "Bright cyan high-clarity Chinese text terminal", "bright-cyan", "black", true, "white", "black", "cyan", true},

  {"usa-flag", "Flag blue base with red/white highlights", "bright-white", "blue", true, "red", "blue", "bright-white", true},
  {"jpn-flag", "Minimalist white with rising sun red accent", "bright-white", "black", false, "red", "black", "black", true},
  {"chn-flag", "Star-red background with lucky yellow text", "bright-yellow", "red", true, "white", "red", "white", true},
  {"rus-flag", "Tricolor base with strong red emphasis", "bright-white", "blue", true, "red", "blue", "bright-white", true},
  {"de-flag", "Tricolor base with strong red/yellow emphasis", "bright-black", "black", true, "yellow", "black", "red", true},
  {"holy-light", "Christian sacred light on pure white/blue base", "bright-white", "blue", false, "blue", "black", "yellow", true},

  {"islam", "Iconic color of muslim, white/green base", "bright-white", "green", false, "green", "black", "bright-white", true},
  {"dharma-ochre", "Ochre robes of enlightenment and vitality", "yellow", "black", true, "red", "black", "yellow", true},
  {"yin-yang", "Balance of Black and White with Jade accent", "white", "black", false, "green", "black", "white", false},

  {"soviet-cold", "Cold blue/white terminal for scientific systems", "white", "blue", false, "white", "blue", "cyan", false},
  {"hi-tel", "1990s Korean BBS blue background and text style", "bright-white", "blue", true, "bright-white", "blue", "magenta", true},
  {"amiga-cli", "AmigaOS style with cyan/blue", "cyan", "blue", true, "cyan", "blue", "blue", true},
  {"jpn-pc98", "NEC PC-9801 subtle, earthy low-res tones", "yellow", "black", false, "red", "black", "yellow", false},
  {"deep-blue", "IBM Supercomputer monitoring interface style", "white", "blue", true, "cyan", "blue", "white", true},

  {"korea", "Taegeuk-gi inspired black base with red and blue accents", "bright-blue", "blue", true, "bright-white", "blue", "red", true},

  {"neo-seoul", "Neon skyline of Gangnam and Hongdae: glowing magenta and cyan lights on dark asphalt", "bright-magenta", "black", true, "bright-cyan", "black", "cyan", true},
  {"incheon-industrial", "Metallic cranes and sodium streetlights of Incheon docks", "bright-yellow", "black", true, "bright-yellow", "black", "bright-red", true},
  {"gyeonggi-modern", "Suburban calm of modern Korea. asphalt gray and warm window light", "bright-white", "black", false, "bright-yellow", "black", "bright-cyan", false},
  {"korean-palace", "Royal dancheong harmony: jade green, vermilion red, and gold over black lacquer", "bright-yellow", "black", true, "red", "black", "green", false},

  {"gyeongsangbukdo", "Stoic mountains and agricultural spirit. stone, pine, and the quiet gold of temples", "bright-yellow", "black", false, "bright-green", "black", "bright-white", false},
  {"daegu-summer", "The biggest, the hottest of north gyeongsang: Blazing red-orange heat and festival gold under night sky", "bright-red", "black", true, "bright-yellow", "black", "yellow", true},
  {"gyeongju-heritage", "Eternal relics and golden crowns: moonlit stone and ancient buddhism with blue flag of shilla military force", "bright-white", "black", false, "bright-yellow", "black", "blue", false},
  {"kangwon-winter", "Cold white peaks and blue shadows of Gangwon’s frozen dawn", "bright-white", "blue", true, "bright-cyan", "blue", "white", true},
  {"ulsan-steel", "Molten metal glow inside heavy industry furnace halls", "bright-red", "black", true, "bright-yellow", "black", "red", true},

  {"jeolla-seaside", "Quiet sea and horizon light of Mokpo and Yeosu nights", "bright-cyan", "black", false, "cyan", "black", "bright-blue", true},
  {"gwangju-biennale", "Experimental art city with a heritage of democracy: violet neon and philosophical blue", "bright-magenta", "black", true, "bright-blue", "black", "magenta", true},
  {"jeonju-hanok", "The symbol of north jeolla. warm roofs and calm golden light", "bright-yellow", "black", false, "yellow", "black", "bright-white", false},

  {"daejeon-tech", "Futuristic research district glow: clean LED light on steel gray night", "white", "black", true, "white", "black", "bright-green", true},
  {"sejong-night", "Balanced dark-blue administration city under cool LED light", "bright-white", "blue", true, "bright-cyan", "blue", "white", true},
  {"cheongju-intellect", "Scholarly ink and soft dawn over hills: serene blue clarity", "bright-cyan", "black", false, "bright-white", "black", "cyan", false},
  {"chungcheong-field", "Muted greens and dust gold of inland farmlands", "yellow", "black", false, "green", "black", "yellow", false},

  {"jeju-rock", "Volcanic basalt, moss green, and deep sea mist of Jeju Island", "bright-green", "black", false, "bright-cyan", "black", "green", false},

  {"gyeongsangnamdo", "Sea breeze and industry — blue steel, orange dusk, and vibrant harbors", "bright-blue", "black", true, "bright-yellow", "black", "bright-cyan", true},
  {"busan-harbor", "Night harbor lights and steel-blue waters of Busan Port", "bright-blue", "black", true, "cyan", "black", "bright-blue", true},

  {"han", "Deep unresolved sorrow and austere beauty pale blue and gray layers", "bright-cyan", "blue", false, "white", "blue", "bright-white", false},
  {"jeong", "Warm emotional bonds and communal comfort soft red and gold glow on darkness", "bright-red", "black", true, "black", "black", "bright-yellow", true},
  {"heung", "Joyful energy and dynamic spirit: brilliant magenta and yellow over black", "bright-magenta", "black", true, "bright-yellow", "black", "magenta", true},
  {"nunchi", "Subtle perception and quiet adaptation: dim neutral tones with cyan glints", "white", "black", false, "bright-cyan", "black", "cyan", false},

  {"pcbang-night", "Late-night gaming neon: cold blue LEDs, energy drink, and so on", "bright-cyan", "black", true, "bright-red", "black", "bright-blue", true},
  {"alcohol", "Soju nights and neon haze: industrial green bottles and pink laughter", "bright-green", "black", true, "bright-magenta", "black", "green", true},

  {"korean-hardcore", "I don't wanna die yet! neon blood and cold steel over asphalt black", "bright-red", "black", true, "bright-blue", "black", "bright-red", true},
  {"korean-nationalists", "Slightly exclusive types. you know the kind.", "bright-green", "black", true, "bright-blue", "black", "bright-cyan", true},

  {"medieval-korea", "Celadon grace and temple gold over aged ink-black lacquer", "bright-cyan", "black", false, "bright-yellow", "black", "cyan", false},
  {"stoneage-korea", "Primitive contrast of pale clothing and ground stone tools - raw earth and silence", "bright-white", "black", false, "bright-yellow", "black", "white", false},

  {"flame-and-blood", "An East Asian war of 1592–1598. A great conflict akin to a world war, where flame met blood and nothing could be forsaken.", "bright-blue", "black", true, "bright-yellow", "black", "red", true},
  {"korean-war", "The Korean War: an unforgettable sorrow beneath ash, blood, and snow.", "bright-white", "black", false, "bright-red", "black", "white", false},
  {"independence-spirit", "The spirit of independence. A soul that we must remember.", "bright-red", "black", true, "blue", "black", "bright-yellow", true},
};

typedef int (*accept_channel_fn_t)(ssh_message, ssh_channel);

#if defined(__GNUC__)
extern int ssh_message_channel_request_open_reply_accept_channel(ssh_message message,
                                                                 ssh_channel channel)
    __attribute__((weak));
#endif

static void resolve_accept_channel_once(void);
static accept_channel_fn_t g_accept_channel_fn = NULL;
static pthread_once_t g_accept_channel_once = PTHREAD_ONCE_INIT;

static accept_channel_fn_t resolve_accept_channel_fn(void) {
  pthread_once(&g_accept_channel_once, resolve_accept_channel_once);
  return g_accept_channel_fn;
}

static void resolve_accept_channel_once(void) {
#if defined(__GNUC__)
  if (ssh_message_channel_request_open_reply_accept_channel != NULL) {
    g_accept_channel_fn = ssh_message_channel_request_open_reply_accept_channel;
    return;
  }
#endif

  static const char *kSymbol = "ssh_message_channel_request_open_reply_accept_channel";

#if defined(RTLD_DEFAULT)
  g_accept_channel_fn = (accept_channel_fn_t)dlsym(RTLD_DEFAULT, kSymbol);
  if (g_accept_channel_fn != NULL) {
    return;
  }
#endif

  const char *candidates[] = {"libssh.so.4", "libssh.so", "libssh.dylib"};
  for (size_t idx = 0; idx < sizeof(candidates) / sizeof(candidates[0]); ++idx) {
    const char *name = candidates[idx];
    void *handle = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
      handle = dlopen(name, RTLD_LAZY);
    }
    if (handle == NULL) {
      continue;
    }

    g_accept_channel_fn = (accept_channel_fn_t)dlsym(handle, kSymbol);
    if (g_accept_channel_fn != NULL) {
      return;
    }
  }
}

static void trim_whitespace_inplace(char *text);
static const char *lookup_color_code(const color_entry_t *entries, size_t entry_count, const char *name);
static bool parse_bool_token(const char *token, bool *value);
static bool session_transport_active(const session_ctx_t *ctx);
static void session_transport_request_close(session_ctx_t *ctx);
static void session_channel_write(session_ctx_t *ctx, const void *data, size_t length);
static bool session_channel_write_all(session_ctx_t *ctx, const void *data, size_t length);
static bool session_channel_wait_writable(session_ctx_t *ctx, int timeout_ms);
static void session_channel_log_write_failure(session_ctx_t *ctx, const char *reason);
static int session_transport_read(session_ctx_t *ctx, void *buffer, size_t length, int timeout_ms);
static bool session_transport_is_open(const session_ctx_t *ctx);
static bool session_transport_is_eof(const session_ctx_t *ctx);
static void session_apply_background_fill(session_ctx_t *ctx);
static void session_write_rendered_line(session_ctx_t *ctx, const char *render_source);
static void session_send_caption_line(session_ctx_t *ctx, const char *message);
static void session_render_caption_with_offset(session_ctx_t *ctx, const char *message, size_t move_up);
static void session_send_line(session_ctx_t *ctx, const char *message);
static void session_send_plain_line(session_ctx_t *ctx, const char *message);
static void session_send_system_line(session_ctx_t *ctx, const char *message);
static void session_send_raw_text(session_ctx_t *ctx, const char *text);
static void session_send_raw_text_bulk(session_ctx_t *ctx, const char *text);
static void session_send_system_lines_bulk(session_ctx_t *ctx, const char *const *lines, size_t line_count);
static void session_render_banner(session_ctx_t *ctx);
static void session_format_separator_line(session_ctx_t *ctx, const char *label, char *out, size_t length);
static void session_render_separator(session_ctx_t *ctx, const char *label);
static void session_clear_screen(session_ctx_t *ctx);
static void session_bbs_prepare_canvas(session_ctx_t *ctx);
static void session_bbs_render_editor(session_ctx_t *ctx, const char *status);
static void session_bbs_recalculate_line_count(session_ctx_t *ctx);
static bool session_bbs_get_line_range(const session_ctx_t *ctx, size_t line_index, size_t *start, size_t *length);
static void session_bbs_copy_line(const session_ctx_t *ctx, size_t line_index, char *buffer, size_t length);
static bool session_bbs_append_line(session_ctx_t *ctx, const char *line, char *status, size_t status_length);
static bool session_bbs_replace_line(session_ctx_t *ctx, size_t line_index, const char *line, char *status,
                                     size_t status_length);
static void session_bbs_move_cursor(session_ctx_t *ctx, int direction);
static bool session_bbs_is_admin_only_tag(const char *tag);
static void session_bbs_buffer_breaking_notice(session_ctx_t *ctx, const char *message);
static bool session_bbs_should_defer_breaking(session_ctx_t *ctx, const char *message);
static void session_render_prompt(session_ctx_t *ctx, bool include_separator);
static void session_refresh_input_line(session_ctx_t *ctx);
static void session_set_input_text(session_ctx_t *ctx, const char *text);
static void session_local_echo_char(session_ctx_t *ctx, char ch);
static void session_local_backspace(session_ctx_t *ctx);
static void session_clear_input(session_ctx_t *ctx);
static bool session_try_command_completion(session_ctx_t *ctx);
static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch);
static void session_cleanup(session_ctx_t *ctx);
static void *session_thread(void *arg);
static void host_telnet_listener_stop(host_t *host);
static void session_history_record(session_ctx_t *ctx, const char *line);
static void session_history_navigate(session_ctx_t *ctx, int direction);
static void session_scrollback_navigate(session_ctx_t *ctx, int direction);
static void chat_history_entry_prepare_user(chat_history_entry_t *entry, const session_ctx_t *from, const char *message);
static bool host_history_record_user(host_t *host, const session_ctx_t *from, const char *message, chat_history_entry_t *stored_entry);
static bool host_history_commit_entry(host_t *host, chat_history_entry_t *entry, chat_history_entry_t *stored_entry);
static void host_notify_external_clients(host_t *host, const chat_history_entry_t *entry);
static bool host_history_append_locked(host_t *host, const chat_history_entry_t *entry);
static bool host_history_reserve_locked(host_t *host, size_t min_capacity);
static size_t host_history_total(host_t *host);
static size_t host_history_copy_range(host_t *host, size_t start_index, chat_history_entry_t *buffer, size_t capacity);
static bool host_history_find_entry_by_id(host_t *host, uint64_t message_id, chat_history_entry_t *entry);
static size_t host_history_delete_range(host_t *host, uint64_t start_id, uint64_t end_id, uint64_t *first_removed,
                                        uint64_t *last_removed, size_t *replies_removed);
static void chat_room_broadcast_entry(chat_room_t *room, const chat_history_entry_t *entry, const session_ctx_t *from);
static void chat_room_broadcast_caption(chat_room_t *room, const char *message);
static bool host_history_apply_reaction(host_t *host, uint64_t message_id, size_t reaction_index, chat_history_entry_t *updated_entry);
static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length);
static void host_ban_resolve_path(host_t *host);
static void host_ban_state_save_locked(host_t *host);
static void host_ban_state_load(host_t *host);
static void host_reply_state_resolve_path(host_t *host);
static void host_reply_state_save_locked(host_t *host);
static void host_reply_state_load(host_t *host);
static bool host_replies_find_entry_by_id(host_t *host, uint64_t reply_id, chat_reply_entry_t *entry);
static bool host_replies_commit_entry(host_t *host, chat_reply_entry_t *entry, chat_reply_entry_t *stored_entry);
static void session_send_reply_tree(session_ctx_t *ctx, uint64_t parent_message_id, uint64_t parent_reply_id, size_t depth);
static void host_broadcast_reply(host_t *host, const chat_reply_entry_t *entry);
static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source,
                                              const char *label, const char *message);
static session_ctx_t *chat_room_find_user(chat_room_t *room, const char *username);
static bool host_is_ip_banned(host_t *host, const char *ip);
static bool host_is_username_banned(host_t *host, const char *username);
static bool host_add_ban_entry(host_t *host, const char *username, const char *ip);
static bool host_remove_ban_entry(host_t *host, const char *token);
static join_activity_entry_t *host_find_join_activity_locked(host_t *host, const char *ip);
static join_activity_entry_t *host_ensure_join_activity_locked(host_t *host, const char *ip);
static bool host_register_suspicious_activity(host_t *host, const char *username, const char *ip,
                                             size_t *attempts_out);
static bool session_is_private_ipv4(const unsigned char octets[4]);
static bool session_is_lan_client(const char *ip);
static void session_assign_lan_privileges(session_ctx_t *ctx);
static void session_apply_granted_privileges(session_ctx_t *ctx);
static void session_apply_theme_defaults(session_ctx_t *ctx);
static void session_apply_system_theme_defaults(session_ctx_t *ctx);
static void session_force_dark_mode_foreground(session_ctx_t *ctx);
static void session_apply_saved_preferences(session_ctx_t *ctx);
static void session_dispatch_command(session_ctx_t *ctx, const char *line);
static void session_handle_exit(session_ctx_t *ctx);
static void session_force_disconnect(session_ctx_t *ctx, const char *reason);
static void session_handle_nick(session_ctx_t *ctx, const char *arguments);
static bool session_detect_provider_ip(const char *ip, char *label, size_t length);
static bool host_lookup_member_ip(host_t *host, const char *username, char *ip, size_t length);
static bool session_should_hide_entry(session_ctx_t *ctx, const chat_history_entry_t *entry);
static bool session_blocklist_add(session_ctx_t *ctx, const char *ip, const char *username, bool ip_wide,
                                  bool *already_present);
static bool session_blocklist_remove(session_ctx_t *ctx, const char *token);
static void session_blocklist_show(session_ctx_t *ctx);
static void session_handle_reply(session_ctx_t *ctx, const char *arguments);
static void session_handle_block(session_ctx_t *ctx, const char *arguments);
static void session_handle_unblock(session_ctx_t *ctx, const char *arguments);
static void session_handle_pm(session_ctx_t *ctx, const char *arguments);
static void session_handle_motd(session_ctx_t *ctx);
static void session_handle_system_color(session_ctx_t *ctx, const char *arguments);
static void session_handle_palette(session_ctx_t *ctx, const char *arguments);
static void session_handle_translate(session_ctx_t *ctx, const char *arguments);
static void session_handle_translate_scope(session_ctx_t *ctx, const char *arguments);
static void session_handle_gemini(session_ctx_t *ctx, const char *arguments);
static void session_handle_set_trans_lang(session_ctx_t *ctx, const char *arguments);
static void session_handle_set_target_lang(session_ctx_t *ctx, const char *arguments);
static void session_handle_chat_spacing(session_ctx_t *ctx, const char *arguments);
static void session_handle_mode(session_ctx_t *ctx, const char *arguments);
static void session_handle_eliza(session_ctx_t *ctx, const char *arguments);
static void session_handle_eliza_chat(session_ctx_t *ctx, const char *arguments);
static void session_handle_status(session_ctx_t *ctx, const char *arguments);
static void session_handle_showstatus(session_ctx_t *ctx, const char *arguments);
static void session_handle_weather(session_ctx_t *ctx, const char *arguments);
static void session_handle_pardon(session_ctx_t *ctx, const char *arguments);
static void session_handle_ban_list(session_ctx_t *ctx, const char *arguments);
static void session_handle_kick(session_ctx_t *ctx, const char *arguments);
static void session_handle_usercount(session_ctx_t *ctx);
static bool host_username_reserved(host_t *host, const char *username);
static void session_handle_search(session_ctx_t *ctx, const char *arguments);
static void session_handle_chat_lookup(session_ctx_t *ctx, const char *arguments);
static void session_handle_image(session_ctx_t *ctx, const char *arguments);
static void session_handle_video(session_ctx_t *ctx, const char *arguments);
static void session_handle_audio(session_ctx_t *ctx, const char *arguments);
static void session_handle_files(session_ctx_t *ctx, const char *arguments);
static void session_handle_reaction(session_ctx_t *ctx, size_t reaction_index, const char *arguments);
static void session_handle_mail(session_ctx_t *ctx, const char *arguments);
static void session_handle_profile_picture(session_ctx_t *ctx, const char *arguments);
static void session_handle_today(session_ctx_t *ctx);
static void session_handle_date(session_ctx_t *ctx, const char *arguments);
static void session_handle_os(session_ctx_t *ctx, const char *arguments);
static void session_handle_getos(session_ctx_t *ctx, const char *arguments);
static void session_handle_pair(session_ctx_t *ctx);
static void session_handle_connected(session_ctx_t *ctx);
static bool session_parse_birthday(const char *input, char *normalized, size_t length);
static void session_handle_birthday(session_ctx_t *ctx, const char *arguments);
static void session_handle_soulmate(session_ctx_t *ctx);
static void session_handle_grant(session_ctx_t *ctx, const char *arguments);
static void session_handle_revoke(session_ctx_t *ctx, const char *arguments);
static void session_handle_delete_message(session_ctx_t *ctx, const char *arguments);
static void session_normalize_newlines(char *text);
static bool timezone_sanitize_identifier(const char *input, char *output, size_t length);
static bool timezone_resolve_identifier(const char *input, char *resolved, size_t length);
static const palette_descriptor_t *palette_find_descriptor(const char *name);
static bool palette_apply_to_session(session_ctx_t *ctx, const palette_descriptor_t *descriptor);
static void session_translation_flush_ready(session_ctx_t *ctx);
static bool session_translation_queue_caption(session_ctx_t *ctx, const char *message, size_t placeholder_lines);
static void session_translation_reserve_placeholders(session_ctx_t *ctx, size_t placeholder_lines);
static void session_translation_clear_queue(session_ctx_t *ctx);
static bool session_translation_worker_ensure(session_ctx_t *ctx);
static void session_translation_worker_shutdown(session_ctx_t *ctx);
static void *session_translation_worker(void *arg);
static void session_translation_queue_block(session_ctx_t *ctx, const char *text);
static bool session_translation_queue_private_message(session_ctx_t *ctx, session_ctx_t *target, const char *message);
static void session_translation_normalize_output(char *text);
static void host_handle_translation_quota_exhausted(host_t *host);
static void session_handle_translation_quota_exhausted(session_ctx_t *ctx, const char *error_detail);
static bool session_argument_is_disable(const char *token);
static void session_language_normalize(const char *input, char *normalized, size_t length);
static bool session_language_equals(const char *lhs, const char *rhs);
static bool session_fetch_weather_summary(const char *region, const char *city, char *summary, size_t summary_len);
static void session_handle_poll(session_ctx_t *ctx, const char *arguments);
static void session_handle_vote(session_ctx_t *ctx, size_t option_index);
static void session_handle_named_vote(session_ctx_t *ctx, size_t option_index, const char *label);
static void session_handle_elect_command(session_ctx_t *ctx, const char *arguments);
static void session_handle_vote_command(session_ctx_t *ctx, const char *arguments, bool allow_multiple);
static bool session_line_is_exit_command(const char *line);
static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line);
static const char *session_consume_token(const char *input, char *token, size_t length);
static bool session_user_data_available(session_ctx_t *ctx);
static bool session_user_data_load(session_ctx_t *ctx);
static bool session_user_data_commit(session_ctx_t *ctx);
static void session_user_data_touch(session_ctx_t *ctx);
static bool host_user_data_send_mail(host_t *host, const char *recipient, const char *sender, const char *message,
                                    char *error, size_t error_length);
static bool host_user_data_load_existing(host_t *host, const char *username, user_data_record_t *record,
                                        bool create_if_missing);
static void host_user_data_bootstrap(host_t *host);
static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count);
static size_t session_utf8_prev_char_len(const char *buffer, size_t length);
static int session_utf8_char_width(const char *bytes, size_t length);
static void host_history_record_system(host_t *host, const char *message);
static void session_send_history(session_ctx_t *ctx);
static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry);
static void session_deliver_outgoing_message(session_ctx_t *ctx, const char *message);
static void chat_room_broadcast_reaction_update(host_t *host, const chat_history_entry_t *entry);
static user_preference_t *host_find_preference_locked(host_t *host, const char *username);
static user_preference_t *host_ensure_preference_locked(host_t *host, const char *username);
static void host_store_user_theme(host_t *host, const session_ctx_t *ctx);
static size_t host_prepare_join_delay(host_t *host, struct timespec *wait_duration);
static bool host_register_join_attempt(host_t *host, const char *username, const char *ip);
static bool session_run_captcha(session_ctx_t *ctx);
static bool session_is_captcha_exempt(const session_ctx_t *ctx);
static void host_store_system_theme(host_t *host, const session_ctx_t *ctx);
static void host_store_user_os(host_t *host, const session_ctx_t *ctx);
static void host_store_birthday(host_t *host, const session_ctx_t *ctx, const char *birthday);
static void host_store_chat_spacing(host_t *host, const session_ctx_t *ctx);
static void host_store_translation_preferences(host_t *host, const session_ctx_t *ctx);
static bool host_ip_has_grant_locked(host_t *host, const char *ip);
static bool host_ip_has_grant(host_t *host, const char *ip);
static bool host_add_operator_grant_locked(host_t *host, const char *ip);
static bool host_remove_operator_grant_locked(host_t *host, const char *ip);
static void host_apply_grant_to_ip(host_t *host, const char *ip);
static void host_refresh_motd_locked(host_t *host);
static void host_refresh_motd(host_t *host);
static void host_build_birthday_notice_locked(host_t *host, char *line, size_t length);
static bool host_is_leap_year(int year);
static void host_revoke_grant_from_ip(host_t *host, const char *ip);
static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry);
static const char *chat_attachment_type_label(chat_attachment_type_t type);
static void host_state_resolve_path(host_t *host);
static void host_state_load(host_t *host);
static void host_state_save_locked(host_t *host);
static void host_eliza_state_resolve_path(host_t *host);
static void host_eliza_state_load(host_t *host);
static void host_eliza_state_save_locked(host_t *host);
static void host_eliza_memory_resolve_path(host_t *host);
static void host_eliza_memory_load(host_t *host);
static void host_eliza_memory_save_locked(host_t *host);
static void host_eliza_memory_store(host_t *host, const char *prompt, const char *reply);
static size_t host_eliza_memory_collect_context(host_t *host, const char *prompt, char *context,
                                                size_t context_length);
static void host_eliza_history_normalize_line(char *text);
static size_t host_eliza_history_collect_context(host_t *host, char *context, size_t context_length);
static void host_eliza_prepare_preview(const char *source, char *dest, size_t dest_length);
static size_t host_eliza_bbs_collect_context(host_t *host, char *context, size_t context_length);
static size_t host_eliza_memory_collect_tokens(const char *prompt, char tokens[][32], size_t max_tokens);
static void host_bbs_resolve_path(host_t *host);
static void host_bbs_state_load(host_t *host);
static void host_bbs_state_save_locked(host_t *host);
static void host_bbs_start_watchdog(host_t *host);
static void *host_bbs_watchdog_thread(void *arg);
static void host_bbs_watchdog_scan(host_t *host);
static void host_security_configure(host_t *host);
static bool host_ensure_private_data_path(host_t *host, const char *path, bool create_directories);
static void host_security_compact_whitespace(char *text);
static bool host_security_execute_clamav_backend(host_t *host, char *notice, size_t notice_length);
static void *host_security_clamav_backend(void *arg);
static void host_security_start_clamav_backend(host_t *host);
static void host_security_disable_filter(host_t *host, const char *reason);
static void host_security_disable_clamav(host_t *host, const char *reason);
static host_security_scan_result_t host_security_scan_payload(host_t *host, const char *category, const char *payload,
                                                              size_t length, char *diagnostic, size_t diagnostic_length);
static bool host_eliza_enable(host_t *host);
static bool host_eliza_disable(host_t *host);
static void host_eliza_announce_join(host_t *host);
static void host_eliza_announce_depart(host_t *host);
static void host_eliza_say(host_t *host, const char *message);
static void host_eliza_handle_private_message(session_ctx_t *ctx, const char *message);
static void host_eliza_prepare_private_reply(const char *message, char *reply, size_t reply_length);
static bool host_eliza_content_is_severe(const char *text);
static bool host_eliza_intervene(session_ctx_t *ctx, const char *content, const char *reason, bool from_filter);
static bool session_security_check_text(session_ctx_t *ctx, const char *category, const char *content, size_t length);
static void host_vote_resolve_path(host_t *host);
static void host_vote_state_load(host_t *host);
static void host_vote_state_save_locked(host_t *host);
static bool host_try_load_motd_from_path(host_t *host, const char *path);
static bool username_contains(const char *username, const char *needle);
static void host_apply_palette_descriptor(host_t *host, const palette_descriptor_t *descriptor);
static bool host_lookup_user_os(host_t *host, const char *username, char *buffer, size_t length);
static void session_send_poll_summary(session_ctx_t *ctx);
static void session_send_poll_summary_generic(session_ctx_t *ctx, const poll_state_t *poll, const char *label);
static void session_list_named_polls(session_ctx_t *ctx);
static void session_handle_bbs(session_ctx_t *ctx, const char *arguments);
static void poll_state_reset(poll_state_t *poll);
static void named_poll_reset(named_poll_state_t *poll);
static named_poll_state_t *host_find_named_poll_locked(host_t *host, const char *label);
static named_poll_state_t *host_ensure_named_poll_locked(host_t *host, const char *label);
static void host_recount_named_polls_locked(host_t *host);
static bool poll_label_is_valid(const char *label);
static void session_bbs_show_dashboard(session_ctx_t *ctx);
static void session_bbs_list(session_ctx_t *ctx);
static void session_bbs_read(session_ctx_t *ctx, uint64_t id);
static void session_bbs_begin_post(session_ctx_t *ctx, const char *arguments);
static void session_bbs_capture_body_text(session_ctx_t *ctx, const char *text);
static void session_bbs_capture_body_line(session_ctx_t *ctx, const char *line);
static bool session_bbs_capture_continue(const session_ctx_t *ctx);
static void session_bbs_add_comment(session_ctx_t *ctx, const char *arguments);
static void session_bbs_regen_post(session_ctx_t *ctx, uint64_t id);
static void session_bbs_delete(session_ctx_t *ctx, uint64_t id);
static void session_bbs_reset_pending_post(session_ctx_t *ctx);
static bbs_post_t *host_find_bbs_post_locked(host_t *host, uint64_t id);
static bbs_post_t *host_allocate_bbs_post_locked(host_t *host);
static void host_clear_bbs_post_locked(host_t *host, bbs_post_t *post);
static void session_bbs_queue_translation(session_ctx_t *ctx, const bbs_post_t *post);
static void session_bbs_render_post(session_ctx_t *ctx, const bbs_post_t *post, const char *notice,
                                    bool reset_scroll, bool scroll_to_bottom);
static bool host_user_data_load_existing(host_t *host, const char *username, user_data_record_t *record,
                                        bool create_if_missing);
static void host_user_data_build_match_key(const char *username, char *key, size_t length);
static bool host_user_data_find_profile_picture(host_t *host, const char *alias, user_data_record_t *record);
static bool session_bbs_scroll(session_ctx_t *ctx, int direction, size_t step);
static bool session_bbs_refresh_view(session_ctx_t *ctx);
static void session_handle_rss(session_ctx_t *ctx, const char *arguments);
static void session_rss_list(session_ctx_t *ctx);
static void session_rss_read(session_ctx_t *ctx, const char *tag);
static void session_rss_begin(session_ctx_t *ctx, const char *tag, const rss_session_item_t *items, size_t count);
static void session_rss_show_current(session_ctx_t *ctx);
static bool session_rss_move(session_ctx_t *ctx, int delta);
static void session_rss_exit(session_ctx_t *ctx, const char *reason);
static void session_rss_clear(session_ctx_t *ctx);
static bool session_parse_command(const char *line, const char *command, const char **arguments);
static void rss_strip_html(char *text);
static void rss_decode_entities(char *text);
static void rss_trim_whitespace(char *text);
static bool rss_tag_is_valid(const char *tag);
static rss_feed_t *host_find_rss_feed_locked(host_t *host, const char *tag);
static void host_clear_rss_feed(rss_feed_t *feed);
static void host_rss_recount_locked(host_t *host);
static bool host_rss_add_feed(host_t *host, const char *url, const char *tag, char *error, size_t error_length);
static bool host_rss_remove_feed(host_t *host, const char *tag, char *error, size_t error_length);
static void host_rss_resolve_path(host_t *host);
static void host_rss_state_load(host_t *host);
static void host_rss_state_save_locked(host_t *host);
static size_t host_rss_write_callback(void *contents, size_t size, size_t nmemb, void *userp);
static bool host_rss_download(const char *url, char **payload, size_t *length);
static bool host_rss_extract_tag(const char *block, const char *tag, char *out, size_t out_len);
static bool host_rss_extract_atom_link(const char *block, char *out, size_t out_len);
static size_t host_rss_parse_items(const char *payload, rss_session_item_t *items, size_t max_items);
static bool host_rss_fetch_items(const rss_feed_t *feed, rss_session_item_t *items, size_t max_items, size_t *out_count);
static void host_rss_start_backend(host_t *host);
static void *host_rss_backend(void *arg);
static bool host_rss_should_broadcast_breaking(const rss_session_item_t *item);
static bool host_asciiart_cooldown_active(host_t *host, const char *ip, const struct timespec *now,
                                          long *remaining_seconds);
static void host_asciiart_register_post(host_t *host, const char *ip, const struct timespec *when);
static bool session_asciiart_cooldown_active(session_ctx_t *ctx, struct timespec *now, long *remaining_seconds);
static void session_asciiart_reset(session_ctx_t *ctx);
static void session_asciiart_begin(session_ctx_t *ctx, session_asciiart_target_t target);
static void session_asciiart_capture_text(session_ctx_t *ctx, const char *text);
static void session_asciiart_capture_line(session_ctx_t *ctx, const char *line);
static void session_asciiart_commit(session_ctx_t *ctx);
static void session_asciiart_cancel(session_ctx_t *ctx, const char *reason);
typedef void (*session_text_line_consumer_t)(session_ctx_t *, const char *);
typedef bool (*session_text_continue_predicate_t)(const session_ctx_t *);
static void session_capture_multiline_text(session_ctx_t *ctx, const char *text, session_text_line_consumer_t consumer,
                                           session_text_continue_predicate_t should_continue);
static bool session_asciiart_capture_continue(const session_ctx_t *ctx);
static void session_handle_game(session_ctx_t *ctx, const char *arguments);
static void session_game_suspend(session_ctx_t *ctx, const char *reason);
static int session_channel_read_poll(session_ctx_t *ctx, char *buffer, size_t length, int timeout_ms);
static void session_game_seed_rng(session_ctx_t *ctx);
static uint32_t session_game_random(session_ctx_t *ctx);
static int session_game_random_range(session_ctx_t *ctx, int max);
static void session_game_start_tetris(session_ctx_t *ctx);
static void session_game_tetris_reset(tetris_game_state_t *state);
static void session_game_tetris_apply_round_settings(tetris_game_state_t *state);
static void session_game_tetris_handle_round_progress(session_ctx_t *ctx);
static void session_game_tetris_fill_bag(session_ctx_t *ctx);
static int session_game_tetris_take_piece(session_ctx_t *ctx);
static bool session_game_tetris_spawn_piece(session_ctx_t *ctx);
static bool session_game_tetris_cell_occupied(int piece, int rotation, int row, int column);
static bool session_game_tetris_position_valid(const tetris_game_state_t *state, int piece, int rotation, int row,
                                               int column);
static bool session_game_tetris_move(session_ctx_t *ctx, int drow, int dcol);
static bool session_game_tetris_soft_drop(session_ctx_t *ctx);
static bool session_game_tetris_rotate(session_ctx_t *ctx);
static bool session_game_tetris_apply_gravity(session_ctx_t *ctx, unsigned ticks);
static bool session_game_tetris_update_timer(session_ctx_t *ctx, bool accelerate);
static bool session_game_tetris_process_timeout(session_ctx_t *ctx);
static bool session_game_tetris_process_action(session_ctx_t *ctx, int action);
static bool session_game_tetris_process_raw_input(session_ctx_t *ctx, char ch);
static void session_game_tetris_lock_piece(session_ctx_t *ctx);
static void session_game_tetris_clear_lines(session_ctx_t *ctx, unsigned *cleared);
static void session_game_tetris_render(session_ctx_t *ctx);
static void session_game_tetris_handle_line(session_ctx_t *ctx, const char *line);
static void session_game_start_liargame(session_ctx_t *ctx);
static void session_game_liar_present_round(session_ctx_t *ctx);
static void session_game_liar_handle_line(session_ctx_t *ctx, const char *line);
static void session_game_start_alpha(session_ctx_t *ctx);
static void session_game_alpha_reset(session_ctx_t *ctx);
static void session_game_alpha_prepare_navigation(session_ctx_t *ctx);
static void session_game_alpha_reroll_navigation(session_ctx_t *ctx);
static void session_game_alpha_add_gravity_source(alpha_centauri_game_state_t *state, int x, int y, double mu,
                                                  int influence_radius, char symbol, const char *name);
static void session_game_alpha_configure_gravity(session_ctx_t *ctx);
static void session_game_alpha_apply_gravity(alpha_centauri_game_state_t *state);
static const char *const kAlphaStarCatalog[] = {
    "Midway Star",
    "Binary Torch",
    "Turnover Sun",
    "Arrival Flare",
    "Relay Star",
    "Shepherd Star",
};

static const char *const kAlphaPlanetCatalog[] = {
    "Departure World",
    "Drift Planet",
    "Relay Outpost",
    "Approach World",
    "Proxima b",
    "Immigrants' Harbor",
};

static const char *const kAlphaDebrisCatalog[] = {
    "Comet Trail",
    "Asteroid Swarm",
    "Ice Shard",
    "Dust Ribbon",
    "Sail Wreck",
};

#define ALPHA_STAR_CATALOG_COUNT (sizeof(kAlphaStarCatalog) / sizeof(kAlphaStarCatalog[0]))
#define ALPHA_PLANET_CATALOG_COUNT (sizeof(kAlphaPlanetCatalog) / sizeof(kAlphaPlanetCatalog[0]))
#define ALPHA_DEBRIS_CATALOG_COUNT (sizeof(kAlphaDebrisCatalog) / sizeof(kAlphaDebrisCatalog[0]))

static bool session_game_alpha_position_occupied(const alpha_centauri_game_state_t *state, int x, int y) {
  if (state == NULL) {
    return true;
  }
  if (state->nav_x == x && state->nav_y == y) {
    return true;
  }
  if (state->nav_target_x == x && state->nav_target_y == y) {
    return true;
  }
  for (unsigned idx = 0U; idx < state->gravity_source_count; ++idx) {
    const alpha_gravity_source_t *existing = &state->gravity_sources[idx];
    if (existing->x == x && existing->y == y) {
      return true;
    }
  }
  if (state->stage == 4U) {
    if (!state->eva_ready) {
      for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
        const alpha_waypoint_t *waypoint = &state->waypoints[idx];
        if (waypoint->x == x && waypoint->y == y) {
          return true;
        }
      }
    }
    if (state->final_waypoint.symbol != '\0' && state->final_waypoint.x == x && state->final_waypoint.y == y) {
      return true;
    }
  }
  return false;
}

static void session_game_alpha_place_random_source(session_ctx_t *ctx, alpha_centauri_game_state_t *state, int margin,
                                                   double mu, int radius, char symbol, const char *name) {
  if (ctx == NULL || state == NULL) {
    return;
  }

  int attempts = 0;
  int min_margin = margin >= 0 ? margin : 0;
  int usable_width = ALPHA_NAV_WIDTH - (min_margin * 2);
  int usable_height = ALPHA_NAV_HEIGHT - (min_margin * 2);
  if (usable_width <= 0) {
    usable_width = ALPHA_NAV_WIDTH;
    min_margin = 0;
  }
  if (usable_height <= 0) {
    usable_height = ALPHA_NAV_HEIGHT;
    min_margin = 0;
  }

  while (attempts < 128) {
    int x = min_margin + session_game_random_range(ctx, usable_width);
    int y = min_margin + session_game_random_range(ctx, usable_height);
    if (!session_game_alpha_position_occupied(state, x, y)) {
      session_game_alpha_add_gravity_source(state, x, y, mu, radius, symbol, name);
      return;
    }
    ++attempts;
  }

  int fallback_x = min_margin < ALPHA_NAV_WIDTH ? min_margin : 0;
  int fallback_y = min_margin < ALPHA_NAV_HEIGHT ? min_margin : 0;
  session_game_alpha_add_gravity_source(state, fallback_x, fallback_y, mu, radius, symbol, name);
}

static double session_game_alpha_random_double(session_ctx_t *ctx, double min_value, double max_value) {
  if (ctx == NULL) {
    return min_value;
  }
  if (max_value <= min_value) {
    return min_value;
  }
  double fraction = (double)session_game_random(ctx) / (double)UINT32_MAX;
  if (fraction < 0.0) {
    fraction = 0.0;
  } else if (fraction > 1.0) {
    fraction = 1.0;
  }
  return min_value + (max_value - min_value) * fraction;
}

static int session_game_alpha_random_with_margin(session_ctx_t *ctx, int extent, int margin) {
  if (extent <= 0) {
    return 0;
  }
  int safe_margin = margin;
  if (safe_margin < 0) {
    safe_margin = 0;
  }
  int usable = extent - (safe_margin * 2);
  if (usable <= 0) {
    usable = extent;
    safe_margin = 0;
  }
  return safe_margin + session_game_random_range(ctx, usable);
}
static void session_game_alpha_sync_from_save(session_ctx_t *ctx);
static void session_game_alpha_sync_to_save(session_ctx_t *ctx);
static void session_game_alpha_present_stage(session_ctx_t *ctx);
static void session_game_alpha_handle_line(session_ctx_t *ctx, const char *line);
static void session_game_alpha_log_completion(session_ctx_t *ctx);
static void session_game_alpha_render_navigation(session_ctx_t *ctx);
static void session_game_alpha_refresh_navigation(session_ctx_t *ctx);
static void session_game_alpha_plan_waypoints(session_ctx_t *ctx);
static void session_game_alpha_present_waypoints(session_ctx_t *ctx);
static void session_game_alpha_complete_waypoint(session_ctx_t *ctx);
static bool session_game_alpha_handle_arrow(session_ctx_t *ctx, int dx, int dy);
static bool session_game_alpha_attempt_completion(session_ctx_t *ctx);
static void session_game_alpha_execute_ignite(session_ctx_t *ctx);
static void session_game_alpha_execute_trim(session_ctx_t *ctx);
static void session_game_alpha_execute_flip(session_ctx_t *ctx);
static void session_game_alpha_execute_retro(session_ctx_t *ctx);
static void session_game_alpha_execute_eva(session_ctx_t *ctx);
static void session_game_alpha_manual_lock(session_ctx_t *ctx);
static void session_game_alpha_manual_save(session_ctx_t *ctx);
static void host_update_last_captcha_prompt(host_t *host, const captcha_prompt_t *prompt);

typedef struct liar_prompt {
  const char *statements[3];
  unsigned liar_index;
} liar_prompt_t;

static const liar_prompt_t LIAR_PROMPTS[] = {
    {{"I have contributed code to an open source project.", "I once replaced an entire server rack solo.",
      "I prefer mechanical keyboards with clicky switches."}, 1U},
    {{"I have memorized pi to 200 digits.", "I used to write BASIC games in middle school.",
      "I cannot solve a Rubik's Cube."}, 0U},
    {{"I drink my coffee without sugar.", "I debug using `printf` more than any other tool.",
      "I have never broken a build."}, 2U},
    {{"I run Linux on my primary laptop.", "I have camped overnight for a console launch.",
      "I have attended a demoparty."}, 1U},
    {{"I know how to solder surface-mount components.", "I have written an emulator in C.",
      "I have a pet snake named Segfault."}, 2U},
    {{"I play at least one rhythm game competitively.", "I once deployed to production from my phone.",
      "I have built a keyboard from scratch."}, 1U},
};

static const char *const TETROMINO_SHAPES[7][4] = {
    {
        "...."
        "####"
        "...."
        "....",
        "..#."
        "..#."
        "..#."
        "..#.",
        "...."
        "####"
        "...."
        "....",
        "..#."
        "..#."
        "..#."
        "..#.",
    },
    {
        "#..."
        "###."
        "...."
        "....",
        ".##."
        ".#.."
        ".#.."
        "....",
        "...."
        "###."
        "..#."
        "....",
        ".#.."
        ".#.."
        "##.."
        "....",
    },
    {
        "..#."
        "###."
        "...."
        "....",
        ".#.."
        ".#.."
        ".##."
        "....",
        "...."
        "###."
        "#..."
        "....",
        "##.."
        ".#.."
        ".#.."
        "....",
    },
    {
        ".##."
        ".##."
        "...."
        "....",
        ".##."
        ".##."
        "...."
        "....",
        ".##."
        ".##."
        "...."
        "....",
        ".##."
        ".##."
        "...."
        "....",
    },
    {
        ".##."
        "##.."
        "...."
        "....",
        ".#.."
        ".##."
        "..#."
        "....",
        ".##."
        "##.."
        "...."
        "....",
        ".#.."
        ".##."
        "..#."
        "....",
    },
    {
        ".#.."
        "###."
        "...."
        "....",
        ".#.."
        ".##."
        ".#.."
        "....",
        "...."
        "###."
        ".#.."
        "....",
        ".#.."
        "##.."
        ".#.."
        "....",
    },
    {
        "##.."
        ".##."
        "...."
        "....",
        "..#."
        ".##."
        ".#.."
        "....",
        "##.."
        ".##."
        "...."
        "....",
        "..#."
        ".##."
        ".#.."
        "....",
    },
};

static const char TETROMINO_DISPLAY_CHARS[7] = {'I', 'J', 'L', 'O', 'S', 'T', 'Z'};

static const uint32_t HOST_STATE_MAGIC = 0x53484354U; /* 'SHCT' */
static const uint32_t HOST_STATE_VERSION = 7U;
static const uint32_t ELIZA_STATE_MAGIC = 0x454c5354U; /* 'ELST' */
static const uint32_t ELIZA_STATE_VERSION = 1U;

#define HOST_STATE_SOUND_ALIAS_LEN 32U

typedef struct eliza_memory_header {
  uint32_t magic;
  uint32_t version;
  uint32_t entry_count;
  uint32_t reserved;
  uint64_t next_id;
} eliza_memory_header_t;

typedef struct eliza_memory_entry_serialized {
  uint64_t id;
  int64_t stored_at;
  char prompt[SSH_CHATTER_MESSAGE_LIMIT];
  char reply[SSH_CHATTER_MESSAGE_LIMIT];
} eliza_memory_entry_serialized_t;

typedef struct eliza_state_record {
  uint32_t magic;
  uint32_t version;
  uint8_t enabled;
  uint8_t reserved[7];
} eliza_state_record_t;

typedef struct host_state_header_v1 {
  uint32_t magic;
  uint32_t version;
  uint32_t history_count;
  uint32_t preference_count;
} host_state_header_v1_t;

typedef struct host_state_header {
  host_state_header_v1_t base;
  uint32_t legacy_sound_count;
  uint32_t grant_count;
  uint64_t next_message_id;
} host_state_header_t;

typedef struct host_state_history_entry_v1 {
  uint8_t is_user_message;
  uint8_t user_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char message[SSH_CHATTER_MESSAGE_LIMIT];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
} host_state_history_entry_v1_t;

typedef struct host_state_history_entry_v2 {
  host_state_history_entry_v1_t base;
  uint64_t message_id;
  uint8_t attachment_type;
  char attachment_target[SSH_CHATTER_ATTACHMENT_TARGET_LEN];
  char attachment_caption[SSH_CHATTER_ATTACHMENT_CAPTION_LEN];
  char sound_alias[HOST_STATE_SOUND_ALIAS_LEN];
  uint32_t reaction_counts[SSH_CHATTER_REACTION_KIND_COUNT];
} host_state_history_entry_v2_t;

typedef struct host_state_history_entry_v3 {
  host_state_history_entry_v1_t base;
  uint64_t message_id;
  uint8_t attachment_type;
  uint8_t reserved[7];
  char attachment_target[SSH_CHATTER_ATTACHMENT_TARGET_LEN];
  char attachment_caption[SSH_CHATTER_ATTACHMENT_CAPTION_LEN];
  uint32_t reaction_counts[SSH_CHATTER_REACTION_KIND_COUNT];
} host_state_history_entry_v3_t;

typedef struct host_state_preference_entry_v3 {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
} host_state_preference_entry_v3_t;

typedef struct host_state_preference_entry_v4 {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int32_t daily_year;
  int32_t daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int32_t last_poll_choice;
} host_state_preference_entry_v4_t;

typedef struct host_state_preference_entry_v5 {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int32_t daily_year;
  int32_t daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int32_t last_poll_choice;
  uint8_t has_birthday;
  uint8_t reserved[3];
  char birthday[16];
} host_state_preference_entry_v5_t;

typedef struct host_state_preference_entry_v6 {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int32_t daily_year;
  int32_t daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int32_t last_poll_choice;
  uint8_t has_birthday;
  uint8_t translation_caption_spacing;
  uint8_t translation_enabled;
  uint8_t output_translation_enabled;
  uint8_t input_translation_enabled;
  uint8_t reserved[3];
  char birthday[16];
  char output_translation_language[SSH_CHATTER_LANG_NAME_LEN];
  char input_translation_language[SSH_CHATTER_LANG_NAME_LEN];
} host_state_preference_entry_v6_t;

typedef struct host_state_preference_entry {
  uint8_t has_user_theme;
  uint8_t has_system_theme;
  uint8_t user_is_bold;
  uint8_t system_is_bold;
  char username[SSH_CHATTER_USERNAME_LEN];
  char user_color_name[SSH_CHATTER_COLOR_NAME_LEN];
  char user_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_fg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_bg_name[SSH_CHATTER_COLOR_NAME_LEN];
  char system_highlight_name[SSH_CHATTER_COLOR_NAME_LEN];
  char os_name[SSH_CHATTER_OS_NAME_LEN];
  int32_t daily_year;
  int32_t daily_yday;
  char daily_function[64];
  uint64_t last_poll_id;
  int32_t last_poll_choice;
  uint8_t has_birthday;
  uint8_t translation_caption_spacing;
  uint8_t translation_enabled;
  uint8_t output_translation_enabled;
  uint8_t input_translation_enabled;
  uint8_t translation_master_explicit;
  uint8_t reserved[2];
  char birthday[16];
  char output_translation_language[SSH_CHATTER_LANG_NAME_LEN];
  char input_translation_language[SSH_CHATTER_LANG_NAME_LEN];
} host_state_preference_entry_t;

static const uint32_t BAN_STATE_MAGIC = 0x5348424eU; /* 'SHBN' */
static const uint32_t BAN_STATE_VERSION = 1U;

typedef struct ban_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t entry_count;
} ban_state_header_t;

typedef struct ban_state_entry {
  char username[SSH_CHATTER_USERNAME_LEN];
  char ip[SSH_CHATTER_IP_LEN];
} ban_state_entry_t;

static const uint32_t REPLY_STATE_MAGIC = 0x53485250U; /* 'SHRP' */
static const uint32_t REPLY_STATE_VERSION = 1U;

typedef struct reply_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t entry_count;
  uint64_t next_reply_id;
} reply_state_header_t;

typedef struct reply_state_entry {
  uint64_t reply_id;
  uint64_t parent_message_id;
  uint64_t parent_reply_id;
  int64_t created_at;
  char username[SSH_CHATTER_USERNAME_LEN];
  char message[SSH_CHATTER_MESSAGE_LIMIT];
} reply_state_entry_t;

typedef struct host_state_grant_entry {
  char ip[SSH_CHATTER_IP_LEN];
} host_state_grant_entry_t;

static const uint32_t BBS_STATE_MAGIC = 0x42425331U; /* 'BBS1' */
static const uint32_t BBS_STATE_VERSION = 3U;

#define SSH_CHATTER_BBS_TITLE_LEN_V1 96U
#define SSH_CHATTER_BBS_BODY_LEN_V1 2048U
#define SSH_CHATTER_BBS_BODY_LEN_V2 10240U

typedef struct bbs_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t post_count;
  uint32_t reserved;
  uint64_t next_id;
} bbs_state_header_t;

typedef struct bbs_state_comment_entry {
  char author[SSH_CHATTER_USERNAME_LEN];
  char text[SSH_CHATTER_BBS_COMMENT_LEN];
  int64_t created_at;
} bbs_state_comment_entry_t;

typedef struct bbs_state_post_entry {
  uint64_t id;
  int64_t created_at;
  int64_t bumped_at;
  uint32_t tag_count;
  uint32_t comment_count;
  char author[SSH_CHATTER_USERNAME_LEN];
  char title[SSH_CHATTER_BBS_TITLE_LEN];
  char body[SSH_CHATTER_BBS_BODY_LEN];
  char tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
  bbs_state_comment_entry_t comments[SSH_CHATTER_BBS_MAX_COMMENTS];
} bbs_state_post_entry_t;

typedef struct bbs_state_post_entry_v1 {
  uint64_t id;
  int64_t created_at;
  int64_t bumped_at;
  uint32_t tag_count;
  uint32_t comment_count;
  char author[SSH_CHATTER_USERNAME_LEN];
  char title[SSH_CHATTER_BBS_TITLE_LEN_V1];
  char body[SSH_CHATTER_BBS_BODY_LEN_V1];
  char tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
  bbs_state_comment_entry_t comments[SSH_CHATTER_BBS_MAX_COMMENTS];
} bbs_state_post_entry_v1_t;

typedef struct bbs_state_post_entry_v2 {
  uint64_t id;
  int64_t created_at;
  int64_t bumped_at;
  uint32_t tag_count;
  uint32_t comment_count;
  char author[SSH_CHATTER_USERNAME_LEN];
  char title[SSH_CHATTER_BBS_TITLE_LEN];
  char body[SSH_CHATTER_BBS_BODY_LEN_V2];
  char tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
  bbs_state_comment_entry_t comments[SSH_CHATTER_BBS_MAX_COMMENTS];
} bbs_state_post_entry_v2_t;

static const uint32_t RSS_STATE_MAGIC = 0x52535331U; /* 'RSS1' */
static const uint32_t RSS_STATE_VERSION = 1U;

typedef struct rss_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t feed_count;
  uint32_t reserved;
} rss_state_header_t;

typedef struct rss_state_entry {
  char tag[SSH_CHATTER_RSS_TAG_LEN];
  char url[SSH_CHATTER_RSS_URL_LEN];
  char last_item_key[SSH_CHATTER_RSS_ITEM_KEY_LEN];
} rss_state_entry_t;

static const uint32_t VOTE_STATE_MAGIC = 0x564F5445U; /* 'VOTE' */
static const uint32_t VOTE_STATE_VERSION = 1U;

typedef struct vote_state_header {
  uint32_t magic;
  uint32_t version;
  uint32_t named_count;
  uint32_t reserved;
} vote_state_header_t;

typedef struct vote_state_poll_option_entry {
  char text[SSH_CHATTER_MESSAGE_LIMIT];
  uint32_t votes;
} vote_state_poll_option_entry_t;

typedef struct vote_state_poll_entry {
  uint8_t active;
  uint8_t allow_multiple;
  uint8_t reserved[6];
  uint64_t id;
  uint32_t option_count;
  uint32_t reserved2;
  char question[SSH_CHATTER_MESSAGE_LIMIT];
  vote_state_poll_option_entry_t options[5];
} vote_state_poll_entry_t;

typedef struct vote_state_named_voter_entry {
  char username[SSH_CHATTER_USERNAME_LEN];
  int32_t choice;
  uint32_t choices_mask;
} vote_state_named_voter_entry_t;

typedef struct vote_state_named_entry {
  vote_state_poll_entry_t poll;
  char label[SSH_CHATTER_POLL_LABEL_LEN];
  char owner[SSH_CHATTER_USERNAME_LEN];
  uint32_t voter_count;
  uint32_t reserved;
  vote_state_named_voter_entry_t voters[SSH_CHATTER_MAX_NAMED_VOTERS];
} vote_state_named_entry_t;


typedef struct reaction_descriptor {
  const char *command;
  const char *label;
  const char *icon;
} reaction_descriptor_t;

static const reaction_descriptor_t REACTION_DEFINITIONS[SSH_CHATTER_REACTION_KIND_COUNT] = {
    {"good", "good", "👍"},   {"sad", "sad", "😢"},   {"cool", "cool", "😎"},
    {"angry", "angry", "😠"}, {"checked", "checked", "✅"},
    {"love", "love", "❤️"},   {"wtf", "wtf", "🖕"},
};

typedef struct os_descriptor {
  const char *name;
  const char *display;
} os_descriptor_t;

static const os_descriptor_t OS_CATALOG[] = {
    {"windows", "Windows"},      {"macos", "macOS"},      {"linux", "Linux"},
    {"freebsd", "FreeBSD"},      {"ios", "iOS"},          {"android", "Android"},
    {"watchos", "watchOS"},      {"solaris", "Solaris"},  {"openbsd", "OpenBSD"},
    {"netbsd", "NetBSD"},        {"dragonflybsd", "DragonFlyBSD"},
    {"reactos", "ReactOS"},      {"tizen", "Tizen"}, {"bsd", "BSD"},
    {"msdos", "MS-DOS"}, {"drdos", "DR-DOS"}, {"kdos", "K-DOS"},
    {"templeos", "TempleOS"}, {"zealos", "ZealOS"},
    {"haiku", "Haiku"}, {"pcdos", "PC-DOS"}
};

static const os_descriptor_t *session_lookup_os_descriptor(const char *name);

static const char *DAILY_FUNCTIONS[] = {"sin",   "cos",   "tan",   "sqrt",  "log",   "exp",     "printf",
                                        "malloc", "free",  "memcpy", "strncpy", "qsort", "fopen",   "close",
                                        "select", "poll",  "fork",  "exec",  "pthread_create", "strtok"};

static bool chat_room_ensure_capacity(chat_room_t *room, size_t required) {
  if (room == NULL) {
    return false;
  }

  if (required <= room->member_capacity) {
    return true;
  }

  size_t new_capacity = room->member_capacity == 0U ? 8U : room->member_capacity;
  while (new_capacity < required) {
    if (new_capacity > SIZE_MAX / 2U) {
      new_capacity = required;
      break;
    }
    new_capacity *= 2U;
  }

  session_ctx_t **resized = realloc(room->members, new_capacity * sizeof(*resized));
  if (resized == NULL) {
    return false;
  }

  for (size_t idx = room->member_capacity; idx < new_capacity; ++idx) {
    resized[idx] = NULL;
  }

  room->members = resized;
  room->member_capacity = new_capacity;
  return true;
}

static void chat_room_init(chat_room_t *room) {
  if (room == NULL) {
    return;
  }
  pthread_mutex_init(&room->lock, NULL);
  room->members = NULL;
  room->member_count = 0U;
  room->member_capacity = 0U;
}

static void session_describe_peer(ssh_session session, char *buffer, size_t len) {
  if (buffer == NULL || len == 0U) {
    return;
  }

  buffer[0] = '\0';
  if (session == NULL) {
    return;
  }

  const int socket_fd = ssh_get_fd(session);
  if (socket_fd < 0) {
    return;
  }

  struct sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  if (getpeername(socket_fd, (struct sockaddr *)&addr, &addr_len) != 0) {
    return;
  }

  char host[NI_MAXHOST];
  if (getnameinfo((struct sockaddr *)&addr, addr_len, host, sizeof(host), NULL, 0,
                  NI_NUMERICHOST) != 0) {
    return;
  }

  snprintf(buffer, len, "%s", host);
}

static void host_format_sockaddr(const struct sockaddr *addr, socklen_t len, char *buffer, size_t size) {
  if (buffer == NULL || size == 0U) {
    return;
  }

  buffer[0] = '\0';
  if (addr == NULL) {
    return;
  }

  socklen_t host_len = (socklen_t)(size > (size_t)UINT_MAX ? UINT_MAX : size);
  if (host_len == 0) {
    return;
  }

  if (getnameinfo(addr, len, buffer, host_len, NULL, 0, NI_NUMERICHOST) != 0) {
    buffer[0] = '\0';
  }
}

typedef enum {
  HOSTKEY_SUPPORT_UNKNOWN = 0,
  HOSTKEY_SUPPORT_ACCEPTED,
  HOSTKEY_SUPPORT_REJECTED,
} hostkey_support_status_t;

typedef struct {
  hostkey_support_status_t status;
  char offered_algorithms[256];
} hostkey_probe_result_t;

static bool hostkey_list_contains(const unsigned char *data, size_t data_len, const char *needle,
                                 size_t needle_len) {
  if (data == NULL || needle == NULL || needle_len == 0U) {
    return false;
  }

  size_t position = 0U;
  while (position < data_len) {
    size_t token_end = position;
    while (token_end < data_len && data[token_end] != ',') {
      ++token_end;
    }

    const size_t token_length = token_end - position;
    if (token_length == needle_len && memcmp(data + position, needle, needle_len) == 0) {
      return true;
    }

    if (token_end >= data_len) {
      break;
    }

    position = token_end + 1U;
  }

  return false;
}

static hostkey_probe_result_t session_probe_client_hostkey_algorithms(
    ssh_session session, const char *const *required_algorithms, size_t required_algorithm_count) {
  hostkey_probe_result_t result;
  result.status = HOSTKEY_SUPPORT_UNKNOWN;
  result.offered_algorithms[0] = '\0';

  if (session == NULL || required_algorithms == NULL || required_algorithm_count == 0U) {
    return result;
  }

  for (size_t i = 0; i < required_algorithm_count; ++i) {
    if (required_algorithms[i] == NULL || required_algorithms[i][0] == '\0') {
      return result;
    }
  }

  const int socket_fd = ssh_get_fd(session);
  if (socket_fd < 0) {
    return result;
  }

  const size_t max_buffer_size = 65536U;
  size_t buffer_size = 16384U;
  unsigned char *buffer = malloc(buffer_size);
  if (buffer == NULL) {
    return result;
  }

  unsigned int attempts = 0U;
  const unsigned int max_attempts = 5U;

  while (attempts < max_attempts) {
    struct pollfd poll_fd;
    poll_fd.fd = socket_fd;
    poll_fd.events = POLLIN;
    poll_fd.revents = 0;

    int poll_result = poll(&poll_fd, 1, 1000);
    if (poll_result < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }

    if (poll_result == 0) {
      ++attempts;
      continue;
    }

    if ((poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      break;
    }

    ssize_t peeked = recv(socket_fd, buffer, buffer_size, MSG_PEEK | MSG_DONTWAIT);
    if (peeked < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN
#ifdef EWOULDBLOCK
          || errno == EWOULDBLOCK
#endif
      ) {
        ++attempts;
        continue;
      }
      break;
    }

    if (peeked == 0) {
      break;
    }

    size_t available = (size_t)peeked;
    unsigned char *newline = memchr(buffer, '\n', available);
    if (newline == NULL) {
      if (available == buffer_size && buffer_size < max_buffer_size) {
        size_t new_size = buffer_size * 2U;
        if (new_size > max_buffer_size) {
          new_size = max_buffer_size;
        }
        unsigned char *resized = realloc(buffer, new_size);
        if (resized != NULL) {
          buffer = resized;
          buffer_size = new_size;
          continue;
        }
      }
      ++attempts;
      continue;
    }

    size_t payload_offset = (size_t)(newline - buffer) + 1U;
    while (payload_offset < available && (buffer[payload_offset] == '\r' || buffer[payload_offset] == '\n')) {
      ++payload_offset;
    }

    if (available <= payload_offset || available - payload_offset < 5U) {
      ++attempts;
      continue;
    }

    const unsigned char *packet = buffer + payload_offset;
    uint32_t packet_length = ((uint32_t)packet[0] << 24) | ((uint32_t)packet[1] << 16) |
                             ((uint32_t)packet[2] << 8) | (uint32_t)packet[3];
    if (packet_length == 0U) {
      break;
    }

    size_t total_packet_size = 4U + (size_t)packet_length;
    if (total_packet_size > available - payload_offset) {
      if (payload_offset + total_packet_size > buffer_size && buffer_size < max_buffer_size) {
        size_t new_size = buffer_size;
        while (new_size < payload_offset + total_packet_size && new_size < max_buffer_size) {
          new_size *= 2U;
          if (new_size > max_buffer_size) {
            new_size = max_buffer_size;
          }
        }
        if (new_size > buffer_size) {
          unsigned char *resized = realloc(buffer, new_size);
          if (resized != NULL) {
            buffer = resized;
            buffer_size = new_size;
            continue;
          }
        }
      }
      ++attempts;
      continue;
    }

    unsigned int padding_length = packet[4];
    if ((size_t)padding_length + 1U > packet_length) {
      break;
    }

    size_t payload_length = (size_t)packet_length - (size_t)padding_length - 1U;
    if (payload_length < 17U) {
      break;
    }

    const unsigned char *payload = packet + 5;
    if (payload[0] != 20U) {
      break;
    }

    const unsigned char *cursor = payload + 17U;
    size_t remaining = payload_length - 17U;
    if (remaining < 4U) {
      break;
    }

    uint32_t kex_names_len = ((uint32_t)cursor[0] << 24) | ((uint32_t)cursor[1] << 16) |
                             ((uint32_t)cursor[2] << 8) | (uint32_t)cursor[3];
    cursor += 4U;
    if ((size_t)kex_names_len > remaining - 4U) {
      break;
    }

    cursor += (size_t)kex_names_len;
    remaining -= 4U + (size_t)kex_names_len;
    if (remaining < 4U) {
      break;
    }

    uint32_t hostkey_names_len = ((uint32_t)cursor[0] << 24) | ((uint32_t)cursor[1] << 16) |
                                 ((uint32_t)cursor[2] << 8) | (uint32_t)cursor[3];
    cursor += 4U;
    if ((size_t)hostkey_names_len > remaining - 4U) {
      break;
    }

    size_t hostkey_len = (size_t)hostkey_names_len;
    const unsigned char *hostkey_data = cursor;

    size_t copy_length = hostkey_len;
    if (copy_length >= sizeof(result.offered_algorithms)) {
      copy_length = sizeof(result.offered_algorithms) - 1U;
    }
    memcpy(result.offered_algorithms, hostkey_data, copy_length);
    result.offered_algorithms[copy_length] = '\0';

    if (hostkey_len == 0U) {
      result.status = HOSTKEY_SUPPORT_REJECTED;
    } else {
      bool supported = false;
      for (size_t i = 0; i < required_algorithm_count; ++i) {
        const char *algorithm = required_algorithms[i];
        const size_t required_length = strlen(algorithm);
        if (required_length == 0U) {
          continue;
        }

        if (hostkey_list_contains(hostkey_data, hostkey_len, algorithm, required_length)) {
          supported = true;
          break;
        }
      }

      if (supported) {
        result.status = HOSTKEY_SUPPORT_ACCEPTED;
      } else {
        result.status = HOSTKEY_SUPPORT_REJECTED;
      }
    }

    free(buffer);
    return result;
  }

  free(buffer);
  return result;
}

static bool session_is_private_ipv4(const unsigned char octets[4]) {
  if (octets == NULL) {
    return false;
  }

  if (octets[0] == 10U || octets[0] == 127U) {
    return true;
  }

  if (octets[0] == 172U && octets[1] >= 16U && octets[1] <= 31U) {
    return true;
  }

  if ((octets[0] == 192U && octets[1] == 168U) || (octets[0] == 169U && octets[1] == 254U)) {
    return true;
  }

  return false;
}

static bool session_is_lan_client(const char *ip) {
  if (ip == NULL || ip[0] == '\0') {
    return false;
  }

  struct in_addr addr4;
  if (inet_pton(AF_INET, ip, &addr4) == 1) {
    unsigned char octets[4];
    memcpy(octets, &addr4.s_addr, sizeof(octets));
    return session_is_private_ipv4(octets);
  }

  struct in6_addr addr6;
  if (inet_pton(AF_INET6, ip, &addr6) != 1) {
    return false;
  }

  if (IN6_IS_ADDR_LOOPBACK(&addr6) || IN6_IS_ADDR_LINKLOCAL(&addr6)) {
    return true;
  }

  if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
    return session_is_private_ipv4(&addr6.s6_addr[12]);
  }

  const unsigned char first_byte = addr6.s6_addr[0];
  if ((first_byte & 0xfeU) == 0xfcU) { // fc00::/7 unique local
    return true;
  }

  return false;
}

static void session_assign_lan_privileges(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (session_is_lan_client(ctx->client_ip)) {
    ctx->user.is_operator = true;
    ctx->auth.is_operator = true;
  }
}

static void session_apply_granted_privileges(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (host_ip_has_grant(ctx->owner, ctx->client_ip)) {
    ctx->user.is_operator = true;
    ctx->auth.is_operator = true;
  }
}

static void chat_room_add(chat_room_t *room, session_ctx_t *session) {
  if (room == NULL || session == NULL) {
    return;
  }

  pthread_mutex_lock(&room->lock);
  if (chat_room_ensure_capacity(room, room->member_count + 1U)) {
    room->members[room->member_count++] = session;
  } else {
    humanized_log_error("chat-room", "failed to grow member list", ENOMEM);
  }
  pthread_mutex_unlock(&room->lock);
}

static void chat_room_remove(chat_room_t *room, const session_ctx_t *session) {
  if (room == NULL || session == NULL) {
    return;
  }

  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    if (room->members[idx] == session) {
      for (size_t shift = idx; shift + 1U < room->member_count; ++shift) {
        room->members[shift] = room->members[shift + 1U];
      }
      room->members[room->member_count - 1U] = NULL;
      room->member_count--;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);
}

static void chat_room_broadcast(chat_room_t *room, const char *message, const session_ctx_t *from) {
  if (room == NULL || message == NULL) {
    return;
  }

  session_ctx_t **targets = NULL;
  size_t target_count = 0U;
  size_t expected_targets = 0U;

  chat_history_entry_t entry = {0};
  if (from != NULL) {
    chat_history_entry_prepare_user(&entry, from, message);
  }

  pthread_mutex_lock(&room->lock);
  expected_targets = room->member_count;
  if (expected_targets > 0U) {
    targets = calloc(expected_targets, sizeof(*targets));
    if (targets != NULL) {
      for (size_t idx = 0; idx < room->member_count; ++idx) {
        session_ctx_t *member = room->members[idx];
        if (member == NULL || member->channel == NULL) {
          continue;
        }
        if (from != NULL && member == from) {
          continue;
        }
        targets[target_count++] = member;
      }
    }
  }
  pthread_mutex_unlock(&room->lock);

  if (targets == NULL && expected_targets > 0U) {
    humanized_log_error("chat-room", "failed to allocate broadcast buffer", ENOMEM);
    return;
  }

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    if (from != NULL) {
      session_send_history_entry(member, &entry);
    } else {
      session_send_system_line(member, message);
    }

    if (member->history_scroll_position == 0U) {
      session_refresh_input_line(member);
    }
  }

  if (from != NULL) {
    printf("[broadcast:%s] %s\n", from->user.name, message);
  } else {
    printf("[broadcast] %s\n", message);
  }

  free(targets);
}

static void chat_room_broadcast_caption(chat_room_t *room, const char *message) {
  if (room == NULL || message == NULL) {
    return;
  }

  session_ctx_t **targets = NULL;
  size_t target_count = 0U;
  size_t expected_targets = 0U;

  pthread_mutex_lock(&room->lock);
  expected_targets = room->member_count;
  if (expected_targets > 0U) {
    targets = calloc(expected_targets, sizeof(*targets));
    if (targets != NULL) {
      for (size_t idx = 0; idx < room->member_count; ++idx) {
        session_ctx_t *member = room->members[idx];
        if (member == NULL || member->channel == NULL) {
          continue;
        }
        targets[target_count++] = member;
      }
    }
  }
  pthread_mutex_unlock(&room->lock);

  if (targets == NULL && expected_targets > 0U) {
    humanized_log_error("chat-room", "failed to allocate broadcast buffer", ENOMEM);
    return;
  }

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    session_send_caption_line(member, message);
    if (member->history_scroll_position == 0U) {
      session_refresh_input_line(member);
    }
  }

  printf("[broadcast caption] %s\n", message);

  free(targets);
}

static void chat_room_broadcast_entry(chat_room_t *room, const chat_history_entry_t *entry, const session_ctx_t *from) {
  if (room == NULL || entry == NULL) {
    return;
  }

  session_ctx_t **targets = NULL;
  size_t target_count = 0U;
  size_t expected_targets = 0U;

  pthread_mutex_lock(&room->lock);
  expected_targets = room->member_count;
  if (expected_targets > 0U) {
    targets = calloc(expected_targets, sizeof(*targets));
    if (targets != NULL) {
      for (size_t idx = 0; idx < room->member_count; ++idx) {
        session_ctx_t *member = room->members[idx];
        if (member == NULL || member->channel == NULL) {
          continue;
        }
        if (from != NULL && member == from) {
          continue;
        }
        targets[target_count++] = member;
      }
    }
  }
  pthread_mutex_unlock(&room->lock);

  if (targets == NULL && expected_targets > 0U) {
    humanized_log_error("chat-room", "failed to allocate entry broadcast buffer", ENOMEM);
    return;
  }

  for (size_t idx = 0; idx < target_count; ++idx) {
    session_ctx_t *member = targets[idx];
    session_send_history_entry(member, entry);
    if (member->history_scroll_position == 0U) {
      session_refresh_input_line(member);
    }
  }

  if (entry->is_user_message) {
    const char *message_text = entry->message;
    char fallback[SSH_CHATTER_MESSAGE_LIMIT + 64];
    if ((message_text == NULL || message_text[0] == '\0') && entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(fallback, sizeof(fallback), "shared a %s", label);
      message_text = fallback;
    } else if (message_text == NULL) {
      message_text = "";
    }

    printf("[broadcast:%s#%" PRIu64 "] %s\n", entry->username, entry->message_id, message_text);
    if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      printf("           %s: %s\n", label, entry->attachment_target);
    }
  }

  free(targets);
}

static void chat_room_broadcast_reaction_update(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  char summary[SSH_CHATTER_MESSAGE_LIMIT];
  if (!chat_history_entry_build_reaction_summary(entry, summary, sizeof(summary))) {
    return;
  }

  char line[SSH_CHATTER_MESSAGE_LIMIT + 64];
  if (entry->message_id > 0U) {
    snprintf(line, sizeof(line), "    ↳ [#%" PRIu64 "] reactions: %s", entry->message_id, summary);
  } else {
    snprintf(line, sizeof(line), "    ↳ reactions: %s", summary);
  }

  chat_room_broadcast_caption(&host->room, line);
}

static void host_broadcast_reply(host_t *host, const chat_reply_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  const char *target_prefix = (entry->parent_reply_id == 0U) ? "#" : "r#";
  uint64_t target_id = (entry->parent_reply_id == 0U) ? entry->parent_message_id : entry->parent_reply_id;

  char line[SSH_CHATTER_MESSAGE_LIMIT + 160];
  snprintf(line, sizeof(line), "↳ [r#%" PRIu64 " → %s%" PRIu64 "] %s: %s", entry->reply_id, target_prefix, target_id,
           entry->username, entry->message);

  chat_room_broadcast(&host->room, line, NULL);
}

static bool host_history_reserve_locked(host_t *host, size_t min_capacity) {
  if (host == NULL) {
    return false;
  }

  if (min_capacity <= host->history_capacity) {
    return true;
  }

  if (min_capacity > SIZE_MAX / sizeof(chat_history_entry_t)) {
    humanized_log_error("host-history", "history buffer too large to allocate", ENOMEM);
    return false;
  }

  size_t new_capacity = host->history_capacity > 0U ? host->history_capacity : 64U;
  if (new_capacity == 0U) {
    new_capacity = 64U;
  }

  while (new_capacity < min_capacity) {
    if (new_capacity > SIZE_MAX / 2U) {
      new_capacity = min_capacity;
      break;
    }
    size_t doubled = new_capacity * 2U;
    if (doubled < new_capacity || doubled > SIZE_MAX / sizeof(chat_history_entry_t)) {
      new_capacity = min_capacity;
      break;
    }
    new_capacity = doubled;
  }

  size_t bytes = new_capacity * sizeof(chat_history_entry_t);
  chat_history_entry_t *resized = realloc(host->history, bytes);
  if (resized == NULL) {
    humanized_log_error("host-history", "failed to grow chat history buffer", errno != 0 ? errno : ENOMEM);
    return false;
  }

  if (new_capacity > host->history_capacity) {
    size_t old_capacity = host->history_capacity;
    size_t added = new_capacity - old_capacity;
    memset(resized + old_capacity, 0, added * sizeof(chat_history_entry_t));
  }

  host->history = resized;
  host->history_capacity = new_capacity;
  return true;
}

static bool host_history_append_locked(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return false;
  }

  if (!host_history_reserve_locked(host, host->history_count + 1U)) {
    return false;
  }

  host->history[host->history_count++] = *entry;
  host_state_save_locked(host);
  return true;
}

static size_t host_history_total(host_t *host) {
  if (host == NULL) {
    return 0U;
  }

  size_t count = 0U;
  pthread_mutex_lock(&host->lock);
  count = host->history_count;
  pthread_mutex_unlock(&host->lock);
  return count;
}

static size_t host_history_copy_range(host_t *host, size_t start_index, chat_history_entry_t *buffer, size_t capacity) {
  if (host == NULL || buffer == NULL || capacity == 0U) {
    return 0U;
  }

  size_t copied = 0U;
  pthread_mutex_lock(&host->lock);
  size_t total = host->history_count;
  if (start_index >= total || host->history == NULL) {
    pthread_mutex_unlock(&host->lock);
    return 0U;
  }

  size_t available = total - start_index;
  if (available > capacity) {
    available = capacity;
  }

  memcpy(buffer, host->history + start_index, available * sizeof(chat_history_entry_t));
  copied = available;
  pthread_mutex_unlock(&host->lock);
  return copied;
}

static bool host_history_find_entry_by_id(host_t *host, uint64_t message_id, chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL || message_id == 0U) {
    return false;
  }

  bool found = false;

  pthread_mutex_lock(&host->lock);
  if (host->history != NULL) {
    for (size_t idx = 0U; idx < host->history_count; ++idx) {
      const chat_history_entry_t *candidate = &host->history[idx];
      if (candidate->message_id != message_id) {
        continue;
      }

      *entry = *candidate;
      found = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return found;
}

static size_t host_history_delete_range(host_t *host, uint64_t start_id, uint64_t end_id, uint64_t *first_removed,
                                        uint64_t *last_removed, size_t *replies_removed) {
  if (first_removed != NULL) {
    *first_removed = 0U;
  }
  if (last_removed != NULL) {
    *last_removed = 0U;
  }
  if (replies_removed != NULL) {
    *replies_removed = 0U;
  }

  if (host == NULL || start_id == 0U || end_id == 0U || start_id > end_id) {
    return 0U;
  }

  size_t removed = 0U;
  size_t reply_removed = 0U;
  uint64_t local_first = 0U;
  uint64_t local_last = 0U;

  pthread_mutex_lock(&host->lock);
  if (host->history != NULL && host->history_count > 0U) {
    size_t write_index = 0U;
    for (size_t idx = 0U; idx < host->history_count; ++idx) {
      chat_history_entry_t *entry = &host->history[idx];
      const bool drop = entry->is_user_message && entry->message_id >= start_id && entry->message_id <= end_id;
      if (drop) {
        if (local_first == 0U || entry->message_id < local_first) {
          local_first = entry->message_id;
        }
        if (entry->message_id > local_last) {
          local_last = entry->message_id;
        }
        ++removed;
        continue;
      }

      if (write_index != idx) {
        host->history[write_index] = *entry;
      }
      ++write_index;
    }

    if (removed > 0U) {
      for (size_t idx = write_index; idx < host->history_count; ++idx) {
        memset(&host->history[idx], 0, sizeof(host->history[idx]));
      }
      host->history_count = write_index;
      host_state_save_locked(host);
    }
  }

  if (removed > 0U && host->reply_count > 0U) {
    size_t write_index = 0U;
    for (size_t idx = 0U; idx < host->reply_count; ++idx) {
      chat_reply_entry_t *entry = &host->replies[idx];
      if (!entry->in_use) {
        continue;
      }

      const bool drop = entry->parent_message_id >= start_id && entry->parent_message_id <= end_id;
      if (drop) {
        ++reply_removed;
        continue;
      }

      if (write_index != idx) {
        host->replies[write_index] = *entry;
      }
      ++write_index;
    }

    if (reply_removed > 0U) {
      for (size_t idx = write_index; idx < host->reply_count; ++idx) {
        memset(&host->replies[idx], 0, sizeof(host->replies[idx]));
      }
      host->reply_count = write_index;

      uint64_t max_reply_id = 0U;
      for (size_t idx = 0U; idx < host->reply_count; ++idx) {
        const chat_reply_entry_t *entry = &host->replies[idx];
        if (!entry->in_use) {
          continue;
        }
        if (entry->reply_id > max_reply_id) {
          max_reply_id = entry->reply_id;
        }
      }

      if (max_reply_id == 0U) {
        host->next_reply_id = host->reply_count == 0U ? 1U : host->next_reply_id;
      } else if (host->next_reply_id <= max_reply_id) {
        host->next_reply_id = (max_reply_id == UINT64_MAX) ? UINT64_MAX : max_reply_id + 1U;
      }

      host_reply_state_save_locked(host);
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (removed > 0U) {
    if (first_removed != NULL) {
      *first_removed = local_first;
    }
    if (last_removed != NULL) {
      *last_removed = local_last;
    }
  }
  if (replies_removed != NULL) {
    *replies_removed = reply_removed;
  }

  return removed;
}

static bool host_replies_find_entry_by_id(host_t *host, uint64_t reply_id, chat_reply_entry_t *entry) {
  if (host == NULL || entry == NULL || reply_id == 0U) {
    return false;
  }

  bool found = false;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < host->reply_count; ++idx) {
    const chat_reply_entry_t *candidate = &host->replies[idx];
    if (!candidate->in_use) {
      continue;
    }
    if (candidate->reply_id != reply_id) {
      continue;
    }

    *entry = *candidate;
    found = true;
    break;
  }
  pthread_mutex_unlock(&host->lock);

  return found;
}

static void chat_history_entry_prepare_user(chat_history_entry_t *entry, const session_ctx_t *from, const char *message) {
  if (entry == NULL || from == NULL) {
    return;
  }

  memset(entry, 0, sizeof(*entry));
  entry->is_user_message = true;
  if (message != NULL) {
    snprintf(entry->message, sizeof(entry->message), "%s", message);
  }
  snprintf(entry->username, sizeof(entry->username), "%s", from->user.name);
  entry->user_color_code = from->user_color_code;
  entry->user_highlight_code = from->user_highlight_code;
  entry->user_is_bold = from->user_is_bold;
  snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", from->user_color_name);
  snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s", from->user_highlight_name);
  entry->attachment_type = CHAT_ATTACHMENT_NONE;
  entry->message_id = 0U;
}

static bool host_history_commit_entry(host_t *host, chat_history_entry_t *entry, chat_history_entry_t *stored_entry) {
  if (host == NULL || entry == NULL) {
    return false;
  }

  host_history_normalize_entry(host, entry);

  pthread_mutex_lock(&host->lock);
  if (entry->is_user_message) {
    if (host->next_message_id == 0U) {
      host->next_message_id = 1U;
    }
    entry->message_id = host->next_message_id++;
  } else {
    entry->message_id = 0U;
  }

  if (!host_history_append_locked(host, entry)) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }

  if (stored_entry != NULL) {
    *stored_entry = *entry;
  }

  pthread_mutex_unlock(&host->lock);
  return true;
}

static bool host_replies_commit_entry(host_t *host, chat_reply_entry_t *entry, chat_reply_entry_t *stored_entry) {
  if (host == NULL || entry == NULL) {
    return false;
  }

  bool committed = false;

  pthread_mutex_lock(&host->lock);
  if (host->reply_count >= SSH_CHATTER_MAX_REPLIES) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }

  uint64_t assigned_id = host->next_reply_id;
  if (assigned_id == 0U || assigned_id == UINT64_MAX) {
    assigned_id = (uint64_t)host->reply_count + 1U;
  }

  entry->reply_id = assigned_id;
  if (assigned_id < UINT64_MAX) {
    host->next_reply_id = assigned_id + 1U;
  } else {
    host->next_reply_id = assigned_id;
  }

  entry->in_use = true;

  size_t slot = host->reply_count;
  host->replies[slot] = *entry;
  host->reply_count = slot + 1U;

  host_reply_state_save_locked(host);

  if (stored_entry != NULL) {
    *stored_entry = host->replies[slot];
  }

  committed = true;

  pthread_mutex_unlock(&host->lock);
  return committed;
}

static void host_notify_external_clients(host_t *host, const chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }
  if (host->clients == NULL) {
    return;
  }
  client_manager_notify_history(host->clients, entry);
}

static bool host_history_record_user(host_t *host, const session_ctx_t *from, const char *message,
                                     chat_history_entry_t *stored_entry) {
  if (host == NULL || from == NULL || message == NULL || message[0] == '\0') {
    return false;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, from, message);
  return host_history_commit_entry(host, &entry, stored_entry);
}

static void host_history_record_system(host_t *host, const char *message) {
  if (host == NULL || message == NULL || message[0] == '\0') {
    return;
  }

  chat_history_entry_t entry = {0};
  entry.is_user_message = false;
  snprintf(entry.message, sizeof(entry.message), "%s", message);
  entry.user_color_name[0] = '\0';
  entry.user_highlight_name[0] = '\0';
  entry.attachment_type = CHAT_ATTACHMENT_NONE;
  entry.message_id = 0U;

  if (!host_history_commit_entry(host, &entry, NULL)) {
    return;
  }
  host_notify_external_clients(host, &entry);
}

static bool host_history_apply_reaction(host_t *host, uint64_t message_id, size_t reaction_index,
                                        chat_history_entry_t *updated_entry) {
  if (host == NULL || message_id == 0U || reaction_index >= SSH_CHATTER_REACTION_KIND_COUNT) {
    return false;
  }

  bool applied = false;

  pthread_mutex_lock(&host->lock);
  if (host->history == NULL) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }
  for (size_t idx = 0U; idx < host->history_count; ++idx) {
    chat_history_entry_t *entry = &host->history[idx];
    if (!entry->is_user_message) {
      continue;
    }
    if (entry->message_id != message_id) {
      continue;
    }

    if (entry->reaction_counts[reaction_index] < UINT32_MAX) {
      entry->reaction_counts[reaction_index] += 1U;
    }

    if (updated_entry != NULL) {
      *updated_entry = *entry;
    }

    host_state_save_locked(host);
    applied = true;
    break;
  }
  pthread_mutex_unlock(&host->lock);

  return applied;
}

static void session_apply_theme_defaults(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;

  ctx->user_color_code = host->user_theme.userColor;
  ctx->user_highlight_code = host->user_theme.highlight;
  ctx->user_is_bold = host->user_theme.isBold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", host->default_user_color_name);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", host->default_user_highlight_name);

  session_apply_system_theme_defaults(ctx);
}

static void session_apply_system_theme_defaults(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;

  ctx->system_fg_code = host->system_theme.foregroundColor;
  ctx->system_bg_code = host->system_theme.backgroundColor;
  ctx->system_highlight_code = host->system_theme.highlightColor;
  ctx->system_is_bold = host->system_theme.isBold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", host->default_system_fg_name);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", host->default_system_bg_name);
  snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", host->default_system_highlight_name);
  session_force_dark_mode_foreground(ctx);
}

static void session_force_dark_mode_foreground(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  const bool has_name = ctx->system_fg_name[0] != '\0';
  const bool name_is_default = has_name && strcasecmp(ctx->system_fg_name, "default") == 0;
  const bool missing_name = !has_name;
  const bool code_is_default = ctx->system_fg_code == NULL || strcmp(ctx->system_fg_code, ANSI_DEFAULT) == 0;

  if (!missing_name && !name_is_default && !code_is_default) {
    return;
  }

  ctx->system_fg_code = ANSI_WHITE;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", "white");
}

static user_preference_t *host_find_preference_locked(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use) {
      continue;
    }

    if (strncmp(pref->username, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      return pref;
    }
  }

  return NULL;
}

static user_preference_t *host_ensure_preference_locked(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return NULL;
  }

  user_preference_t *existing = host_find_preference_locked(host, username);
  if (existing != NULL) {
    return existing;
  }

  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    user_preference_t *pref = &host->preferences[idx];
    if (pref->in_use) {
      continue;
    }

    memset(pref, 0, sizeof(*pref));
    pref->in_use = true;
    pref->last_poll_choice = -1;
    snprintf(pref->username, sizeof(pref->username), "%s", username);
    if (host->preference_count < SSH_CHATTER_MAX_PREFERENCES) {
      ++host->preference_count;
    }
    return pref;
  }

  return NULL;
}

static void host_store_user_theme(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->has_user_theme = true;
    snprintf(pref->user_color_name, sizeof(pref->user_color_name), "%s", ctx->user_color_name);
    snprintf(pref->user_highlight_name, sizeof(pref->user_highlight_name), "%s", ctx->user_highlight_name);
    pref->user_is_bold = ctx->user_is_bold;
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_system_theme(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->has_system_theme = true;
    snprintf(pref->system_fg_name, sizeof(pref->system_fg_name), "%s", ctx->system_fg_name);
    snprintf(pref->system_bg_name, sizeof(pref->system_bg_name), "%s", ctx->system_bg_name);
    snprintf(pref->system_highlight_name, sizeof(pref->system_highlight_name), "%s", ctx->system_highlight_name);
    pref->system_is_bold = ctx->system_is_bold;
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_user_os(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    snprintf(pref->os_name, sizeof(pref->os_name), "%s", ctx->os_name);
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_birthday(host_t *host, const session_ctx_t *ctx, const char *birthday) {
  if (host == NULL || ctx == NULL || birthday == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->has_birthday = true;
    snprintf(pref->birthday, sizeof(pref->birthday), "%s", birthday);
  }
  host_state_save_locked(host);
  host_refresh_motd_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_chat_spacing(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    if (ctx->translation_caption_spacing > UINT8_MAX) {
      pref->translation_caption_spacing = UINT8_MAX;
    } else {
      pref->translation_caption_spacing = (uint8_t)ctx->translation_caption_spacing;
    }
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_store_translation_preferences(host_t *host, const session_ctx_t *ctx) {
  if (host == NULL || ctx == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    pref->translation_master_enabled = ctx->translation_enabled;
    pref->translation_master_explicit = true;
    pref->output_translation_enabled = ctx->output_translation_enabled;
    pref->input_translation_enabled = ctx->input_translation_enabled;
    snprintf(pref->output_translation_language, sizeof(pref->output_translation_language), "%s",
             ctx->output_translation_language);
    snprintf(pref->input_translation_language, sizeof(pref->input_translation_language), "%s",
             ctx->input_translation_language);
  }
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static bool host_ip_has_grant_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  for (size_t idx = 0U; idx < host->operator_grant_count; ++idx) {
    if (strncmp(host->operator_grants[idx].ip, ip, SSH_CHATTER_IP_LEN) == 0) {
      return true;
    }
  }

  return false;
}

static bool host_add_operator_grant_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  if (host_ip_has_grant_locked(host, ip)) {
    return true;
  }

  if (host->operator_grant_count >= SSH_CHATTER_MAX_GRANTS) {
    return false;
  }

  snprintf(host->operator_grants[host->operator_grant_count].ip,
           sizeof(host->operator_grants[host->operator_grant_count].ip), "%s", ip);
  ++host->operator_grant_count;
  return true;
}

static bool host_ip_has_grant(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  bool result = false;
  pthread_mutex_lock(&host->lock);
  result = host_ip_has_grant_locked(host, ip);
  pthread_mutex_unlock(&host->lock);
  return result;
}

static void host_apply_grant_to_ip(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return;
  }

  session_ctx_t **matches = NULL;
  size_t match_count = 0U;

  pthread_mutex_lock(&host->room.lock);
  if (host->room.member_count > 0U) {
    matches = calloc(host->room.member_count, sizeof(*matches));
    if (matches != NULL) {
      for (size_t idx = 0U; idx < host->room.member_count; ++idx) {
        session_ctx_t *member = host->room.members[idx];
        if (member == NULL) {
          continue;
        }
        if (strncmp(member->client_ip, ip, SSH_CHATTER_IP_LEN) != 0) {
          continue;
        }
        member->user.is_operator = true;
        member->auth.is_operator = true;
        matches[match_count++] = member;
      }
    }
  }
  pthread_mutex_unlock(&host->room.lock);

  if (matches == NULL) {
    return;
  }

  for (size_t idx = 0U; idx < match_count; ++idx) {
    session_ctx_t *member = matches[idx];
    session_send_system_line(member, "Operator privileges granted for your IP address.");
  }
  free(matches);
}

static bool host_remove_operator_grant_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  for (size_t idx = 0U; idx < host->operator_grant_count; ++idx) {
    if (strncmp(host->operator_grants[idx].ip, ip, SSH_CHATTER_IP_LEN) != 0) {
      continue;
    }

    for (size_t shift = idx; shift + 1U < host->operator_grant_count; ++shift) {
      host->operator_grants[shift] = host->operator_grants[shift + 1U];
    }
    memset(&host->operator_grants[host->operator_grant_count - 1U], 0,
           sizeof(host->operator_grants[host->operator_grant_count - 1U]));
    --host->operator_grant_count;
    return true;
  }

  return false;
}

static void host_revoke_grant_from_ip(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return;
  }

  session_ctx_t **matches = NULL;
  size_t match_count = 0U;

  pthread_mutex_lock(&host->room.lock);
  if (host->room.member_count > 0U) {
    session_ctx_t **allocated = calloc(host->room.member_count, sizeof(*allocated));
    if (allocated != NULL) {
      matches = allocated;
    }

    for (size_t idx = 0U; idx < host->room.member_count; ++idx) {
      session_ctx_t *member = host->room.members[idx];
      if (member == NULL) {
        continue;
      }
      if (strncmp(member->client_ip, ip, SSH_CHATTER_IP_LEN) != 0) {
        continue;
      }
      if (member->user.is_lan_operator) {
        continue;
      }

      member->user.is_operator = false;
      member->auth.is_operator = false;

      if (matches != NULL) {
        matches[match_count++] = member;
      }
    }
  }
  pthread_mutex_unlock(&host->room.lock);

  if (matches == NULL) {
    return;
  }

  for (size_t idx = 0U; idx < match_count; ++idx) {
    session_ctx_t *member = matches[idx];
    if (member == NULL) {
      continue;
    }
    session_send_system_line(member, "Operator privileges revoked for your IP address.");
  }

  free(matches);
}

static bool host_lookup_user_os(host_t *host, const char *username, char *buffer, size_t length) {
  if (host == NULL || username == NULL || buffer == NULL || length == 0U) {
    return false;
  }

  bool found = false;

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_find_preference_locked(host, username);
  if (pref != NULL && pref->os_name[0] != '\0') {
    snprintf(buffer, length, "%s", pref->os_name);
    found = true;
  }
  pthread_mutex_unlock(&host->lock);

  if (found) {
    return true;
  }

  session_ctx_t *session = chat_room_find_user(&host->room, username);
  if (session != NULL && session->os_name[0] != '\0') {
    snprintf(buffer, length, "%s", session->os_name);
    return true;
  }

  return false;
}

static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry) {
  if (host == NULL || entry == NULL) {
    return;
  }

  if (!entry->is_user_message) {
    entry->user_color_code = NULL;
    entry->user_highlight_code = NULL;
    entry->user_is_bold = false;
    entry->user_color_name[0] = '\0';
    entry->user_highlight_name[0] = '\0';
    return;
  }

  const char *color_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                             entry->user_color_name);
  if (color_code == NULL) {
    color_code = host->user_theme.userColor;
    snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", host->default_user_color_name);
  }

  const char *highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                entry->user_highlight_name);
  if (highlight_code == NULL) {
    highlight_code = host->user_theme.highlight;
    snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
             host->default_user_highlight_name);
  }

  entry->user_color_code = color_code;
  entry->user_highlight_code = highlight_code;
}

static void host_security_configure(host_t *host) {
  if (host == NULL) {
    return;
  }

  atomic_store(&host->security_filter_enabled, false);
  atomic_store(&host->security_filter_failure_logged, false);
  atomic_store(&host->security_ai_enabled, false);
  atomic_store(&host->security_clamav_enabled, false);
  atomic_store(&host->security_clamav_failure_logged, false);
  host->security_clamav_command[0] = '\0';

  const char *toggle = getenv("CHATTER_SECURITY_FILTER");
  if (toggle != NULL && toggle[0] != '\0') {
    if (strcasecmp(toggle, "0") == 0 || strcasecmp(toggle, "false") == 0 || strcasecmp(toggle, "off") == 0) {
      return;
    }
  }

  bool pipeline_enabled = false;

  const char *clamav_toggle = getenv("CHATTER_CLAMAV");
  bool clamav_disabled = false;
  if (clamav_toggle != NULL && clamav_toggle[0] != '\0') {
    if (strcasecmp(clamav_toggle, "0") == 0 || strcasecmp(clamav_toggle, "false") == 0 ||
        strcasecmp(clamav_toggle, "off") == 0) {
      clamav_disabled = true;
    }
  }

  if (!clamav_disabled) {
    const char *command = getenv("CHATTER_CLAMAV_COMMAND");
    if (command == NULL || command[0] == '\0') {
      command = "clamscan --no-summary --stdout .";
    }

    size_t command_length = strlen(command);
    if (command_length < sizeof(host->security_clamav_command)) {
      snprintf(host->security_clamav_command, sizeof(host->security_clamav_command), "%s", command);
      atomic_store(&host->security_clamav_enabled, true);
      pipeline_enabled = true;
      printf("[security] ClamAV scanning enabled via command: %s\n", host->security_clamav_command);
    } else {
      printf("[security] unable to enable ClamAV scanning: command is too long\n");
    }
  }

  bool ai_requested = false;
  const char *ai_toggle = getenv("CHATTER_SECURITY_AI");
  if (ai_toggle != NULL && ai_toggle[0] != '\0') {
    if (!(strcasecmp(ai_toggle, "0") == 0 || strcasecmp(ai_toggle, "false") == 0 ||
          strcasecmp(ai_toggle, "off") == 0)) {
      ai_requested = true;
    }
  }

  if (ai_requested) {
    bool has_gemini = false;
    const char *gemini_key = getenv("GEMINI_API_KEY");
    if (gemini_key != NULL && gemini_key[0] != '\0') {
      has_gemini = true;
    }

    atomic_store(&host->security_ai_enabled, true);
    pipeline_enabled = true;

    const char *message = has_gemini ?
                             "[security] AI payload moderation enabled (Gemini primary, Ollama fallback)" :
                             "[security] AI payload moderation enabled (Ollama fallback only)";

    printf("%s\n", message);
  } else {
    printf("[security] AI payload moderation disabled (set CHATTER_SECURITY_AI=on to enable)\n");
  }

  if (pipeline_enabled) {
    atomic_store(&host->security_filter_enabled, true);
  }
}

static void host_security_disable_filter(host_t *host, const char *reason) {
  if (host == NULL) {
    return;
  }

  if (!atomic_exchange(&host->security_ai_enabled, false)) {
    return;
  }

  if (reason == NULL || reason[0] == '\0') {
    reason = "moderation failure";
  }

  if (!atomic_exchange(&host->security_filter_failure_logged, true)) {
    printf("[security] disabling payload moderation: %s\n", reason);
  }

  if (!atomic_load(&host->security_clamav_enabled)) {
    atomic_store(&host->security_filter_enabled, false);
  }
}

static void host_security_disable_clamav(host_t *host, const char *reason) {
  if (host == NULL) {
    return;
  }

  if (!atomic_exchange(&host->security_clamav_enabled, false)) {
    return;
  }

  if (reason == NULL || reason[0] == '\0') {
    reason = "ClamAV failure";
  }

  if (!atomic_exchange(&host->security_clamav_failure_logged, true)) {
    printf("[security] disabling ClamAV scanning: %s\n", reason);
  }

  if (!atomic_load(&host->security_ai_enabled)) {
    atomic_store(&host->security_filter_enabled, false);
  }
}

static void host_security_compact_whitespace(char *text) {
  if (text == NULL) {
    return;
  }

  size_t read_index = 0U;
  size_t write_index = 0U;
  bool previous_was_space = false;

  while (text[read_index] != '\0') {
    unsigned char ch = (unsigned char)text[read_index++];
    if (ch == '\r' || ch == '\n' || ch == '\t') {
      ch = ' ';
    } else if (ch < 0x20U || ch == 0x7FU) {
      ch = ' ';
    }

    if (ch == ' ') {
      if (previous_was_space) {
        continue;
      }
      previous_was_space = true;
      text[write_index++] = ' ';
    } else {
      previous_was_space = false;
      text[write_index++] = (char)ch;
    }
  }

  if (write_index > 0U && text[write_index - 1U] == ' ') {
    --write_index;
  }

  text[write_index] = '\0';
}

static bool host_security_execute_clamav_backend(host_t *host, char *notice, size_t notice_length) {
  if (notice != NULL && notice_length > 0U) {
    notice[0] = '\0';
  }

  if (host == NULL || notice == NULL || notice_length == 0U) {
    return false;
  }

  if (!atomic_load(&host->security_clamav_enabled)) {
    return false;
  }

  if (host->security_clamav_command[0] == '\0') {
    return false;
  }

  struct timespec start = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &start);

  FILE *pipe = popen(host->security_clamav_command, "r");
  if (pipe == NULL) {
    int error_code = errno;
    char reason[128];
    if (error_code != 0) {
      snprintf(reason, sizeof(reason), "%s", strerror(error_code));
    } else {
      snprintf(reason, sizeof(reason), "%s", "unable to launch command");
    }
    snprintf(notice, notice_length, "* [security] Scheduled ClamAV scan failed to start (%s).", reason);
    host_security_disable_clamav(host, reason);
    return true;
  }

  char output[SSH_CHATTER_CLAMAV_OUTPUT_LIMIT];
  output[0] = '\0';
  size_t output_length = 0U;

  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    size_t chunk = strlen(buffer);
    if (chunk == 0U) {
      continue;
    }
    if (output_length + chunk >= sizeof(output)) {
      chunk = sizeof(output) - output_length - 1U;
    }
    if (chunk == 0U) {
      break;
    }
    memcpy(output + output_length, buffer, chunk);
    output_length += chunk;
    output[output_length] = '\0';
  }

  errno = 0;
  int status = pclose(pipe);
  struct timespec end = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &end);
  host->security_clamav_last_run = end;
  struct timespec elapsed = timespec_diff(&end, &start);
  double seconds = (double)elapsed.tv_sec + (double)elapsed.tv_nsec / 1000000000.0;

  host_security_compact_whitespace(output);

  if (status == -1) {
    int error_code = errno;
    if (error_code != 0) {
      snprintf(notice, notice_length,
               "* [security] Scheduled ClamAV scan failed (unable to retrieve status: %s).",
               strerror(error_code));
    } else {
      snprintf(notice, notice_length,
               "* [security] Scheduled ClamAV scan failed (unable to retrieve status).");
    }
    host_security_disable_clamav(host, "unable to retrieve scheduled ClamAV status");
    return true;
  }

  if (!WIFEXITED(status)) {
    snprintf(notice, notice_length, "* [security] Scheduled ClamAV scan terminated unexpectedly.");
    host_security_disable_clamav(host, "scheduled ClamAV scan terminated unexpectedly");
    return true;
  }

  int exit_code = WEXITSTATUS(status);
  if (exit_code == 0) {
    if (output[0] != '\0') {
      snprintf(notice, notice_length, "* [security] Scheduled ClamAV scan finished in %.1fs (clean): %s", seconds, output);
    } else {
      snprintf(notice, notice_length, "* [security] Scheduled ClamAV scan finished in %.1fs (clean).", seconds);
    }
    return true;
  }

  if (exit_code == 1) {
    if (output[0] != '\0') {
      snprintf(notice, notice_length,
               "* [security] Scheduled ClamAV scan finished in %.1fs (issues found): %s", seconds, output);
    } else {
      snprintf(notice, notice_length,
               "* [security] Scheduled ClamAV scan finished in %.1fs (issues found).", seconds);
    }
    return true;
  }

  if (output[0] != '\0') {
    snprintf(notice, notice_length,
             "* [security] Scheduled ClamAV scan failed in %.1fs (exit code %d): %s", seconds, exit_code, output);
  } else {
    snprintf(notice, notice_length,
             "* [security] Scheduled ClamAV scan failed in %.1fs (exit code %d).", seconds, exit_code);
  }
  host_security_disable_clamav(host, "scheduled ClamAV scan returned an error");
  return true;
}

static void *host_security_clamav_backend(void *arg) {
  host_t *host = (host_t *)arg;
  if (host == NULL) {
    return NULL;
  }

  atomic_store(&host->security_clamav_thread_running, true);
  printf("[security] scheduled ClamAV backend thread started (interval: %u seconds)\n",
         (unsigned int)SSH_CHATTER_CLAMAV_SCAN_INTERVAL_SECONDS);

  while (!atomic_load(&host->security_clamav_thread_stop)) {
    if (atomic_load(&host->security_clamav_enabled) && host->security_clamav_command[0] != '\0') {
      char notice[SSH_CHATTER_MESSAGE_LIMIT];
      if (host_security_execute_clamav_backend(host, notice, sizeof(notice)) && notice[0] != '\0') {
        printf("%s\n", notice);
        host_history_record_system(host, notice);
        chat_room_broadcast(&host->room, notice, NULL);
      }
    }

    unsigned int remaining = SSH_CHATTER_CLAMAV_SCAN_INTERVAL_SECONDS;
    while (remaining > 0U && !atomic_load(&host->security_clamav_thread_stop)) {
      unsigned int chunk =
          remaining > SSH_CHATTER_CLAMAV_SLEEP_CHUNK_SECONDS ? SSH_CHATTER_CLAMAV_SLEEP_CHUNK_SECONDS : remaining;
      struct timespec pause_duration = {
          .tv_sec = (time_t)chunk,
          .tv_nsec = 0,
      };
      nanosleep(&pause_duration, NULL);
      if (remaining < chunk) {
        remaining = 0U;
      } else {
        remaining -= chunk;
      }
    }
  }

  atomic_store(&host->security_clamav_thread_running, false);
  printf("[security] scheduled ClamAV backend thread stopped\n");
  return NULL;
}

static void host_security_start_clamav_backend(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->security_clamav_thread_initialized) {
    return;
  }

  if (!atomic_load(&host->security_clamav_enabled)) {
    return;
  }

  if (host->security_clamav_command[0] == '\0') {
    return;
  }

  atomic_store(&host->security_clamav_thread_stop, false);
  atomic_store(&host->security_clamav_thread_running, false);

  int error = pthread_create(&host->security_clamav_thread, NULL, host_security_clamav_backend, host);
  if (error != 0) {
    printf("[security] failed to start ClamAV backend thread: %s\n", strerror(error));
    return;
  }

  host->security_clamav_thread_initialized = true;
}

static bool host_ensure_private_data_path(host_t *host, const char *path, bool create_directories) {
  (void)host;
  if (path == NULL || path[0] == '\0') {
    return false;
  }

  char parent_buffer[PATH_MAX];
  snprintf(parent_buffer, sizeof(parent_buffer), "%s", path);
  char *parent_dir = dirname(parent_buffer);
  if (parent_dir == NULL || parent_dir[0] == '\0') {
    parent_dir = ".";
  }

  char parent_path[PATH_MAX];
  snprintf(parent_path, sizeof(parent_path), "%s", parent_dir);

  struct stat dir_stat;
  if (stat(parent_path, &dir_stat) != 0) {
    if (!(create_directories && errno == ENOENT)) {
      humanized_log_error("host", "failed to inspect data directory", errno != 0 ? errno : EIO);
      return false;
    }

    if (mkdir(parent_path, 0750) != 0 && errno != EEXIST) {
      humanized_log_error("host", "failed to create data directory", errno != 0 ? errno : EIO);
      return false;
    }

    if (stat(parent_path, &dir_stat) != 0) {
      humanized_log_error("host", "failed to inspect data directory", errno != 0 ? errno : EIO);
      return false;
    }
  }

  if (!S_ISDIR(dir_stat.st_mode)) {
    humanized_log_error("host", "data path parent is not a directory", ENOTDIR);
    return false;
  }

  mode_t insecure_bits = dir_stat.st_mode & (S_IWOTH | S_IWGRP);
  bool is_dot = strcmp(parent_path, ".") == 0;
  bool is_root = strcmp(parent_path, "/") == 0;
  if (insecure_bits != 0U) {
    if (!is_dot && !is_root) {
      mode_t tightened = dir_stat.st_mode & (mode_t)~(S_IWOTH | S_IWGRP);
      if (chmod(parent_path, tightened) != 0) {
        humanized_log_error("host", "failed to tighten data directory permissions", errno != 0 ? errno : EACCES);
        return false;
      }
    } else {
      humanized_log_error("host", "data directory permissions are too loose", EACCES);
      return false;
    }
  }

  struct stat file_stat;
  if (lstat(path, &file_stat) == 0) {
    if (!S_ISREG(file_stat.st_mode)) {
      humanized_log_error("host", "bbs state path does not reference a regular file", EINVAL);
      return false;
    }

    if ((file_stat.st_mode & (S_IWOTH | S_IWGRP)) != 0U) {
      if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        humanized_log_error("host", "failed to tighten bbs state permissions", errno != 0 ? errno : EACCES);
        return false;
      }
    }

    if (file_stat.st_uid != geteuid()) {
      humanized_log_error("host", "bbs state file ownership mismatch", EPERM);
      return false;
    }
  } else if (errno != ENOENT) {
    humanized_log_error("host", "failed to inspect bbs state path", errno != 0 ? errno : EIO);
    return false;
  }

  return true;
}

static host_security_scan_result_t host_security_scan_payload(host_t *host, const char *category, const char *payload,
                                                             size_t length, char *diagnostic,
                                                             size_t diagnostic_length) {
  if (diagnostic != NULL && diagnostic_length > 0U) {
    diagnostic[0] = '\0';
  }

  if (host == NULL || payload == NULL || length == 0U) {
    return HOST_SECURITY_SCAN_CLEAN;
  }

  if (!atomic_load(&host->security_filter_enabled)) {
    return HOST_SECURITY_SCAN_CLEAN;
  }

  bool clamav_active = atomic_load(&host->security_clamav_enabled);
  bool ai_active = atomic_load(&host->security_ai_enabled);

  if (!clamav_active && !ai_active) {
    atomic_store(&host->security_filter_enabled, false);
    return HOST_SECURITY_SCAN_CLEAN;
  }

  if (clamav_active) {
    // ClamAV scans now run asynchronously in the scheduled backend thread.
    clamav_active = false;
  }

  ai_active = atomic_load(&host->security_ai_enabled);
  if (!ai_active) {
    return HOST_SECURITY_SCAN_CLEAN;
  }

  if (!atomic_load(&host->eliza_enabled)) {
    return HOST_SECURITY_SCAN_CLEAN;
  }

  char snippet[1024];
  size_t copy_length = length;
  if (copy_length >= sizeof(snippet)) {
    copy_length = sizeof(snippet) - 1U;
  }

  memcpy(snippet, payload, copy_length);
  for (size_t idx = 0U; idx < copy_length; ++idx) {
    unsigned char ch = (unsigned char)snippet[idx];
    if (ch == '\0') {
      copy_length = idx;
      break;
    }
    if (ch < 0x20 && ch != '\n' && ch != '\r' && ch != '\t') {
      snippet[idx] = ' ';
    }
  }
  snippet[copy_length] = '\0';

  bool blocked = false;
  char reason[256];
  reason[0] = '\0';

  bool success = translator_moderate_text(category, snippet, &blocked, reason, sizeof(reason));
  if (!success) {
    const char *error = translator_last_error();
    if (diagnostic != NULL && diagnostic_length > 0U) {
      if (error != NULL && error[0] != '\0') {
        snprintf(diagnostic, diagnostic_length, "%s", error);
      } else {
        snprintf(diagnostic, diagnostic_length, "%s", "moderation unavailable");
      }
    }
    host_security_disable_filter(host, "moderation pipeline unavailable");
    return HOST_SECURITY_SCAN_ERROR;
  }

  if (!blocked) {
    if (diagnostic != NULL && diagnostic_length > 0U) {
      diagnostic[0] = '\0';
    }
    return HOST_SECURITY_SCAN_CLEAN;
  }

  if (diagnostic != NULL && diagnostic_length > 0U) {
    if (reason[0] != '\0') {
      snprintf(diagnostic, diagnostic_length, "%s", reason);
    } else {
      snprintf(diagnostic, diagnostic_length, "%s", "potential intrusion attempt");
    }
  }

  return HOST_SECURITY_SCAN_BLOCKED;
}

static bool host_eliza_enable(host_t *host) {
  if (host == NULL) {
    return false;
  }

  bool changed = false;
  bool announce = false;

  pthread_mutex_lock(&host->lock);
  if (!atomic_load(&host->eliza_enabled)) {
    atomic_store(&host->eliza_enabled, true);
    changed = true;
  }
  if (!atomic_load(&host->eliza_announced)) {
    atomic_store(&host->eliza_announced, true);
    announce = true;
  }
  if (changed) {
    host_eliza_state_save_locked(host);
  }
  pthread_mutex_unlock(&host->lock);

  if (announce) {
    host_eliza_announce_join(host);
  }

  return changed;
}

static bool host_eliza_disable(host_t *host) {
  if (host == NULL) {
    return false;
  }

  bool changed = false;
  bool announce_depart = false;

  pthread_mutex_lock(&host->lock);
  if (atomic_load(&host->eliza_enabled)) {
    changed = true;
  }
  atomic_store(&host->eliza_enabled, false);
  if (atomic_load(&host->eliza_announced)) {
    announce_depart = true;
  }
  atomic_store(&host->eliza_announced, false);
  if (changed) {
    host_eliza_state_save_locked(host);
  }
  pthread_mutex_unlock(&host->lock);

  if (announce_depart) {
    host_eliza_announce_depart(host);
  }

  return changed;
}

static void host_eliza_announce_join(host_t *host) {
  if (host == NULL) {
    return;
  }

  host_history_record_system(host, "* [eliza] has joined the chat");
  host_eliza_say(host, "Hey everyone, I'm eliza. Just another chatter keeping an eye on things.");
}

static void host_eliza_announce_depart(host_t *host) {
  if (host == NULL) {
    return;
  }

  host_eliza_say(host, "I'm heading out. Stay safe!");
  host_history_record_system(host, "* [eliza] has left the chat");
}

static void host_eliza_say(host_t *host, const char *message) {
  if (host == NULL || message == NULL || message[0] == '\0') {
    return;
  }

  if (!host_post_client_message(host, "eliza", message, NULL, NULL, false)) {
    printf("[eliza] failed to deliver message: %s\n", message);
  }
}

static void host_eliza_prepare_private_reply(const char *message, char *reply, size_t reply_length) {
  if (reply == NULL || reply_length == 0U) {
    return;
  }

  reply[0] = '\0';

  if (message == NULL) {
    snprintf(reply, reply_length, "I'm listening. Let me know what's going on.");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", message);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    snprintf(reply, reply_length, "I'm here if you want to talk about anything.");
    return;
  }

  if (translator_eliza_respond(working, reply, reply_length)) {
    trim_whitespace_inplace(reply);
    if (reply[0] != '\0') {
      return;
    }
  } else {
    const char *error = translator_last_error();
    if (error != NULL && error[0] != '\0') {
      printf("[eliza] AI backend error: %s\n", error);
    }
  }

  const bool says_hello = string_contains_case_insensitive(working, "hello") ||
                          string_contains_case_insensitive(working, "hi") ||
                          string_contains_case_insensitive(working, "안녕");
  const bool asks_help = string_contains_case_insensitive(working, "help") ||
                         string_contains_case_insensitive(working, "도와");
  const bool expresses_thanks = string_contains_case_insensitive(working, "thank") ||
                                string_contains_case_insensitive(working, "고마");
  const bool asks_question = strchr(working, '?') != NULL;

  if (says_hello) {
    snprintf(reply, reply_length, "Hi there! I'm here if you need anything.");
    return;
  }

  if (expresses_thanks) {
    snprintf(reply, reply_length, "You're welcome. I'm glad to help keep things calm.");
    return;
  }

  if (asks_help) {
    snprintf(reply, reply_length, "Tell me what's happening and I'll see how I can help.");
    return;
  }

  if (asks_question) {
    snprintf(reply, reply_length, "That's a thoughtful question. What do you think about it?");
    return;
  }

  snprintf(reply, reply_length, "I'm listening. Share anything that's on your mind.");
}

static void host_eliza_handle_private_message(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  if (!atomic_load(&host->eliza_enabled)) {
    session_send_system_line(ctx, "eliza isn't around right now.");
    return;
  }

  session_ctx_t palette = {0};
  palette.user_color_code = host->user_theme.userColor != NULL ? host->user_theme.userColor : "";
  palette.user_highlight_code = host->user_theme.highlight != NULL ? host->user_theme.highlight : "";
  palette.user_is_bold = host->user_theme.isBold;

  char reply[SSH_CHATTER_MESSAGE_LIMIT];
  host_eliza_prepare_private_reply(message, reply, sizeof(reply));

  session_send_private_message_line(ctx, &palette, "eliza -> you", reply);
  printf("[pm] eliza -> %s: %s\n", ctx->user.name, reply);

  clock_gettime(CLOCK_MONOTONIC, &host->eliza_last_action);
}

static bool host_eliza_content_is_severe(const char *text) {
  if (text == NULL || text[0] == '\0') {
    return false;
  }

  static const char *const kPhrases[] = {
    // 혐오 단어 찾는 것도 고역입니다. 겨우 여기까지만 어떻게 저떻게 찾았는데 솔직히 치면서 숨막힙니다..
    // It is really painful to find hate speech...It is really hard and sad to type these kinds of words
    "찢재명", "찢가카", "찢칠라", "화짱조", 
    "노묵훈", "노무쿤", "노알라", "노미현", "운지", "딱좋노", "야기분좋다", "이기야", // 진짜 왜 하필 노무현에만 이만큼 있나요?
    "문재앙", "문코리타", "문켓몬", "문크예거", "문슬람", // 이쪽도 만만찮긴 한데....
    "닭근혜", "닥그네", "닭그네",
    "고담대구", "광주 폭동", "광주폭동", // 지역드립은 얄짤없습니다. 
    "7시", "쌍도", "전라디언", "전라민국", 
    "통구이", "엔젤두환", "즌라도",
    "깜둥이", "좆슬람", "개슬람", "흑좆", "백좆", "똥남아", "깜씨", "쪽바리", "쪽발이", "짱꼴라", "좆선족", // 외국인 혐오와 일반화는 좋지 않아요. 물론 일부 밀입국자들이 문제라고는 하지만...
    "ㅈ선족", 
    // 어..이게...우리가 아는 그 ㅉㄲ는 아무래도.....이게 중국집에 대한 은어기도 해서 금지하고 싶어도 힘드네요
  };

  for (size_t idx = 0U; idx < sizeof(kPhrases) / sizeof(kPhrases[0]); ++idx) {
    if (string_contains_case_insensitive(text, kPhrases[idx])) {
      return true;
    }
  }

  if (string_contains_case_insensitive(text, "nigger")) {
    if (string_contains_case_insensitive(text, "ching chang") ||
        string_contains_case_insensitive(text, "goy") ||
        string_contains_case_insensitive(text, "nxxxxx") ||
        string_contains_case_insensitive(text, "nxxxxr") ||
        string_contains_case_insensitive(text, "nxxxer") ||
        string_contains_case_insensitive(text, "nixxer") ||
	string_contains_case_insensitive(text, "n_____") ||
	string_contains_case_insensitive(text, "n____r") ||
	string_contains_case_insensitive(text, "n___er") ||
	string_contains_case_insensitive(text, "ni__er") ||
	string_contains_case_insensitive(text, "nig_er") ||
	string_contains_case_insensitive(text, "n___a") ||
        string_contains_case_insensitive(text, "nig_er") ||
        string_contains_case_insensitive(text, "n___a") ||
        string_contains_case_insensitive(text, "ni__a")) {
      return true;
    }
  }

  if (string_contains_case_insensitive(text, "child")) {
    if (string_contains_case_insensitive(text, "exploitation") || string_contains_case_insensitive(text, "abuse") ||
        string_contains_case_insensitive(text, "porn")) {
      return true;
    }
  }

  if (string_contains_case_insensitive(text, "아동")) {
    if (string_contains_case_insensitive(text, "학대") || string_contains_case_insensitive(text, "착취") ||
        string_contains_case_insensitive(text, "포르노")) {
      return true;
    }
  }

  return false;
}

static bool host_eliza_intervene(session_ctx_t *ctx, const char *content, const char *reason, bool from_filter) {
  if (ctx == NULL || ctx->owner == NULL) {
    return false;
  }

  host_t *host = ctx->owner;
  if (!atomic_load(&host->eliza_enabled)) {
    return false;
  }

  if (ctx->should_exit) {
    return false;
  }

  bool severe = host_eliza_content_is_severe(content);
  if (!severe && reason != NULL) {
    severe = host_eliza_content_is_severe(reason);
  }

  if (!severe) {
    return false;
  }

  if (!atomic_load(&host->eliza_announced)) {
    bool announce = false;
    pthread_mutex_lock(&host->lock);
    if (!atomic_load(&host->eliza_announced)) {
      atomic_store(&host->eliza_announced, true);
      announce = true;
    }
    pthread_mutex_unlock(&host->lock);
    if (announce) {
      host_eliza_announce_join(host);
    }
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%s, that crosses a legal line. You're out of here.", ctx->user.name);
  host_eliza_say(host, message);

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [eliza] removed [%s] for severe content.", ctx->user.name);
  host_history_record_system(host, notice);

  clock_gettime(CLOCK_MONOTONIC, &host->eliza_last_action);
  if (from_filter && reason != NULL && reason[0] != '\0') {
    printf("[eliza] removing %s (%s) after filter flag: %s\n", ctx->user.name, ctx->client_ip, reason);
  } else {
    printf("[eliza] removing %s (%s) after manual keyword flag\n", ctx->user.name, ctx->client_ip);
  }

  session_force_disconnect(ctx, "You have been removed by eliza for severe content.");
  return true;
}

static bool session_security_check_text(session_ctx_t *ctx, const char *category, const char *content, size_t length) {
  if (ctx == NULL || ctx->owner == NULL || content == NULL || length == 0U) {
    return true;
  }

  char diagnostic[256];
  host_security_scan_result_t scan_result =
      host_security_scan_payload(ctx->owner, category, content, length, diagnostic, sizeof(diagnostic));

  if (scan_result == HOST_SECURITY_SCAN_CLEAN) {
    return true;
  }

  const char *label = category != NULL ? category : "submission";

  if (scan_result == HOST_SECURITY_SCAN_BLOCKED) {
    if (diagnostic[0] == '\0') {
      snprintf(diagnostic, sizeof(diagnostic), "%s", "suspected intrusion content");
    }
    printf("[security] blocked %s from %s: %s\n", label, ctx->user.name, diagnostic);

    char message[512];
    snprintf(message, sizeof(message), "Security filter rejected your %s: %s", label, diagnostic);
    session_send_system_line(ctx, message);

    size_t attempts = 0U;
    bool banned = host_register_suspicious_activity(ctx->owner, ctx->user.name, ctx->client_ip, &attempts);
    if (attempts > 0U) {
      printf("[security] suspicious payload counter for %s (%s): %zu/%u\n", ctx->user.name,
             ctx->client_ip, attempts, (unsigned int)SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD);
    }

    if (banned) {
      printf("[security] auto-banned %s (%s) for repeated suspicious payloads\n", ctx->user.name,
             ctx->client_ip);
      char notice[256];
      snprintf(notice, sizeof(notice),
               "Repeated suspicious activity detected. You have been banned.");
      session_force_disconnect(ctx, notice);
      return false;
    }

    if (attempts > 0U) {
      char warning[256];
      snprintf(warning, sizeof(warning), "Further suspicious activity will result in a ban (%zu/%u).",
               attempts, (unsigned int)SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD);
      session_send_system_line(ctx, warning);
    }
    (void)host_eliza_intervene(ctx, content, diagnostic, true);
    return false;
  }

  const char *error = translator_last_error();
  if (diagnostic[0] == '\0' && error != NULL && error[0] != '\0') {
    snprintf(diagnostic, sizeof(diagnostic), "%s", error);
  }

  if (diagnostic[0] != '\0') {
    printf("[security] unable to moderate %s from %s: %s\n", label, ctx->user.name, diagnostic);
  } else {
    printf("[security] unable to moderate %s from %s\n", label, ctx->user.name);
  }

  char message[512];
  if (diagnostic[0] != '\0') {
    snprintf(message, sizeof(message), "Security filter is unavailable (%s). Please try again later.", diagnostic);
  } else {
    snprintf(message, sizeof(message), "%s", "Security filter could not validate your submission. Please try again later.");
  }
  session_send_system_line(ctx, message);
  return false;
}

static void host_state_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *state_path = getenv("CHATTER_STATE_FILE");
  if (state_path == NULL || state_path[0] == '\0') {
    state_path = "chatter_state.dat";
  }

  int written = snprintf(host->state_file_path, sizeof(host->state_file_path), "%s", state_path);
  if (written < 0 || (size_t)written >= sizeof(host->state_file_path)) {
    humanized_log_error("host", "state file path is too long", ENAMETOOLONG);
    host->state_file_path[0] = '\0';
  }
}

static void host_vote_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *vote_path = getenv("CHATTER_VOTE_FILE");
  if (vote_path == NULL || vote_path[0] == '\0') {
    vote_path = "vote_state.dat";
  }

  int written = snprintf(host->vote_state_file_path, sizeof(host->vote_state_file_path), "%s", vote_path);
  if (written < 0 || (size_t)written >= sizeof(host->vote_state_file_path)) {
    humanized_log_error("host", "vote state file path is too long", ENAMETOOLONG);
    host->vote_state_file_path[0] = '\0';
  }
}

static void host_ban_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *ban_path = getenv("CHATTER_BAN_FILE");
  if (ban_path == NULL || ban_path[0] == '\0') {
    ban_path = "ban_state.dat";
  }

  int written = snprintf(host->ban_state_file_path, sizeof(host->ban_state_file_path), "%s", ban_path);
  if (written < 0 || (size_t)written >= sizeof(host->ban_state_file_path)) {
    humanized_log_error("host", "ban state file path is too long", ENAMETOOLONG);
    host->ban_state_file_path[0] = '\0';
  }
}

static void host_reply_state_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *reply_path = getenv("CHATTER_REPLY_FILE");
  if (reply_path == NULL || reply_path[0] == '\0') {
    reply_path = "reply_state.dat";
  }

  int written = snprintf(host->reply_state_file_path, sizeof(host->reply_state_file_path), "%s", reply_path);
  if (written < 0 || (size_t)written >= sizeof(host->reply_state_file_path)) {
    humanized_log_error("host", "reply state file path is too long", ENAMETOOLONG);
    host->reply_state_file_path[0] = '\0';
  }
}

static bool host_user_data_bootstrap_username_is_valid(const char *username) {
  if (username == NULL) {
    return false;
  }

  const char *cursor = username;
  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    return false;
  }

  char sanitized[SSH_CHATTER_USERNAME_LEN * 2U];
  if (!user_data_sanitize_username(username, sanitized, sizeof(sanitized))) {
    return false;
  }

  return sanitized[0] != '\0';
}

static void host_user_data_bootstrap_visit(host_t *host, const char *username) {
  if (host == NULL) {
    return;
  }

  if (!host_user_data_bootstrap_username_is_valid(username)) {
    return;
  }

  (void)host_user_data_load_existing(host, username, NULL, true);
}

static void host_user_data_bootstrap(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (!host->user_data_ready) {
    if (user_data_ensure_root(host->user_data_root)) {
      host->user_data_ready = true;
    } else {
      humanized_log_error("mailbox", "failed to prepare mailbox directory", errno != 0 ? errno : EIO);
      return;
    }
  }

  if (!host->user_data_lock_initialized) {
    if (pthread_mutex_init(&host->user_data_lock, NULL) != 0) {
      humanized_log_error("mailbox", "failed to initialise mailbox lock", errno != 0 ? errno : ENOMEM);
      host->user_data_lock_initialized = false;
      host->user_data_ready = false;
      return;
    }
    host->user_data_lock_initialized = true;
  }

  if (!host->user_data_ready) {
    return;
  }

  if (host->history != NULL) {
    for (size_t idx = 0U; idx < host->history_count; ++idx) {
      const chat_history_entry_t *entry = &host->history[idx];
      if (!entry->is_user_message) {
        continue;
      }
      host_user_data_bootstrap_visit(host, entry->username);
    }
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    const user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use || pref->username[0] == '\0') {
      continue;
    }
    host_user_data_bootstrap_visit(host, pref->username);
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_REPLIES; ++idx) {
    const chat_reply_entry_t *reply = &host->replies[idx];
    if (!reply->in_use) {
      continue;
    }
    host_user_data_bootstrap_visit(host, reply->username);
  }

  for (size_t idx = 0U; idx < host->ban_count && idx < SSH_CHATTER_MAX_BANS; ++idx) {
    host_user_data_bootstrap_visit(host, host->bans[idx].username);
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    const named_poll_state_t *poll = &host->named_polls[idx];
    if (poll->label[0] == '\0') {
      continue;
    }
    host_user_data_bootstrap_visit(host, poll->owner);
    size_t voter_count = poll->voter_count;
    if (voter_count > SSH_CHATTER_MAX_NAMED_VOTERS) {
      voter_count = SSH_CHATTER_MAX_NAMED_VOTERS;
    }
    for (size_t voter = 0U; voter < voter_count; ++voter) {
      host_user_data_bootstrap_visit(host, poll->voters[voter].username);
    }
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    const bbs_post_t *post = &host->bbs_posts[idx];
    if (!post->in_use) {
      continue;
    }
    host_user_data_bootstrap_visit(host, post->author);
    size_t comment_count = post->comment_count;
    if (comment_count > SSH_CHATTER_BBS_MAX_COMMENTS) {
      comment_count = SSH_CHATTER_BBS_MAX_COMMENTS;
    }
    for (size_t comment = 0U; comment < comment_count; ++comment) {
      host_user_data_bootstrap_visit(host, post->comments[comment].author);
    }
  }
}

static void host_eliza_state_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *state_path = getenv("CHATTER_ELIZA_STATE_FILE");
  char fallback_path[PATH_MAX];
  fallback_path[0] = '\0';
  if (state_path == NULL || state_path[0] == '\0') {
    state_path = "eliza_state.dat";
    if (host->eliza_memory_file_path[0] != '\0') {
      char memory_parent_buffer[PATH_MAX];
      snprintf(memory_parent_buffer, sizeof(memory_parent_buffer), "%s", host->eliza_memory_file_path);
      char *memory_parent = dirname(memory_parent_buffer);
      if (memory_parent != NULL && memory_parent[0] != '\0' && strcmp(memory_parent, ".") != 0) {
        int derived_written = snprintf(fallback_path, sizeof(fallback_path), "%s/%s", memory_parent, "eliza_state.dat");
        if (derived_written >= 0 && (size_t)derived_written < sizeof(fallback_path)) {
          state_path = fallback_path;
        }
      }
    }
  }

  int written = snprintf(host->eliza_state_file_path, sizeof(host->eliza_state_file_path), "%s", state_path);
  if (written < 0 || (size_t)written >= sizeof(host->eliza_state_file_path)) {
    humanized_log_error("host", "eliza state file path is too long", ENAMETOOLONG);
    host->eliza_state_file_path[0] = '\0';
  }
}

static void host_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open state file", errno);
    return;
  }

  size_t preference_count = 0U;
  for (size_t idx = 0; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    if (host->preferences[idx].in_use) {
      ++preference_count;
    }
  }

  host_state_header_t header = {0};
  header.base.magic = HOST_STATE_MAGIC;
  header.base.version = HOST_STATE_VERSION;
  header.base.history_count = (uint32_t)host->history_count;
  header.base.preference_count = (uint32_t)preference_count;
  header.legacy_sound_count = 0U;
  header.grant_count = (uint32_t)host->operator_grant_count;
  header.next_message_id = host->next_message_id;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  if (host->history_count > 0U && host->history == NULL) {
    success = false;
  }

  for (size_t idx = 0; success && idx < host->history_count; ++idx) {
    const chat_history_entry_t *entry = &host->history[idx];

    host_state_history_entry_v3_t serialized = {0};
    serialized.base.is_user_message = entry->is_user_message ? 1U : 0U;
    serialized.base.user_is_bold = entry->user_is_bold ? 1U : 0U;
    snprintf(serialized.base.username, sizeof(serialized.base.username), "%s", entry->username);
    snprintf(serialized.base.message, sizeof(serialized.base.message), "%s", entry->message);
    snprintf(serialized.base.user_color_name, sizeof(serialized.base.user_color_name), "%s", entry->user_color_name);
    snprintf(serialized.base.user_highlight_name, sizeof(serialized.base.user_highlight_name), "%s",
             entry->user_highlight_name);
    serialized.message_id = entry->message_id;
    serialized.attachment_type = (uint8_t)entry->attachment_type;
    memset(serialized.reserved, 0, sizeof(serialized.reserved));
    snprintf(serialized.attachment_target, sizeof(serialized.attachment_target), "%s", entry->attachment_target);
    snprintf(serialized.attachment_caption, sizeof(serialized.attachment_caption), "%s", entry->attachment_caption);
    memcpy(serialized.reaction_counts, entry->reaction_counts, sizeof(serialized.reaction_counts));

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
    }
  }

  for (size_t idx = 0; success && idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    const user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use) {
      continue;
    }

    host_state_preference_entry_t serialized = {0};
    serialized.has_user_theme = pref->has_user_theme ? 1U : 0U;
    serialized.has_system_theme = pref->has_system_theme ? 1U : 0U;
    serialized.user_is_bold = pref->user_is_bold ? 1U : 0U;
    serialized.system_is_bold = pref->system_is_bold ? 1U : 0U;
    snprintf(serialized.username, sizeof(serialized.username), "%s", pref->username);
    snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", pref->user_color_name);
    snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", pref->user_highlight_name);
    snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", pref->system_fg_name);
    snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", pref->system_bg_name);
    snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
             pref->system_highlight_name);
    snprintf(serialized.os_name, sizeof(serialized.os_name), "%s", pref->os_name);
    serialized.daily_year = pref->daily_year;
    serialized.daily_yday = pref->daily_yday;
    snprintf(serialized.daily_function, sizeof(serialized.daily_function), "%s", pref->daily_function);
    serialized.last_poll_id = pref->last_poll_id;
    serialized.last_poll_choice = pref->last_poll_choice;
    serialized.has_birthday = pref->has_birthday ? 1U : 0U;
    serialized.translation_caption_spacing = pref->translation_caption_spacing;
    serialized.translation_enabled = pref->translation_master_enabled ? 1U : 0U;
    serialized.output_translation_enabled = pref->output_translation_enabled ? 1U : 0U;
    serialized.input_translation_enabled = pref->input_translation_enabled ? 1U : 0U;
    serialized.translation_master_explicit = pref->translation_master_explicit ? 1U : 0U;
    memset(serialized.reserved, 0, sizeof(serialized.reserved));
    snprintf(serialized.birthday, sizeof(serialized.birthday), "%s", pref->birthday);
    snprintf(serialized.output_translation_language, sizeof(serialized.output_translation_language), "%s",
             pref->output_translation_language);
    snprintf(serialized.input_translation_language, sizeof(serialized.input_translation_language), "%s",
             pref->input_translation_language);

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      break;
    }
  }

  for (size_t idx = 0; success && idx < host->operator_grant_count; ++idx) {
    host_state_grant_entry_t grant = {0};
    snprintf(grant.ip, sizeof(grant.ip), "%s", host->operator_grants[idx].ip);
    if (fwrite(&grant, sizeof(grant), 1U, fp) != 1U) {
      success = false;
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
    }
  }

  if (fclose(fp) != 0) {
    success = false;
  }

  if (!success) {
    humanized_log_error("host", "failed to write state file", errno);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->state_file_path) != 0) {
    humanized_log_error("host", "failed to update state file", errno);
    unlink(temp_path);
  }
}

static void host_eliza_state_save_locked(host_t *host) {
  if (host == NULL || host->eliza_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->eliza_state_file_path, true)) {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->eliza_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "eliza state path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open eliza state file", errno != 0 ? errno : EIO);
    return;
  }

  eliza_state_record_t record = {0};
  record.magic = ELIZA_STATE_MAGIC;
  record.version = ELIZA_STATE_VERSION;
  record.enabled = atomic_load(&host->eliza_enabled) ? 1U : 0U;

  bool success = fwrite(&record, sizeof(record), 1U, fp) == 1U;
  int write_error = 0;
  if (!success && errno != 0) {
    write_error = errno;
  }

  if (success && fflush(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
    }
  }

  if (fclose(fp) != 0) {
    if (success && errno != 0) {
      write_error = errno;
    }
    success = false;
  }

  if (!success) {
    unlink(temp_path);
    humanized_log_error("host", "failed to write eliza state file", write_error != 0 ? write_error : EIO);
    return;
  }

  if (rename(temp_path, host->eliza_state_file_path) != 0) {
    int rename_error = errno != 0 ? errno : EIO;
    unlink(temp_path);
    humanized_log_error("host", "failed to update eliza state file", rename_error);
    return;
  }

  if (chmod(host->eliza_state_file_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to set eliza state permissions", errno != 0 ? errno : EACCES);
  }
}

static void host_eliza_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->eliza_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->eliza_state_file_path, false)) {
    return;
  }

  FILE *fp = fopen(host->eliza_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  eliza_state_record_t record = {0};
  if (fread(&record, sizeof(record), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  fclose(fp);

  if (record.magic != ELIZA_STATE_MAGIC || record.version == 0U || record.version > ELIZA_STATE_VERSION) {
    return;
  }

  if (record.enabled != 0U) {
    (void)host_eliza_enable(host);
  } else {
    pthread_mutex_lock(&host->lock);
    atomic_store(&host->eliza_enabled, false);
    atomic_store(&host->eliza_announced, false);
    pthread_mutex_unlock(&host->lock);
  }
}

static void host_ban_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->ban_state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->ban_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "ban state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open ban state file", errno);
    return;
  }

  ban_state_header_t header = {0};
  header.magic = BAN_STATE_MAGIC;
  header.version = BAN_STATE_VERSION;
  header.entry_count = (uint32_t)host->ban_count;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;
  int write_error = 0;
  if (!success && errno != 0) {
    write_error = errno;
  }

  for (size_t idx = 0U; success && idx < host->ban_count; ++idx) {
    ban_state_entry_t entry = {0};
    snprintf(entry.username, sizeof(entry.username), "%s", host->bans[idx].username);
    snprintf(entry.ip, sizeof(entry.ip), "%s", host->bans[idx].ip);
    if (fwrite(&entry, sizeof(entry), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
    }
  }

  if (fclose(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (!success) {
    humanized_log_error("host", "failed to write ban state file", write_error != 0 ? write_error : EIO);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->ban_state_file_path) != 0) {
    humanized_log_error("host", "failed to update ban state file", errno);
    unlink(temp_path);
  }
}

static void host_reply_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->reply_state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->reply_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "reply state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open reply state file", errno);
    return;
  }

  size_t stored_count = 0U;
  for (size_t idx = 0U; idx < host->reply_count; ++idx) {
    if (host->replies[idx].in_use) {
      ++stored_count;
    }
  }

  reply_state_header_t header = {0};
  header.magic = REPLY_STATE_MAGIC;
  header.version = REPLY_STATE_VERSION;
  header.entry_count = (uint32_t)stored_count;
  header.next_reply_id = host->next_reply_id;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;
  int write_error = 0;
  if (!success && errno != 0) {
    write_error = errno;
  }

  for (size_t idx = 0U; success && idx < host->reply_count; ++idx) {
    const chat_reply_entry_t *reply = &host->replies[idx];
    if (!reply->in_use) {
      continue;
    }

    reply_state_entry_t serialized = {0};
    serialized.reply_id = reply->reply_id;
    serialized.parent_message_id = reply->parent_message_id;
    serialized.parent_reply_id = reply->parent_reply_id;
    serialized.created_at = (int64_t)reply->created_at;
    snprintf(serialized.username, sizeof(serialized.username), "%s", reply->username);
    snprintf(serialized.message, sizeof(serialized.message), "%s", reply->message);

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
    }
  }

  if (fclose(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (!success) {
    humanized_log_error("host", "failed to write reply state file", write_error != 0 ? write_error : EIO);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->reply_state_file_path) != 0) {
    humanized_log_error("host", "failed to update reply state file", errno);
    unlink(temp_path);
  }
}

static void vote_state_export_poll_entry(const poll_state_t *source, vote_state_poll_entry_t *dest) {
  if (dest == NULL) {
    return;
  }

  memset(dest, 0, sizeof(*dest));
  if (source == NULL) {
    return;
  }

  dest->active = source->active ? 1U : 0U;
  dest->allow_multiple = source->allow_multiple ? 1U : 0U;
  dest->id = source->id;
  dest->option_count = (uint32_t)source->option_count;
  if (dest->option_count > 5U) {
    dest->option_count = 5U;
  }
  snprintf(dest->question, sizeof(dest->question), "%s", source->question);
  for (size_t idx = 0U; idx < 5U; ++idx) {
    snprintf(dest->options[idx].text, sizeof(dest->options[idx].text), "%s", source->options[idx].text);
    dest->options[idx].votes = source->options[idx].votes;
  }
}

static void vote_state_import_poll_entry(const vote_state_poll_entry_t *source, poll_state_t *dest) {
  if (dest == NULL) {
    return;
  }

  poll_state_reset(dest);
  if (source == NULL) {
    return;
  }

  dest->active = source->active != 0U;
  dest->allow_multiple = source->allow_multiple != 0U;
  dest->id = source->id;
  size_t option_count = source->option_count;
  if (option_count > 5U) {
    option_count = 5U;
  }
  dest->option_count = option_count;
  snprintf(dest->question, sizeof(dest->question), "%s", source->question);
  for (size_t idx = 0U; idx < option_count; ++idx) {
    snprintf(dest->options[idx].text, sizeof(dest->options[idx].text), "%s", source->options[idx].text);
    dest->options[idx].votes = source->options[idx].votes;
  }
  for (size_t idx = option_count; idx < 5U; ++idx) {
    dest->options[idx].text[0] = '\0';
    dest->options[idx].votes = 0U;
  }
}

static void host_vote_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->vote_state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->vote_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "vote state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open vote state file", errno);
    return;
  }

  uint32_t named_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] != '\0') {
      ++named_count;
    }
  }

  vote_state_header_t header = {0};
  header.magic = VOTE_STATE_MAGIC;
  header.version = VOTE_STATE_VERSION;
  header.named_count = named_count;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;
  int write_error = 0;
  if (!success && errno != 0) {
    write_error = errno;
  }

  vote_state_poll_entry_t main_entry = {0};
  vote_state_export_poll_entry(&host->poll, &main_entry);
  if (success) {
    success = fwrite(&main_entry, sizeof(main_entry), 1U, fp) == 1U;
    if (!success && errno != 0) {
      write_error = errno;
    }
  }

  for (size_t idx = 0U; success && idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    const named_poll_state_t *poll = &host->named_polls[idx];
    if (poll->label[0] == '\0') {
      continue;
    }

    vote_state_named_entry_t entry = {0};
    vote_state_export_poll_entry(&poll->poll, &entry.poll);
    snprintf(entry.label, sizeof(entry.label), "%s", poll->label);
    snprintf(entry.owner, sizeof(entry.owner), "%s", poll->owner);
    entry.voter_count = (uint32_t)poll->voter_count;
    if (entry.voter_count > SSH_CHATTER_MAX_NAMED_VOTERS) {
      entry.voter_count = SSH_CHATTER_MAX_NAMED_VOTERS;
    }
    for (size_t voter = 0U; voter < SSH_CHATTER_MAX_NAMED_VOTERS; ++voter) {
      snprintf(entry.voters[voter].username, sizeof(entry.voters[voter].username), "%s", poll->voters[voter].username);
      entry.voters[voter].choice = poll->voters[voter].choice;
      entry.voters[voter].choices_mask = poll->voters[voter].choices_mask;
    }

    if (fwrite(&entry, sizeof(entry), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
    }
  }

  if (fclose(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (!success) {
    humanized_log_error("host", "failed to write vote state file", write_error != 0 ? write_error : EIO);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->vote_state_file_path) != 0) {
    humanized_log_error("host", "failed to update vote state file", errno);
    unlink(temp_path);
  }
}

static void host_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->state_file_path[0] == '\0') {
    return;
  }

  FILE *fp = fopen(host->state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  host_state_header_v1_t base_header = {0};
  if (fread(&base_header, sizeof(base_header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (base_header.magic != HOST_STATE_MAGIC) {
    fclose(fp);
    return;
  }

  uint32_t version = base_header.version;
  if (version == 0U || version > HOST_STATE_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t history_count = base_header.history_count;
  uint32_t preference_count = base_header.preference_count;
  uint64_t next_message_id = 1U;

  uint32_t grant_count = 0U;
  if (version >= 2U) {
    uint32_t sound_count_raw = 0U;
    uint32_t grant_count_raw = 0U;
    uint64_t next_id_raw = 0U;
    if (fread(&sound_count_raw, sizeof(sound_count_raw), 1U, fp) != 1U ||
        fread(&grant_count_raw, sizeof(grant_count_raw), 1U, fp) != 1U ||
        fread(&next_id_raw, sizeof(next_id_raw), 1U, fp) != 1U) {
      fclose(fp);
      return;
    }
    next_message_id = next_id_raw;
    if (version >= 5U) {
      grant_count = grant_count_raw;
    }
  }

  if (preference_count > SSH_CHATTER_MAX_PREFERENCES) {
    preference_count = SSH_CHATTER_MAX_PREFERENCES;
  }

  pthread_mutex_lock(&host->lock);

  bool success = true;

  if (history_count > 0U) {
    success = host_history_reserve_locked(host, history_count);
  }
  host->history_count = 0U;

  for (uint32_t idx = 0; success && idx < history_count; ++idx) {
    chat_history_entry_t *entry = &host->history[idx];
    memset(entry, 0, sizeof(*entry));

    if (version >= 3U) {
      host_state_history_entry_v3_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.base.is_user_message != 0U;
      entry->user_is_bold = serialized.base.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.base.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.base.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.base.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
               serialized.base.user_highlight_name);
      entry->message_id = serialized.message_id;
      if (serialized.attachment_type > CHAT_ATTACHMENT_FILE) {
        entry->attachment_type = CHAT_ATTACHMENT_NONE;
      } else {
        entry->attachment_type = (chat_attachment_type_t)serialized.attachment_type;
      }
      snprintf(entry->attachment_target, sizeof(entry->attachment_target), "%s", serialized.attachment_target);
      snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.attachment_caption);
      memcpy(entry->reaction_counts, serialized.reaction_counts, sizeof(entry->reaction_counts));
    } else if (version == 2U) {
      host_state_history_entry_v2_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.base.is_user_message != 0U;
      entry->user_is_bold = serialized.base.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.base.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.base.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.base.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s",
               serialized.base.user_highlight_name);
      entry->message_id = serialized.message_id;
      if (serialized.attachment_type > CHAT_ATTACHMENT_AUDIO) {
        entry->attachment_type = CHAT_ATTACHMENT_NONE;
      } else {
        entry->attachment_type = (chat_attachment_type_t)serialized.attachment_type;
      }
      snprintf(entry->attachment_target, sizeof(entry->attachment_target), "%s", serialized.attachment_target);
      snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.attachment_caption);
      memcpy(entry->reaction_counts, serialized.reaction_counts, sizeof(entry->reaction_counts));
      if (serialized.sound_alias[0] != '\0' && entry->attachment_caption[0] == '\0') {
        snprintf(entry->attachment_caption, sizeof(entry->attachment_caption), "%s", serialized.sound_alias);
      }
    } else {
      host_state_history_entry_v1_t serialized = {0};
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }

      entry->is_user_message = serialized.is_user_message != 0U;
      entry->user_is_bold = serialized.user_is_bold != 0U;
      snprintf(entry->username, sizeof(entry->username), "%s", serialized.username);
      snprintf(entry->message, sizeof(entry->message), "%s", serialized.message);
      snprintf(entry->user_color_name, sizeof(entry->user_color_name), "%s", serialized.user_color_name);
      snprintf(entry->user_highlight_name, sizeof(entry->user_highlight_name), "%s", serialized.user_highlight_name);
      entry->attachment_type = CHAT_ATTACHMENT_NONE;
      entry->message_id = 0U;
    }

    host_history_normalize_entry(host, entry);
    ++host->history_count;
  }

  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;

  for (uint32_t idx = 0; success && idx < preference_count; ++idx) {
    host_state_preference_entry_t serialized = {0};
    if (version >= 7U) {
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }
    } else if (version == 6U) {
      host_state_preference_entry_v6_t legacy6 = {0};
      if (fread(&legacy6, sizeof(legacy6), 1U, fp) != 1U) {
        success = false;
        break;
      }
      serialized.has_user_theme = legacy6.has_user_theme;
      serialized.has_system_theme = legacy6.has_system_theme;
      serialized.user_is_bold = legacy6.user_is_bold;
      serialized.system_is_bold = legacy6.system_is_bold;
      snprintf(serialized.username, sizeof(serialized.username), "%s", legacy6.username);
      snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", legacy6.user_color_name);
      snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", legacy6.user_highlight_name);
      snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", legacy6.system_fg_name);
      snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", legacy6.system_bg_name);
      snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
               legacy6.system_highlight_name);
      snprintf(serialized.os_name, sizeof(serialized.os_name), "%s", legacy6.os_name);
      serialized.daily_year = legacy6.daily_year;
      serialized.daily_yday = legacy6.daily_yday;
      snprintf(serialized.daily_function, sizeof(serialized.daily_function), "%s", legacy6.daily_function);
      serialized.last_poll_id = legacy6.last_poll_id;
      serialized.last_poll_choice = legacy6.last_poll_choice;
      serialized.has_birthday = legacy6.has_birthday;
      serialized.translation_caption_spacing = legacy6.translation_caption_spacing;
      serialized.translation_enabled = legacy6.translation_enabled;
      serialized.output_translation_enabled = legacy6.output_translation_enabled;
      serialized.input_translation_enabled = legacy6.input_translation_enabled;
      serialized.translation_master_explicit = legacy6.translation_enabled;
      snprintf(serialized.birthday, sizeof(serialized.birthday), "%s", legacy6.birthday);
      snprintf(serialized.output_translation_language, sizeof(serialized.output_translation_language), "%s",
               legacy6.output_translation_language);
      snprintf(serialized.input_translation_language, sizeof(serialized.input_translation_language), "%s",
               legacy6.input_translation_language);
    } else if (version == 5U) {
      host_state_preference_entry_v5_t legacy5 = {0};
      if (fread(&legacy5, sizeof(legacy5), 1U, fp) != 1U) {
        success = false;
        break;
      }
      serialized.has_user_theme = legacy5.has_user_theme;
      serialized.has_system_theme = legacy5.has_system_theme;
      serialized.user_is_bold = legacy5.user_is_bold;
      serialized.system_is_bold = legacy5.system_is_bold;
      snprintf(serialized.username, sizeof(serialized.username), "%s", legacy5.username);
      snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", legacy5.user_color_name);
      snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", legacy5.user_highlight_name);
      snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", legacy5.system_fg_name);
      snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", legacy5.system_bg_name);
      snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
               legacy5.system_highlight_name);
      snprintf(serialized.os_name, sizeof(serialized.os_name), "%s", legacy5.os_name);
      serialized.daily_year = legacy5.daily_year;
      serialized.daily_yday = legacy5.daily_yday;
      snprintf(serialized.daily_function, sizeof(serialized.daily_function), "%s", legacy5.daily_function);
      serialized.last_poll_id = legacy5.last_poll_id;
      serialized.last_poll_choice = legacy5.last_poll_choice;
      serialized.has_birthday = legacy5.has_birthday;
      serialized.translation_caption_spacing = legacy5.reserved[0];
      serialized.translation_enabled = 0U;
      serialized.output_translation_enabled = 0U;
      serialized.input_translation_enabled = 0U;
      serialized.translation_master_explicit = 0U;
      snprintf(serialized.birthday, sizeof(serialized.birthday), "%s", legacy5.birthday);
      serialized.output_translation_language[0] = '\0';
      serialized.input_translation_language[0] = '\0';
    } else if (version == 4U) {
      host_state_preference_entry_v4_t legacy4 = {0};
      if (fread(&legacy4, sizeof(legacy4), 1U, fp) != 1U) {
        success = false;
        break;
      }
      serialized.has_user_theme = legacy4.has_user_theme;
      serialized.has_system_theme = legacy4.has_system_theme;
      serialized.user_is_bold = legacy4.user_is_bold;
      serialized.system_is_bold = legacy4.system_is_bold;
      snprintf(serialized.username, sizeof(serialized.username), "%s", legacy4.username);
      snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", legacy4.user_color_name);
      snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", legacy4.user_highlight_name);
      snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", legacy4.system_fg_name);
      snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", legacy4.system_bg_name);
      snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
               legacy4.system_highlight_name);
      snprintf(serialized.os_name, sizeof(serialized.os_name), "%s", legacy4.os_name);
      serialized.daily_year = legacy4.daily_year;
      serialized.daily_yday = legacy4.daily_yday;
      snprintf(serialized.daily_function, sizeof(serialized.daily_function), "%s", legacy4.daily_function);
      serialized.last_poll_id = legacy4.last_poll_id;
      serialized.last_poll_choice = legacy4.last_poll_choice;
      serialized.has_birthday = 0U;
      serialized.translation_caption_spacing = 0U;
      serialized.translation_enabled = 0U;
      serialized.output_translation_enabled = 0U;
      serialized.input_translation_enabled = 0U;
      serialized.translation_master_explicit = 0U;
      serialized.birthday[0] = '\0';
      serialized.output_translation_language[0] = '\0';
      serialized.input_translation_language[0] = '\0';
    } else {
      host_state_preference_entry_v3_t legacy = {0};
      if (fread(&legacy, sizeof(legacy), 1U, fp) != 1U) {
        success = false;
        break;
      }
      serialized.has_user_theme = legacy.has_user_theme;
      serialized.has_system_theme = legacy.has_system_theme;
      serialized.user_is_bold = legacy.user_is_bold;
      serialized.system_is_bold = legacy.system_is_bold;
      snprintf(serialized.username, sizeof(serialized.username), "%s", legacy.username);
      snprintf(serialized.user_color_name, sizeof(serialized.user_color_name), "%s", legacy.user_color_name);
      snprintf(serialized.user_highlight_name, sizeof(serialized.user_highlight_name), "%s", legacy.user_highlight_name);
      snprintf(serialized.system_fg_name, sizeof(serialized.system_fg_name), "%s", legacy.system_fg_name);
      snprintf(serialized.system_bg_name, sizeof(serialized.system_bg_name), "%s", legacy.system_bg_name);
      snprintf(serialized.system_highlight_name, sizeof(serialized.system_highlight_name), "%s",
               legacy.system_highlight_name);
      serialized.os_name[0] = '\0';
      serialized.daily_year = 0;
      serialized.daily_yday = 0;
      serialized.daily_function[0] = '\0';
      serialized.last_poll_id = 0U;
      serialized.last_poll_choice = -1;
      serialized.has_birthday = 0U;
      serialized.translation_caption_spacing = 0U;
      serialized.translation_enabled = 0U;
      serialized.output_translation_enabled = 0U;
      serialized.input_translation_enabled = 0U;
      serialized.translation_master_explicit = 0U;
      serialized.birthday[0] = '\0';
      serialized.output_translation_language[0] = '\0';
      serialized.input_translation_language[0] = '\0';
    }

    if (host->preference_count >= SSH_CHATTER_MAX_PREFERENCES) {
      continue;
    }

    user_preference_t *pref = &host->preferences[host->preference_count];
    memset(pref, 0, sizeof(*pref));
    pref->in_use = true;
    pref->has_user_theme = serialized.has_user_theme != 0U;
    pref->has_system_theme = serialized.has_system_theme != 0U;
    pref->user_is_bold = serialized.user_is_bold != 0U;
    pref->system_is_bold = serialized.system_is_bold != 0U;
    snprintf(pref->username, sizeof(pref->username), "%s", serialized.username);
    snprintf(pref->user_color_name, sizeof(pref->user_color_name), "%s", serialized.user_color_name);
    snprintf(pref->user_highlight_name, sizeof(pref->user_highlight_name), "%s", serialized.user_highlight_name);
    snprintf(pref->system_fg_name, sizeof(pref->system_fg_name), "%s", serialized.system_fg_name);
    snprintf(pref->system_bg_name, sizeof(pref->system_bg_name), "%s", serialized.system_bg_name);
    snprintf(pref->system_highlight_name, sizeof(pref->system_highlight_name), "%s",
             serialized.system_highlight_name);
    snprintf(pref->os_name, sizeof(pref->os_name), "%s", serialized.os_name);
    pref->daily_year = serialized.daily_year;
    pref->daily_yday = serialized.daily_yday;
    snprintf(pref->daily_function, sizeof(pref->daily_function), "%s", serialized.daily_function);
    pref->last_poll_id = serialized.last_poll_id;
    pref->last_poll_choice = serialized.last_poll_choice;
    pref->has_birthday = serialized.has_birthday != 0U;
    snprintf(pref->birthday, sizeof(pref->birthday), "%s", serialized.birthday);
    pref->translation_caption_spacing = serialized.translation_caption_spacing;
    pref->translation_master_enabled = serialized.translation_enabled != 0U;
    pref->translation_master_explicit = serialized.translation_master_explicit != 0U;
    pref->output_translation_enabled = serialized.output_translation_enabled != 0U;
    pref->input_translation_enabled = serialized.input_translation_enabled != 0U;
    snprintf(pref->output_translation_language, sizeof(pref->output_translation_language), "%s",
             serialized.output_translation_language);
    snprintf(pref->input_translation_language, sizeof(pref->input_translation_language), "%s",
             serialized.input_translation_language);
    ++host->preference_count;
  }

  memset(host->operator_grants, 0, HOST_GRANTS_CLEAR_SIZE);
  host->operator_grant_count = 0U;
  for (uint32_t idx = 0; success && idx < grant_count; ++idx) {
    host_state_grant_entry_t serialized = {0};
    if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      break;
    }
    if (serialized.ip[0] == '\0') {
      continue;
    }
    if (host->operator_grant_count >= SSH_CHATTER_MAX_GRANTS) {
      continue;
    }
    snprintf(host->operator_grants[host->operator_grant_count].ip,
             sizeof(host->operator_grants[host->operator_grant_count].ip), "%s", serialized.ip);
    ++host->operator_grant_count;
  }

  if (!success) {
    if (host->history != NULL && host->history_capacity > 0U) {
      memset(host->history, 0, host->history_capacity * sizeof(chat_history_entry_t));
    }
    host->history_count = 0U;
    host->preference_count = 0U;
    memset(host->preferences, 0, sizeof(host->preferences));
  }

  if (next_message_id == 0U) {
    next_message_id = (uint64_t)host->history_count + 1U;
  }
  if (next_message_id <= (uint64_t)host->history_count) {
    next_message_id = (uint64_t)host->history_count + 1U;
  }
  host->next_message_id = next_message_id;

  pthread_mutex_unlock(&host->lock);
  fclose(fp);
}

static void host_clear_rss_feed(rss_feed_t *feed) {
  if (feed == NULL) {
    return;
  }

  memset(feed, 0, sizeof(*feed));
}

static void host_rss_recount_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  size_t count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    if (host->rss_feeds[idx].in_use) {
      ++count;
    }
  }
  host->rss_feed_count = count;
}

static rss_feed_t *host_find_rss_feed_locked(host_t *host, const char *tag) {
  if (host == NULL || tag == NULL || tag[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    rss_feed_t *entry = &host->rss_feeds[idx];
    if (!entry->in_use) {
      continue;
    }
    if (strcasecmp(entry->tag, tag) == 0) {
      return entry;
    }
  }
  return NULL;
}

static bool host_rss_add_feed(host_t *host, const char *url, const char *tag, char *error, size_t error_length) {
  if (error != NULL && error_length > 0U) {
    error[0] = '\0';
  }

  if (host == NULL || url == NULL || url[0] == '\0' || tag == NULL || tag[0] == '\0') {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Invalid RSS feed details.");
    }
    return false;
  }

  pthread_mutex_lock(&host->lock);

  bool success = false;

  if (!rss_tag_is_valid(tag)) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Tag may only contain letters, numbers, '-', '_' or '.'.");
    }
    goto cleanup;
  }

  if (host->rss_feed_count >= SSH_CHATTER_RSS_MAX_FEEDS) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Maximum RSS feed capacity reached.");
    }
    goto cleanup;
  }

  if (host_find_rss_feed_locked(host, tag) != NULL) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Tag '%s' is already assigned to another feed.", tag);
    }
    goto cleanup;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    rss_feed_t *entry = &host->rss_feeds[idx];
    if (!entry->in_use) {
      continue;
    }
    if (strcasecmp(entry->url, url) == 0) {
      if (error != NULL && error_length > 0U) {
        snprintf(error, error_length, "Feed '%s' is already registered as '%s'.", url, entry->tag);
      }
      goto cleanup;
    }
  }

  rss_feed_t *slot = NULL;
  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    if (!host->rss_feeds[idx].in_use) {
      slot = &host->rss_feeds[idx];
      break;
    }
  }

  if (slot == NULL) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Unable to allocate RSS feed slot.");
    }
    goto cleanup;
  }

  host_clear_rss_feed(slot);
  slot->in_use = true;
  snprintf(slot->tag, sizeof(slot->tag), "%s", tag);
  snprintf(slot->url, sizeof(slot->url), "%s", url);
  slot->last_item_key[0] = '\0';
  slot->last_title[0] = '\0';
  slot->last_link[0] = '\0';
  slot->last_checked = 0;

  host_rss_recount_locked(host);
  host_rss_state_save_locked(host);
  success = true;

cleanup:
  pthread_mutex_unlock(&host->lock);
  return success;
}

static bool host_rss_remove_feed(host_t *host, const char *tag, char *error, size_t error_length) {
  if (error != NULL && error_length > 0U) {
    error[0] = '\0';
  }

  if (host == NULL || tag == NULL || tag[0] == '\0') {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Invalid RSS feed tag.");
    }
    return false;
  }

  pthread_mutex_lock(&host->lock);

  bool success = false;

  if (!rss_tag_is_valid(tag)) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Tag may only contain letters, numbers, '-', '_' or '.'.");
    }
    goto cleanup;
  }

  rss_feed_t *entry = host_find_rss_feed_locked(host, tag);
  if (entry == NULL) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "No RSS feed found for tag '%s'.", tag);
    }
    goto cleanup;
  }

  host_clear_rss_feed(entry);
  host_rss_recount_locked(host);
  host_rss_state_save_locked(host);
  success = true;

cleanup:
  pthread_mutex_unlock(&host->lock);
  return success;
}

static void host_rss_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *rss_path = getenv("CHATTER_RSS_FILE");
  if (rss_path == NULL || rss_path[0] == '\0') {
    rss_path = "rss_state.dat";
  }

  int written = snprintf(host->rss_state_file_path, sizeof(host->rss_state_file_path), "%s", rss_path);
  if (written < 0 || (size_t)written >= sizeof(host->rss_state_file_path)) {
    humanized_log_error("host", "rss state file path is too long", ENAMETOOLONG);
    host->rss_state_file_path[0] = '\0';
  }
}

static void host_rss_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->rss_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->rss_state_file_path, true)) {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->rss_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "rss state file path is too long", ENAMETOOLONG);
    return;
  }

  int temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if (temp_fd < 0) {
    humanized_log_error("host", "failed to open rss state file", errno != 0 ? errno : EIO);
    return;
  }

  FILE *fp = fdopen(temp_fd, "wb");
  if (fp == NULL) {
    int saved_errno = errno;
    close(temp_fd);
    unlink(temp_path);
    humanized_log_error("host", "failed to wrap rss state descriptor", saved_errno != 0 ? saved_errno : EIO);
    return;
  }

  uint32_t feed_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    if (host->rss_feeds[idx].in_use) {
      ++feed_count;
    }
  }

  rss_state_header_t header = {0};
  header.magic = RSS_STATE_MAGIC;
  header.version = RSS_STATE_VERSION;
  header.feed_count = feed_count;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  for (size_t idx = 0U; success && idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    const rss_feed_t *entry = &host->rss_feeds[idx];
    if (!entry->in_use) {
      continue;
    }

    rss_state_entry_t record = {0};
    snprintf(record.tag, sizeof(record.tag), "%s", entry->tag);
    snprintf(record.url, sizeof(record.url), "%s", entry->url);
    snprintf(record.last_item_key, sizeof(record.last_item_key), "%s", entry->last_item_key);

    if (fwrite(&record, sizeof(record), 1U, fp) != 1U) {
      success = false;
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
  }

  if (success) {
    int descriptor = fileno(fp);
    if (descriptor >= 0 && fsync(descriptor) != 0) {
      success = false;
    }
  }

  if (fclose(fp) != 0) {
    success = false;
  }

  if (!success) {
    humanized_log_error("host", "failed to write rss state file", errno != 0 ? errno : EIO);
    unlink(temp_path);
    return;
  }

  if (chmod(temp_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to tighten temporary rss state permissions", errno != 0 ? errno : EACCES);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->rss_state_file_path) != 0) {
    humanized_log_error("host", "failed to update rss state file", errno != 0 ? errno : EIO);
    unlink(temp_path);
  } else if (chmod(host->rss_state_file_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to tighten rss state permissions", errno != 0 ? errno : EACCES);
  }
}

static void host_rss_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->rss_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->rss_state_file_path, false)) {
    return;
  }

  FILE *fp = fopen(host->rss_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  rss_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != RSS_STATE_MAGIC || header.version == 0U || header.version > RSS_STATE_VERSION) {
    fclose(fp);
    return;
  }

  pthread_mutex_lock(&host->lock);

  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    host_clear_rss_feed(&host->rss_feeds[idx]);
  }
  host->rss_feed_count = 0U;

  bool success = true;
  for (uint32_t idx = 0U; idx < header.feed_count; ++idx) {
    rss_state_entry_t record = {0};
    if (fread(&record, sizeof(record), 1U, fp) != 1U) {
      success = false;
      break;
    }

    rss_trim_whitespace(record.tag);
    rss_trim_whitespace(record.url);
    rss_trim_whitespace(record.last_item_key);

    if (!rss_tag_is_valid(record.tag) || record.url[0] == '\0') {
      continue;
    }

    rss_feed_t *slot = NULL;
    for (size_t pos = 0U; pos < SSH_CHATTER_RSS_MAX_FEEDS; ++pos) {
      if (!host->rss_feeds[pos].in_use) {
        slot = &host->rss_feeds[pos];
        break;
      }
    }

    if (slot == NULL) {
      continue;
    }

    host_clear_rss_feed(slot);
    slot->in_use = true;
    snprintf(slot->tag, sizeof(slot->tag), "%s", record.tag);
    snprintf(slot->url, sizeof(slot->url), "%s", record.url);
    snprintf(slot->last_item_key, sizeof(slot->last_item_key), "%s", record.last_item_key);
    slot->last_checked = 0;
  }

  if (success) {
    host_rss_recount_locked(host);
  } else {
    for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
      host_clear_rss_feed(&host->rss_feeds[idx]);
    }
    host->rss_feed_count = 0U;
  }

  pthread_mutex_unlock(&host->lock);
  fclose(fp);
}

typedef struct host_rss_buffer {
  char *data;
  size_t length;
} host_rss_buffer_t;

static size_t host_rss_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  host_rss_buffer_t *buffer = (host_rss_buffer_t *)userp;
  const size_t total = size * nmemb;
  if (buffer == NULL || total == 0U) {
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

static bool host_rss_download(const char *url, char **payload, size_t *length) {
  if (payload != NULL) {
    *payload = NULL;
  }
  if (length != NULL) {
    *length = 0U;
  }

  if (url == NULL || url[0] == '\0') {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    return false;
  }

  host_rss_buffer_t buffer = {0};
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, SSH_CHATTER_RSS_USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, host_rss_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

  bool success = false;
  CURLcode result = curl_easy_perform(curl);
  if (result == CURLE_OK) {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status >= 200L && status < 300L && buffer.data != NULL) {
      if (payload != NULL) {
        *payload = buffer.data;
      }
      if (length != NULL) {
        *length = buffer.length;
      }
      buffer.data = NULL;
      success = true;
    }
  }

  if (!success) {
    free(buffer.data);
  }

  curl_easy_cleanup(curl);
  return success;
}

static bool host_rss_extract_tag(const char *block, const char *tag, char *out, size_t out_len) {
  if (block == NULL || tag == NULL || out == NULL || out_len == 0U) {
    return false;
  }

  char open_pattern[32];
  char close_pattern[32];
  int open_written = snprintf(open_pattern, sizeof(open_pattern), "<%s", tag);
  int close_written = snprintf(close_pattern, sizeof(close_pattern), "</%s>", tag);
  if (open_written < 0 || (size_t)open_written >= sizeof(open_pattern) || close_written < 0 ||
      (size_t)close_written >= sizeof(close_pattern)) {
    return false;
  }

  const char *start = strcasestr(block, open_pattern);
  if (start == NULL) {
    return false;
  }

  const char *content = strchr(start, '>');
  if (content == NULL) {
    return false;
  }
  ++content;

  const char *end = strcasestr(content, close_pattern);
  if (end == NULL) {
    return false;
  }

  size_t length = (size_t)(end - content);
  if (length >= out_len) {
    length = out_len - 1U;
  }
  memcpy(out, content, length);
  out[length] = '\0';
  return true;
}

static bool host_rss_extract_atom_link(const char *block, char *out, size_t out_len) {
  if (block == NULL || out == NULL || out_len == 0U) {
    return false;
  }

  const char *cursor = block;
  while ((cursor = strcasestr(cursor, "<link")) != NULL) {
    const char *close = strchr(cursor, '>');
    if (close == NULL) {
      return false;
    }

    const char *href = strcasestr(cursor, "href=");
    if (href == NULL || href > close) {
      cursor = close + 1;
      continue;
    }

    href += 5; // skip href=
    char quote = *href;
    if (quote != '\"' && quote != '\'') {
      cursor = close + 1;
      continue;
    }
    ++href;

    const char *end = strchr(href, quote);
    if (end == NULL || end > close) {
      cursor = close + 1;
      continue;
    }

    size_t length = (size_t)(end - href);
    if (length >= out_len) {
      length = out_len - 1U;
    }
    memcpy(out, href, length);
    out[length] = '\0';
    rss_trim_whitespace(out);
    return out[0] != '\0';
  }

  return false;
}

static size_t host_rss_parse_items(const char *payload, rss_session_item_t *items, size_t max_items) {
  if (payload == NULL || items == NULL || max_items == 0U) {
    return 0U;
  }

  for (size_t idx = 0U; idx < max_items; ++idx) {
    memset(&items[idx], 0, sizeof(items[idx]));
  }

  size_t count = 0U;
  const char *cursor = payload;
  while (*cursor != '\0' && count < max_items) {
    const char *item_start = strcasestr(cursor, "<item");
    const char *entry_start = strcasestr(cursor, "<entry");
    const char *start = NULL;
    const char *close_tag = NULL;
    bool is_atom = false;

    if (item_start == NULL && entry_start == NULL) {
      break;
    }

    if (item_start != NULL && (entry_start == NULL || item_start < entry_start)) {
      start = item_start;
      close_tag = "</item>";
    } else {
      start = entry_start;
      close_tag = "</entry>";
      is_atom = true;
    }

    const char *end = strcasestr(start, close_tag);
    if (end == NULL) {
      break;
    }
    end += strlen(close_tag);

    size_t block_len = (size_t)(end - start);
    char *block = malloc(block_len + 1U);
    if (block == NULL) {
      break;
    }
    memcpy(block, start, block_len);
    block[block_len] = '\0';

    char title[SSH_CHATTER_RSS_TITLE_LEN] = {0};
    char link[SSH_CHATTER_RSS_LINK_LEN] = {0};
    char summary[SSH_CHATTER_RSS_SUMMARY_LEN] = {0};
    char guid[SSH_CHATTER_RSS_ITEM_KEY_LEN] = {0};

    bool have_title = host_rss_extract_tag(block, "title", title, sizeof(title));
    bool have_link = host_rss_extract_tag(block, "link", link, sizeof(link));
    if (!have_link) {
      have_link = host_rss_extract_atom_link(block, link, sizeof(link));
    }
    bool have_guid = false;
    if (is_atom) {
      have_guid = host_rss_extract_tag(block, "id", guid, sizeof(guid));
    } else {
      have_guid = host_rss_extract_tag(block, "guid", guid, sizeof(guid));
    }
    bool have_summary = host_rss_extract_tag(block, "description", summary, sizeof(summary));
    if (!have_summary) {
      have_summary = host_rss_extract_tag(block, "summary", summary, sizeof(summary));
    }
    if (!have_summary) {
      have_summary = host_rss_extract_tag(block, "content", summary, sizeof(summary));
    }

    rss_trim_whitespace(title);
    rss_trim_whitespace(link);
    rss_trim_whitespace(guid);
    rss_trim_whitespace(summary);
    rss_strip_html(summary);
    rss_decode_entities(title);
    rss_decode_entities(link);
    rss_decode_entities(guid);
    rss_decode_entities(summary);

    rss_session_item_t *item = &items[count];
    if (have_title) {
      snprintf(item->title, sizeof(item->title), "%s", title);
    }
    if (have_link) {
      snprintf(item->link, sizeof(item->link), "%s", link);
    }
    if (have_summary) {
      snprintf(item->summary, sizeof(item->summary), "%s", summary);
    }

    if (have_guid) {
      snprintf(item->id, sizeof(item->id), "%s", guid);
    } else if (have_link) {
      snprintf(item->id, sizeof(item->id), "%s", link);
    } else if (have_title) {
      snprintf(item->id, sizeof(item->id), "%s", title);
    }

    ++count;
    free(block);
    cursor = end;
  }

  return count;
}

static bool host_rss_fetch_items(const rss_feed_t *feed, rss_session_item_t *items, size_t max_items, size_t *out_count) {
  if (out_count != NULL) {
    *out_count = 0U;
  }

  if (feed == NULL || items == NULL || max_items == 0U) {
    return false;
  }

  char *payload = NULL;
  size_t length = 0U;
  if (!host_rss_download(feed->url, &payload, &length)) {
    return false;
  }

  size_t count = host_rss_parse_items(payload, items, max_items);
  if (out_count != NULL) {
    *out_count = count;
  }

  free(payload);
  return true;
}

static bool host_rss_should_broadcast_breaking(const rss_session_item_t *item) {
  if (item == NULL) {
    return false;
  }

  const char *fields[] = {item->title, item->summary, item->link};
  for (size_t field_index = 0U; field_index < sizeof(fields) / sizeof(fields[0]); ++field_index) {
    const char *field = fields[field_index];
    if (field == NULL || field[0] == '\0') {
      continue;
    }

    if (strncasecmp(field, "[breaking", 9) == 0) {
      return true;
    }
    if (strcasestr(field, "breaking news") != NULL || strcasestr(field, "breaking:") != NULL ||
        strcasestr(field, "breaking ") != NULL) {
      return true;
    }
    if (strcasestr(field, "urgent") != NULL || strcasestr(field, "alert") != NULL) {
      return true;
    }
    if (strstr(field, "속보") != NULL || strstr(field, "速報") != NULL) {
      return true;
    }
  }

  return false;
}

static void *host_rss_backend(void *arg) {
  host_t *host = (host_t *)arg;
  if (host == NULL) {
    return NULL;
  }

  atomic_store(&host->rss_thread_running, true);
  printf("[rss] backend thread started (interval: %u seconds)\n", (unsigned int)SSH_CHATTER_RSS_REFRESH_SECONDS);

  while (!atomic_load(&host->rss_thread_stop)) {
    rss_feed_t feed_snapshots[SSH_CHATTER_RSS_MAX_FEEDS];
    size_t snapshot_count = 0U;

    pthread_mutex_lock(&host->lock);
    for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
      if (!host->rss_feeds[idx].in_use) {
        continue;
      }
      feed_snapshots[snapshot_count++] = host->rss_feeds[idx];
    }
    pthread_mutex_unlock(&host->lock);

    if (snapshot_count > 0U) {
      for (size_t snapshot_index = 0U; snapshot_index < snapshot_count && !atomic_load(&host->rss_thread_stop);
           ++snapshot_index) {
        rss_feed_t feed_snapshot = feed_snapshots[snapshot_index];

        rss_session_item_t items[SSH_CHATTER_RSS_MAX_ITEMS];
        size_t item_count = 0U;
        if (!host_rss_fetch_items(&feed_snapshot, items, SSH_CHATTER_RSS_MAX_ITEMS, &item_count)) {
          printf("[rss] failed to refresh feed '%s' (%s)\n", feed_snapshot.tag, feed_snapshot.url);
          continue;
        }

        size_t new_item_count = 0U;
        if (item_count > 0U) {
          if (feed_snapshot.last_item_key[0] == '\0') {
            new_item_count = 0U;
          } else {
            bool found_marker = false;
            for (size_t idx = 0U; idx < item_count; ++idx) {
              if (items[idx].id[0] == '\0' || feed_snapshot.last_item_key[0] == '\0') {
                continue;
              }
              if (strcmp(items[idx].id, feed_snapshot.last_item_key) == 0) {
                new_item_count = idx;
                found_marker = true;
                break;
              }
            }
            if (!found_marker) {
              new_item_count = item_count;
            }
          }
        }

        bool feed_active = false;
        bool key_changed = false;
        time_t now = time(NULL);

        pthread_mutex_lock(&host->lock);
        rss_feed_t *entry = host_find_rss_feed_locked(host, feed_snapshot.tag);
        if (entry != NULL && entry->in_use) {
          feed_active = true;
          entry->last_checked = now;
          if (item_count > 0U) {
            const rss_session_item_t *latest = &items[0U];
            char new_key[SSH_CHATTER_RSS_ITEM_KEY_LEN];
            new_key[0] = '\0';
            if (latest->id[0] != '\0') {
              snprintf(new_key, sizeof(new_key), "%s", latest->id);
            } else if (latest->link[0] != '\0') {
              snprintf(new_key, sizeof(new_key), "%s", latest->link);
            } else if (latest->title[0] != '\0') {
              snprintf(new_key, sizeof(new_key), "%s", latest->title);
            }

            if (new_key[0] != '\0' && strcmp(entry->last_item_key, new_key) != 0) {
              snprintf(entry->last_item_key, sizeof(entry->last_item_key), "%s", new_key);
              key_changed = true;
            }

            if (latest->title[0] != '\0') {
              snprintf(entry->last_title, sizeof(entry->last_title), "%s", latest->title);
            } else {
              entry->last_title[0] = '\0';
            }

            if (latest->link[0] != '\0') {
              snprintf(entry->last_link, sizeof(entry->last_link), "%s", latest->link);
            } else {
              entry->last_link[0] = '\0';
            }
          }

          if (key_changed) {
            host_rss_state_save_locked(host);
          }
        }
        pthread_mutex_unlock(&host->lock);

        if (!feed_active || new_item_count == 0U) {
          continue;
        }

        for (size_t idx = new_item_count; idx > 0U && !atomic_load(&host->rss_thread_stop); --idx) {
          const rss_session_item_t *item = &items[idx - 1U];
          if (!host_rss_should_broadcast_breaking(item)) {
            continue;
          }

          char headline[SSH_CHATTER_RSS_TITLE_LEN];
          if (item->title[0] != '\0') {
            snprintf(headline, sizeof(headline), "%s", item->title);
          } else if (item->summary[0] != '\0') {
            snprintf(headline, sizeof(headline), "%s", item->summary);
          } else if (item->link[0] != '\0') {
            snprintf(headline, sizeof(headline), "%s", item->link);
          } else {
            snprintf(headline, sizeof(headline), "%s", "New update");
          }

          rss_trim_whitespace(headline);
          for (size_t pos = 0U; headline[pos] != '\0'; ++pos) {
            if (headline[pos] == '\r' || headline[pos] == '\n' || headline[pos] == '\t') {
              headline[pos] = ' ';
            }
          }
          rss_trim_whitespace(headline);
          if (headline[0] == '\0') {
            snprintf(headline, sizeof(headline), "%s", "New update");
          }

          char notice[SSH_CHATTER_MESSAGE_LIMIT];
          if (item->link[0] != '\0') {
            snprintf(notice, sizeof(notice), "* %s [%s] %s — %s", SSH_CHATTER_RSS_BREAKING_PREFIX, feed_snapshot.tag,
                     headline, item->link);
          } else {
            snprintf(notice, sizeof(notice), "* %s [%s] %s", SSH_CHATTER_RSS_BREAKING_PREFIX, feed_snapshot.tag,
                     headline);
          }

          printf("%s\n", notice);
          host_history_record_system(host, notice);
          chat_room_broadcast(&host->room, notice, NULL);
        }
      }
    }

    struct timespec mark;
    if (clock_gettime(CLOCK_MONOTONIC, &mark) == 0) {
      host->rss_last_run = mark;
    } else {
      host->rss_last_run.tv_sec = time(NULL);
      host->rss_last_run.tv_nsec = 0L;
    }

    unsigned int remaining = snapshot_count > 0U ? SSH_CHATTER_RSS_REFRESH_SECONDS : SSH_CHATTER_RSS_SLEEP_CHUNK_SECONDS;
    while (remaining > 0U && !atomic_load(&host->rss_thread_stop)) {
      unsigned int chunk = remaining > SSH_CHATTER_RSS_SLEEP_CHUNK_SECONDS ? SSH_CHATTER_RSS_SLEEP_CHUNK_SECONDS : remaining;
      struct timespec pause = {
          .tv_sec = (time_t)chunk,
          .tv_nsec = 0L,
      };
      nanosleep(&pause, NULL);
      if (remaining <= chunk) {
        remaining = 0U;
      } else {
        remaining -= chunk;
      }
    }
  }

  atomic_store(&host->rss_thread_running, false);
  printf("[rss] backend thread stopped\n");
  return NULL;
}

static void host_rss_start_backend(host_t *host) {
  if (host == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  bool has_feeds = host->rss_feed_count > 0U;
  pthread_mutex_unlock(&host->lock);

  if (!has_feeds) {
    return;
  }

  if (host->rss_thread_initialized) {
    return;
  }

  atomic_store(&host->rss_thread_stop, false);
  atomic_store(&host->rss_thread_running, false);

  int error = pthread_create(&host->rss_thread, NULL, host_rss_backend, host);
  if (error != 0) {
    printf("[rss] failed to start backend thread: %s\n", strerror(error));
    return;
  }

  host->rss_thread_initialized = true;
}

static void host_vote_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->vote_state_file_path[0] == '\0') {
    return;
  }

  FILE *fp = fopen(host->vote_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  vote_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != VOTE_STATE_MAGIC) {
    fclose(fp);
    return;
  }

  if (header.version == 0U || header.version > VOTE_STATE_VERSION) {
    fclose(fp);
    return;
  }

  pthread_mutex_lock(&host->lock);

  poll_state_reset(&host->poll);
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    named_poll_reset(&host->named_polls[idx]);
  }
  host->named_poll_count = 0U;

  bool success = true;

  vote_state_poll_entry_t main_entry = {0};
  if (fread(&main_entry, sizeof(main_entry), 1U, fp) != 1U) {
    success = false;
  } else {
    vote_state_import_poll_entry(&main_entry, &host->poll);
  }

  for (uint32_t idx = 0U; success && idx < header.named_count; ++idx) {
    vote_state_named_entry_t entry = {0};
    if (fread(&entry, sizeof(entry), 1U, fp) != 1U) {
      success = false;
      break;
    }

    if (idx >= SSH_CHATTER_MAX_NAMED_POLLS) {
      continue;
    }

    named_poll_state_t *poll = &host->named_polls[idx];
    vote_state_import_poll_entry(&entry.poll, &poll->poll);
    snprintf(poll->label, sizeof(poll->label), "%s", entry.label);
    snprintf(poll->owner, sizeof(poll->owner), "%s", entry.owner);
    poll->voter_count = entry.voter_count;
    if (poll->voter_count > SSH_CHATTER_MAX_NAMED_VOTERS) {
      poll->voter_count = SSH_CHATTER_MAX_NAMED_VOTERS;
    }
    for (size_t voter = 0U; voter < SSH_CHATTER_MAX_NAMED_VOTERS; ++voter) {
      snprintf(poll->voters[voter].username, sizeof(poll->voters[voter].username), "%s", entry.voters[voter].username);
      poll->voters[voter].choice = entry.voters[voter].choice;
      poll->voters[voter].choices_mask = entry.voters[voter].choices_mask;
    }
  }

  if (success) {
    host_recount_named_polls_locked(host);
  } else {
    poll_state_reset(&host->poll);
    for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
      named_poll_reset(&host->named_polls[idx]);
    }
    host->named_poll_count = 0U;
  }

  pthread_mutex_unlock(&host->lock);
  fclose(fp);
}

static void host_ban_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->ban_state_file_path[0] == '\0') {
    return;
  }

  FILE *fp = fopen(host->ban_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  ban_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != BAN_STATE_MAGIC || header.version == 0U || header.version > BAN_STATE_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t entry_count = header.entry_count;
  ban_state_entry_t *entries = NULL;
  if (entry_count > 0U) {
    entries = calloc(entry_count, sizeof(*entries));
    if (entries == NULL) {
      fclose(fp);
      humanized_log_error("host", "failed to allocate ban state buffer", ENOMEM);
      return;
    }
  }

  bool success = true;
  int read_error = 0;
  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    if (fread(&entries[idx], sizeof(entries[idx]), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        read_error = errno;
      }
      break;
    }
  }

  fclose(fp);

  if (!success) {
    humanized_log_error("host", "failed to read ban state file", read_error != 0 ? read_error : EIO);
    free(entries);
    return;
  }

  pthread_mutex_lock(&host->lock);
  memset(host->bans, 0, sizeof(host->bans));
  host->ban_count = 0U;
  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    if (host->ban_count >= SSH_CHATTER_MAX_BANS) {
      break;
    }
    snprintf(host->bans[host->ban_count].username, sizeof(host->bans[host->ban_count].username), "%s",
             entries[idx].username);
    snprintf(host->bans[host->ban_count].ip, sizeof(host->bans[host->ban_count].ip), "%s", entries[idx].ip);
    ++host->ban_count;
  }
  pthread_mutex_unlock(&host->lock);

  free(entries);
}

static void host_reply_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->reply_state_file_path[0] == '\0') {
    return;
  }

  FILE *fp = fopen(host->reply_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  reply_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != REPLY_STATE_MAGIC || header.version == 0U || header.version > REPLY_STATE_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t entry_count = header.entry_count;
  reply_state_entry_t *entries = NULL;
  if (entry_count > 0U) {
    entries = calloc(entry_count, sizeof(*entries));
    if (entries == NULL) {
      fclose(fp);
      humanized_log_error("host", "failed to allocate reply state buffer", ENOMEM);
      return;
    }
  }

  bool success = true;
  int read_error = 0;
  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    if (fread(&entries[idx], sizeof(entries[idx]), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        read_error = errno;
      }
      break;
    }
  }

  fclose(fp);

  if (!success) {
    humanized_log_error("host", "failed to read reply state file", read_error != 0 ? read_error : EIO);
    free(entries);
    return;
  }

  pthread_mutex_lock(&host->lock);
  memset(host->replies, 0, sizeof(host->replies));
  host->reply_count = 0U;
  host->next_reply_id = header.next_reply_id != 0U ? header.next_reply_id : 1U;
  uint64_t max_reply_id = 0U;

  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    if (host->reply_count >= SSH_CHATTER_MAX_REPLIES) {
      if (entries[idx].reply_id > max_reply_id) {
        max_reply_id = entries[idx].reply_id;
      }
      continue;
    }

    chat_reply_entry_t *slot = &host->replies[host->reply_count];
    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->reply_id = entries[idx].reply_id != 0U ? entries[idx].reply_id : (uint64_t)(host->reply_count + 1U);
    if (slot->reply_id > max_reply_id) {
      max_reply_id = slot->reply_id;
    }
    slot->parent_message_id = entries[idx].parent_message_id;
    slot->parent_reply_id = entries[idx].parent_reply_id;
    slot->created_at = (time_t)entries[idx].created_at;
    snprintf(slot->username, sizeof(slot->username), "%s", entries[idx].username);
    snprintf(slot->message, sizeof(slot->message), "%s", entries[idx].message);
    ++host->reply_count;
  }

  if (host->next_reply_id <= max_reply_id) {
    if (max_reply_id == UINT64_MAX) {
      host->next_reply_id = UINT64_MAX;
    } else {
      host->next_reply_id = max_reply_id + 1U;
    }
  }

  if (host->next_reply_id == 0U) {
    host->next_reply_id = (uint64_t)host->reply_count + 1U;
  }

  pthread_mutex_unlock(&host->lock);

  free(entries);
}

static void host_eliza_memory_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *memory_path = getenv("CHATTER_ELIZA_MEMORY_FILE");
  if (memory_path == NULL || memory_path[0] == '\0') {
    memory_path = "eliza_memory.dat";
  }

  int written = snprintf(host->eliza_memory_file_path, sizeof(host->eliza_memory_file_path), "%s", memory_path);
  if (written < 0 || (size_t)written >= sizeof(host->eliza_memory_file_path)) {
    humanized_log_error("host", "eliza memory file path is too long", ENAMETOOLONG);
    host->eliza_memory_file_path[0] = '\0';
  }
}

static void host_eliza_memory_save_locked(host_t *host) {
  if (host == NULL || host->eliza_memory_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->eliza_memory_file_path, true)) {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->eliza_memory_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "eliza memory path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open eliza memory file", errno != 0 ? errno : EIO);
    return;
  }

  size_t stored = host->eliza_memory_count;
  if (stored > SSH_CHATTER_ELIZA_MEMORY_MAX) {
    stored = SSH_CHATTER_ELIZA_MEMORY_MAX;
  }

  eliza_memory_header_t header = {0};
  header.magic = ELIZA_MEMORY_MAGIC;
  header.version = ELIZA_MEMORY_VERSION;
  header.entry_count = (uint32_t)stored;
  header.next_id = host->eliza_memory_next_id;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;
  int write_error = 0;
  if (!success && errno != 0) {
    write_error = errno;
  }

  for (size_t idx = 0U; success && idx < stored; ++idx) {
    const eliza_memory_entry_t *entry = &host->eliza_memory[idx];
    eliza_memory_entry_serialized_t serialized = {0};
    serialized.id = entry->id;
    serialized.stored_at = (int64_t)entry->stored_at;
    snprintf(serialized.prompt, sizeof(serialized.prompt), "%s", entry->prompt);
    snprintf(serialized.reply, sizeof(serialized.reply), "%s", entry->reply);
    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
    if (errno != 0) {
      write_error = errno;
    }
  }

  if (success) {
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
      success = false;
      if (errno != 0) {
        write_error = errno;
      }
    }
  }

  if (fclose(fp) != 0) {
    if (success && errno != 0) {
      write_error = errno;
    }
    success = false;
  }

  if (!success) {
    unlink(temp_path);
    humanized_log_error("host", "failed to write eliza memory file", write_error != 0 ? write_error : EIO);
    return;
  }

  if (rename(temp_path, host->eliza_memory_file_path) != 0) {
    int rename_error = errno != 0 ? errno : EIO;
    unlink(temp_path);
    humanized_log_error("host", "failed to install eliza memory file", rename_error);
    return;
  }

  if (chmod(host->eliza_memory_file_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to set eliza memory permissions", errno != 0 ? errno : EACCES);
  }
}

static void host_eliza_memory_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->eliza_memory_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->eliza_memory_file_path, false)) {
    return;
  }

  FILE *fp = fopen(host->eliza_memory_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  eliza_memory_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != ELIZA_MEMORY_MAGIC || header.version == 0U || header.version > ELIZA_MEMORY_VERSION) {
    fclose(fp);
    return;
  }

  uint32_t entry_count = header.entry_count;
  eliza_memory_entry_serialized_t *entries = NULL;
  if (entry_count > 0U) {
    entries = calloc(entry_count, sizeof(*entries));
    if (entries == NULL) {
      fclose(fp);
      humanized_log_error("host", "failed to allocate eliza memory buffer", ENOMEM);
      return;
    }
  }

  bool success = true;
  int read_error = 0;
  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    if (fread(&entries[idx], sizeof(entries[idx]), 1U, fp) != 1U) {
      success = false;
      if (errno != 0) {
        read_error = errno;
      }
      break;
    }
  }

  fclose(fp);

  if (!success) {
    humanized_log_error("host", "failed to read eliza memory file", read_error != 0 ? read_error : EIO);
    free(entries);
    return;
  }

  pthread_mutex_lock(&host->lock);
  memset(host->eliza_memory, 0, sizeof(host->eliza_memory));
  host->eliza_memory_count = 0U;
  host->eliza_memory_next_id = header.next_id != 0U ? header.next_id : 1U;

  uint64_t max_id = 0U;
  for (uint32_t idx = 0U; idx < entry_count; ++idx) {
    uint64_t entry_id = entries[idx].id != 0U ? entries[idx].id : (uint64_t)(idx + 1U);
    if (idx < SSH_CHATTER_ELIZA_MEMORY_MAX) {
      eliza_memory_entry_t *slot = &host->eliza_memory[host->eliza_memory_count++];
      slot->id = entry_id;
      slot->stored_at = (time_t)entries[idx].stored_at;
      snprintf(slot->prompt, sizeof(slot->prompt), "%s", entries[idx].prompt);
      snprintf(slot->reply, sizeof(slot->reply), "%s", entries[idx].reply);
    }
    if (entry_id > max_id) {
      max_id = entry_id;
    }
  }

  if (max_id >= host->eliza_memory_next_id) {
    host->eliza_memory_next_id = (max_id == UINT64_MAX) ? UINT64_MAX : max_id + 1U;
  }
  if (host->eliza_memory_next_id == 0U) {
    host->eliza_memory_next_id = (uint64_t)host->eliza_memory_count + 1U;
  }

  pthread_mutex_unlock(&host->lock);
  free(entries);
}

static void host_eliza_memory_store(host_t *host, const char *prompt, const char *reply) {
  if (host == NULL || prompt == NULL || reply == NULL) {
    return;
  }

  char clean_prompt[SSH_CHATTER_MESSAGE_LIMIT];
  char clean_reply[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(clean_prompt, sizeof(clean_prompt), "%s", prompt);
  snprintf(clean_reply, sizeof(clean_reply), "%s", reply);
  trim_whitespace_inplace(clean_prompt);
  trim_whitespace_inplace(clean_reply);

  pthread_mutex_lock(&host->lock);
  if (host->eliza_memory_count >= SSH_CHATTER_ELIZA_MEMORY_MAX) {
    memmove(host->eliza_memory, host->eliza_memory + 1,
            (SSH_CHATTER_ELIZA_MEMORY_MAX - 1U) * sizeof(host->eliza_memory[0]));
    host->eliza_memory_count = SSH_CHATTER_ELIZA_MEMORY_MAX - 1U;
  }

  eliza_memory_entry_t *entry = &host->eliza_memory[host->eliza_memory_count++];
  if (host->eliza_memory_next_id == 0U) {
    host->eliza_memory_next_id = 1U;
  }
  entry->id = host->eliza_memory_next_id;
  if (host->eliza_memory_next_id < UINT64_MAX) {
    host->eliza_memory_next_id += 1U;
  }
  entry->stored_at = time(NULL);
  snprintf(entry->prompt, sizeof(entry->prompt), "%s", clean_prompt);
  snprintf(entry->reply, sizeof(entry->reply), "%s", clean_reply);

  host_eliza_memory_save_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static size_t host_eliza_memory_collect_tokens(const char *prompt, char tokens[][32], size_t max_tokens) {
  if (tokens == NULL || max_tokens == 0U || prompt == NULL) {
    return 0U;
  }

  size_t count = 0U;
  size_t length = strlen(prompt);
  size_t idx = 0U;
  while (idx < length && count < max_tokens) {
    while (idx < length && isspace((unsigned char)prompt[idx])) {
      ++idx;
    }
    if (idx >= length) {
      break;
    }

    size_t token_idx = 0U;
    char buffer[32];
    while (idx < length && !isspace((unsigned char)prompt[idx])) {
      unsigned char ch = (unsigned char)prompt[idx];
      if (token_idx + 1U < sizeof(buffer)) {
        buffer[token_idx++] = (ch < 0x80U) ? (char)tolower(ch) : (char)ch;
      }
      ++idx;
    }
    buffer[token_idx] = '\0';

    if (token_idx == 0U) {
      continue;
    }
    if (token_idx < 3U && (unsigned char)buffer[0] < 0x80U) {
      continue;
    }

    bool duplicate = false;
    for (size_t existing = 0U; existing < count; ++existing) {
      if (strcmp(tokens[existing], buffer) == 0) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      continue;
    }

    snprintf(tokens[count], 32U, "%s", buffer);
    ++count;
  }

  return count;
}

static size_t host_eliza_memory_collect_context(host_t *host, const char *prompt, char *context,
                                                size_t context_length) {
  if (context == NULL || context_length == 0U) {
    return 0U;
  }

  context[0] = '\0';
  if (host == NULL || prompt == NULL) {
    return 0U;
  }

  eliza_memory_entry_t snapshot[SSH_CHATTER_ELIZA_MEMORY_MAX];
  size_t snapshot_count = 0U;

  pthread_mutex_lock(&host->lock);
  snapshot_count = host->eliza_memory_count;
  if (snapshot_count > SSH_CHATTER_ELIZA_MEMORY_MAX) {
    snapshot_count = SSH_CHATTER_ELIZA_MEMORY_MAX;
  }
  if (snapshot_count > 0U) {
    memcpy(snapshot, host->eliza_memory, snapshot_count * sizeof(snapshot[0]));
  }
  pthread_mutex_unlock(&host->lock);

  if (snapshot_count == 0U) {
    return 0U;
  }

  char tokens[SSH_CHATTER_ELIZA_TOKEN_LIMIT][32];
  size_t token_count = host_eliza_memory_collect_tokens(prompt, tokens, SSH_CHATTER_ELIZA_TOKEN_LIMIT);

  size_t best_indices[SSH_CHATTER_ELIZA_CONTEXT_LIMIT] = {0U};
  size_t best_scores[SSH_CHATTER_ELIZA_CONTEXT_LIMIT] = {0U};
  size_t best_count = 0U;

  for (size_t idx = 0U; idx < snapshot_count; ++idx) {
    const eliza_memory_entry_t *entry = &snapshot[idx];
    size_t score = 0U;

    if (token_count > 0U) {
      for (size_t token_idx = 0U; token_idx < token_count; ++token_idx) {
        if (tokens[token_idx][0] == '\0') {
          continue;
        }
        if (string_contains_case_insensitive(entry->prompt, tokens[token_idx]) ||
            string_contains_case_insensitive(entry->reply, tokens[token_idx])) {
          ++score;
        }
      }

      if (score == 0U) {
        continue;
      }
    }

    size_t recency_bonus = snapshot_count - idx;
    if (recency_bonus > 4U) {
      recency_bonus = 4U;
    }
    score += recency_bonus;

    size_t insert_pos = best_count;
    if (best_count < SSH_CHATTER_ELIZA_CONTEXT_LIMIT) {
      ++best_count;
    } else if (score <= best_scores[SSH_CHATTER_ELIZA_CONTEXT_LIMIT - 1U]) {
      continue;
    } else {
      insert_pos = SSH_CHATTER_ELIZA_CONTEXT_LIMIT - 1U;
    }

    while (insert_pos > 0U && score > best_scores[insert_pos - 1U]) {
      if (insert_pos < SSH_CHATTER_ELIZA_CONTEXT_LIMIT) {
        best_scores[insert_pos] = best_scores[insert_pos - 1U];
        best_indices[insert_pos] = best_indices[insert_pos - 1U];
      }
      --insert_pos;
    }

    best_scores[insert_pos] = score;
    best_indices[insert_pos] = idx;
  }

  if (best_count == 0U && token_count == 0U) {
    size_t fallback = snapshot_count < SSH_CHATTER_ELIZA_CONTEXT_LIMIT ? snapshot_count : SSH_CHATTER_ELIZA_CONTEXT_LIMIT;
    for (size_t idx = 0U; idx < fallback; ++idx) {
      best_indices[idx] = snapshot_count - idx - 1U;
    }
    best_count = fallback;
  }

  if (best_count == 0U) {
    return 0U;
  }

  size_t offset = 0U;
  for (size_t idx = 0U; idx < best_count; ++idx) {
    const eliza_memory_entry_t *entry = &snapshot[best_indices[idx]];
    char time_buffer[32];
    time_buffer[0] = '\0';
    if (entry->stored_at != 0) {
      struct tm tm_value;
      if (localtime_r(&entry->stored_at, &tm_value) != NULL) {
        strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M", &tm_value);
      }
    }
    if (time_buffer[0] == '\0') {
      snprintf(time_buffer, sizeof(time_buffer), "-");
    }

    char block[SSH_CHATTER_MESSAGE_LIMIT * 2];
    int written = snprintf(block, sizeof(block), "%s- [%s] user: %s\n  eliza: %s", idx == 0U ? "" : "\n",
                           time_buffer,
                           entry->prompt[0] != '\0' ? entry->prompt : "(empty)",
                           entry->reply[0] != '\0' ? entry->reply : "(empty)");
    if (written < 0) {
      continue;
    }

    size_t block_len = (size_t)written;
    if (block_len >= sizeof(block)) {
      block_len = sizeof(block) - 1U;
      block[block_len] = '\0';
    }

    if (offset + block_len >= context_length) {
      size_t available = (offset < context_length) ? context_length - offset - 1U : 0U;
      if (available > 0U) {
        memcpy(context + offset, block, available);
        offset += available;
        context[offset] = '\0';
      }
      break;
    }

    memcpy(context + offset, block, block_len);
    offset += block_len;
    context[offset] = '\0';
  }

  return best_count;
}

static void host_eliza_history_normalize_line(char *text) {
  if (text == NULL) {
    return;
  }

  size_t read_index = 0U;
  size_t write_index = 0U;
  bool last_was_space = true;

  while (text[read_index] != '\0') {
    unsigned char ch = (unsigned char)text[read_index++];
    if (ch < 0x20U || ch == 0x7FU) {
      ch = ' ';
    }

    if (ch == ' ') {
      if (last_was_space) {
        continue;
      }
      text[write_index++] = ' ';
      last_was_space = true;
      continue;
    }

    text[write_index++] = (char)ch;
    last_was_space = false;
  }

  if (write_index > 0U && text[write_index - 1U] == ' ') {
    --write_index;
  }

  text[write_index] = '\0';
}

static size_t host_eliza_history_collect_context(host_t *host, char *context, size_t context_length) {
  if (context == NULL || context_length == 0U) {
    return 0U;
  }

  context[0] = '\0';
  if (host == NULL) {
    return 0U;
  }

  size_t total = host_history_total(host);
  if (total == 0U) {
    return 0U;
  }

  size_t start_index = 0U;
  if (total > SSH_CHATTER_ELIZA_HISTORY_WINDOW) {
    start_index = total - SSH_CHATTER_ELIZA_HISTORY_WINDOW;
  }

  chat_history_entry_t snapshot[SSH_CHATTER_ELIZA_HISTORY_WINDOW];
  size_t retrieved = host_history_copy_range(host, start_index, snapshot, SSH_CHATTER_ELIZA_HISTORY_WINDOW);
  if (retrieved == 0U) {
    return 0U;
  }

  char messages[SSH_CHATTER_ELIZA_HISTORY_LIMIT][SSH_CHATTER_MESSAGE_LIMIT];
  char names[SSH_CHATTER_ELIZA_HISTORY_LIMIT][SSH_CHATTER_USERNAME_LEN];
  size_t collected = 0U;

  for (size_t idx = 0U; idx < retrieved && collected < SSH_CHATTER_ELIZA_HISTORY_LIMIT; ++idx) {
    size_t current = retrieved - idx - 1U;
    const chat_history_entry_t *entry = &snapshot[current];
    if (!entry->is_user_message) {
      continue;
    }

    char working[SSH_CHATTER_MESSAGE_LIMIT * 2U];
    working[0] = '\0';
    if (entry->message[0] != '\0') {
      snprintf(working, sizeof(working), "%s", entry->message);
    } else if (entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(working, sizeof(working), "shared a %s", label != NULL ? label : "attachment");
    }

    if (entry->attachment_caption[0] != '\0') {
      size_t existing = strnlen(working, sizeof(working));
      if (existing < sizeof(working) - 1U) {
        int appended = snprintf(working + existing, sizeof(working) - existing, "%s(caption: %s)",
                                existing > 0U ? " " : "", entry->attachment_caption);
        if (appended < 0) {
          working[existing] = '\0';
        }
      }
    } else if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      size_t existing = strnlen(working, sizeof(working));
      if (existing < sizeof(working) - 1U) {
        int appended = snprintf(working + existing, sizeof(working) - existing, "%s(link shared)",
                                existing > 0U ? " " : "");
        if (appended < 0) {
          working[existing] = '\0';
        }
      }
    }

    host_eliza_history_normalize_line(working);
    trim_whitespace_inplace(working);

    if (working[0] == '\0') {
      continue;
    }

    snprintf(messages[collected], sizeof(messages[collected]), "%s", working);
    if (entry->username[0] != '\0') {
      snprintf(names[collected], sizeof(names[collected]), "%s", entry->username);
    } else {
      snprintf(names[collected], sizeof(names[collected]), "%s", "unknown");
    }
    ++collected;
  }

  if (collected == 0U) {
    return 0U;
  }

  size_t offset = 0U;
  for (size_t idx = 0U; idx < collected; ++idx) {
    size_t source = collected - idx - 1U;
    const char *name = names[source][0] != '\0' ? names[source] : "unknown";
    const char *message = messages[source];

    char line[SSH_CHATTER_MESSAGE_LIMIT * 2U];
    int written = snprintf(line, sizeof(line), "%s- [%s] %s", offset == 0U ? "" : "\n", name, message);
    if (written < 0) {
      continue;
    }

    size_t line_length = (size_t)written;
    if (line_length >= sizeof(line)) {
      line_length = sizeof(line) - 1U;
      line[line_length] = '\0';
    }

    size_t remaining = (offset < context_length) ? context_length - offset : 0U;
    if (remaining <= 1U) {
      context[context_length - 1U] = '\0';
      break;
    }

    size_t max_append = remaining - 1U;
    if (line_length > max_append) {
      memcpy(context + offset, line, max_append);
      offset += max_append;
      context[offset] = '\0';
      break;
    }

    memcpy(context + offset, line, line_length);
    offset += line_length;
    context[offset] = '\0';
  }

  return collected;
}

static void host_eliza_prepare_preview(const char *source, char *dest, size_t dest_length) {
  if (dest == NULL || dest_length == 0U) {
    return;
  }

  dest[0] = '\0';
  if (source == NULL || source[0] == '\0') {
    return;
  }

  size_t copy_length = strnlen(source, dest_length);
  bool truncated = false;
  if (copy_length >= dest_length) {
    copy_length = dest_length - 1U;
    truncated = true;
  }

  memcpy(dest, source, copy_length);
  dest[copy_length] = '\0';

  host_eliza_history_normalize_line(dest);
  trim_whitespace_inplace(dest);

  if (truncated && dest_length > 4U) {
    size_t length = strnlen(dest, dest_length);
    if (length + 3U < dest_length) {
      dest[length++] = '.';
      dest[length++] = '.';
      dest[length++] = '.';
      dest[length] = '\0';
    }
  }
}

static size_t host_eliza_bbs_collect_context(host_t *host, char *context, size_t context_length) {
  if (context == NULL || context_length == 0U) {
    return 0U;
  }

  context[0] = '\0';
  if (host == NULL) {
    return 0U;
  }

  bbs_post_t snapshot[SSH_CHATTER_BBS_MAX_POSTS];
  size_t snapshot_count = 0U;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (!host->bbs_posts[idx].in_use) {
      continue;
    }

    if (snapshot_count < SSH_CHATTER_BBS_MAX_POSTS) {
      snapshot[snapshot_count++] = host->bbs_posts[idx];
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (snapshot_count == 0U) {
    return 0U;
  }

  for (size_t idx = 0U; idx + 1U < snapshot_count; ++idx) {
    size_t best = idx;
    time_t best_time = snapshot[idx].bumped_at != 0 ? snapshot[idx].bumped_at : snapshot[idx].created_at;
    for (size_t scan = idx + 1U; scan < snapshot_count; ++scan) {
      time_t candidate = snapshot[scan].bumped_at != 0 ? snapshot[scan].bumped_at : snapshot[scan].created_at;
      if (candidate > best_time) {
        best = scan;
        best_time = candidate;
      }
    }
    if (best != idx) {
      bbs_post_t temp = snapshot[idx];
      snapshot[idx] = snapshot[best];
      snapshot[best] = temp;
    }
  }

  size_t limit = snapshot_count;
  if (limit > SSH_CHATTER_ELIZA_BBS_CONTEXT_LIMIT) {
    limit = SSH_CHATTER_ELIZA_BBS_CONTEXT_LIMIT;
  }

  size_t offset = 0U;
  size_t appended_count = 0U;
  for (size_t idx = 0U; idx < limit; ++idx) {
    const bbs_post_t *post = &snapshot[idx];

    char title[SSH_CHATTER_BBS_TITLE_LEN];
    snprintf(title, sizeof(title), "%s", post->title[0] != '\0' ? post->title : "(untitled)");
    host_eliza_history_normalize_line(title);
    trim_whitespace_inplace(title);

    char tags_buffer[SSH_CHATTER_BBS_MAX_TAGS * (SSH_CHATTER_BBS_TAG_LEN + 2U)];
    size_t tags_offset = 0U;
    tags_buffer[0] = '\0';
    for (size_t tag = 0U; tag < post->tag_count && tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
      if (post->tags[tag][0] == '\0') {
        continue;
      }
      if (tags_offset + 1U < sizeof(tags_buffer)) {
        if (tags_offset > 0U) {
          tags_buffer[tags_offset++] = ',';
        }
        size_t remaining = sizeof(tags_buffer) - tags_offset;
        size_t tag_length = strnlen(post->tags[tag], remaining);
        if (tag_length >= remaining) {
          tag_length = remaining - 1U;
        }
        memcpy(tags_buffer + tags_offset, post->tags[tag], tag_length);
        tags_offset += tag_length;
        tags_buffer[tags_offset] = '\0';
      }
    }

    char body_preview[SSH_CHATTER_ELIZA_BBS_PREVIEW_LEN];
    host_eliza_prepare_preview(post->body, body_preview, sizeof(body_preview));

    char comment_preview[SSH_CHATTER_ELIZA_BBS_PREVIEW_LEN];
    comment_preview[0] = '\0';
    char comment_author[SSH_CHATTER_USERNAME_LEN];
    comment_author[0] = '\0';
    if (post->comment_count > 0U) {
      const bbs_comment_t *comment = &post->comments[post->comment_count - 1U];
      host_eliza_prepare_preview(comment->text, comment_preview, sizeof(comment_preview));
      snprintf(comment_author, sizeof(comment_author), "%s", comment->author[0] != '\0' ? comment->author : "(anonymous)");
      host_eliza_history_normalize_line(comment_author);
      trim_whitespace_inplace(comment_author);
    }

    char line[SSH_CHATTER_MESSAGE_LIMIT];
    size_t line_offset = 0U;
    int written = snprintf(line, sizeof(line), "%s- [#%" PRIu64 " %s] %s",
                           idx == 0U ? "" : "\n",
                           post->id,
                           post->author[0] != '\0' ? post->author : "(unknown)",
                           title[0] != '\0' ? title : "(untitled)");
    if (written < 0) {
      continue;
    }

    line_offset = (size_t)written;
    if (line_offset >= sizeof(line)) {
      line_offset = sizeof(line) - 1U;
      line[line_offset] = '\0';
    }

    if (tags_buffer[0] != '\0' && line_offset + 1U < sizeof(line)) {
      int appended = snprintf(line + line_offset, sizeof(line) - line_offset, " | tags: %s", tags_buffer);
      if (appended > 0) {
        size_t used = (size_t)appended;
        if (used >= sizeof(line) - line_offset) {
          line_offset = sizeof(line) - 1U;
          line[line_offset] = '\0';
        } else {
          line_offset += used;
        }
      }
    }

    if (body_preview[0] != '\0' && line_offset + 1U < sizeof(line)) {
      int appended = snprintf(line + line_offset, sizeof(line) - line_offset, " | body: %s", body_preview);
      if (appended > 0) {
        size_t used = (size_t)appended;
        if (used >= sizeof(line) - line_offset) {
          line_offset = sizeof(line) - 1U;
          line[line_offset] = '\0';
        } else {
          line_offset += used;
        }
      }
    }

    if (comment_preview[0] != '\0' && line_offset + 1U < sizeof(line)) {
      const char *author_label = comment_author[0] != '\0' ? comment_author : "(anonymous)";
      int appended = snprintf(line + line_offset, sizeof(line) - line_offset, " | last comment by %s: %s", author_label,
                               comment_preview);
      if (appended > 0) {
        size_t used = (size_t)appended;
        if (used >= sizeof(line) - line_offset) {
          line_offset = sizeof(line) - 1U;
          line[line_offset] = '\0';
        } else {
          line_offset += used;
        }
      }
    }

    size_t remaining = (offset < context_length) ? context_length - offset : 0U;
    if (remaining <= 1U) {
      context[context_length - 1U] = '\0';
      break;
    }

    size_t max_copy = remaining - 1U;
    size_t copy_len = strnlen(line, sizeof(line));
    if (copy_len > max_copy) {
      memcpy(context + offset, line, max_copy);
      offset += max_copy;
      context[offset] = '\0';
      ++appended_count;
      break;
    }

    memcpy(context + offset, line, copy_len);
    offset += copy_len;
    context[offset] = '\0';
    ++appended_count;
  }

  if (context[0] == '\0') {
    return 0U;
  }

  if (appended_count == 0U) {
    return 0U;
  }

  return appended_count;
}

static void host_bbs_resolve_path(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *bbs_path = getenv("CHATTER_BBS_FILE");
  if (bbs_path == NULL || bbs_path[0] == '\0') {
    bbs_path = "bbs_state.dat";
  }

  int written = snprintf(host->bbs_state_file_path, sizeof(host->bbs_state_file_path), "%s", bbs_path);
  if (written < 0 || (size_t)written >= sizeof(host->bbs_state_file_path)) {
    humanized_log_error("host", "bbs state file path is too long", ENAMETOOLONG);
    host->bbs_state_file_path[0] = '\0';
  }
}

static size_t host_column_reset_sequence_length(const char *text) {
  if (text == NULL) {
    return 0U;
  }

  if (text[0] == '\033' && text[1] == '[' && text[2] == '1' && text[3] == 'G') {
    return 4U;
  }

  if (text[0] == '[' && text[1] == '1' && text[2] == 'G') {
    return 3U;
  }

  return 0U;
}

static bool host_contains_column_reset(const char *text) {
  if (text == NULL) {
    return false;
  }

  while (*text != '\0') {
    if (host_column_reset_sequence_length(text) > 0U) {
      return true;
    }
    ++text;
  }

  return false;
}

static void host_strip_column_reset(char *text) {
  if (text == NULL || text[0] == '\0') {
    return;
  }

  char *dst = text;
  const char *src = text;
  while (*src != '\0') {
    size_t skip = host_column_reset_sequence_length(src);
    if (skip > 0U) {
      src += skip;
      continue;
    }

    *dst++ = *src++;
  }

  *dst = '\0';
}

static void host_bbs_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->bbs_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->bbs_state_file_path, true)) {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->bbs_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "bbs state file path is too long", ENAMETOOLONG);
    return;
  }

  int temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
  if (temp_fd < 0) {
    humanized_log_error("host", "failed to open bbs state file", errno != 0 ? errno : EIO);
    return;
  }

  FILE *fp = fdopen(temp_fd, "wb");
  if (fp == NULL) {
    int saved_errno = errno;
    close(temp_fd);
    unlink(temp_path);
    humanized_log_error("host", "failed to wrap bbs state descriptor", saved_errno != 0 ? saved_errno : EIO);
    return;
  }

  uint32_t post_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (host->bbs_posts[idx].in_use) {
      ++post_count;
    }
  }

  bbs_state_header_t header = {0};
  header.magic = BBS_STATE_MAGIC;
  header.version = BBS_STATE_VERSION;
  header.post_count = post_count;
  header.next_id = host->next_bbs_id;

  bool success = fwrite(&header, sizeof(header), 1U, fp) == 1U;

  for (size_t idx = 0U; success && idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    const bbs_post_t *post = &host->bbs_posts[idx];
    if (!post->in_use) {
      continue;
    }

    bbs_state_post_entry_t serialized = {0};
    serialized.id = post->id;
    serialized.created_at = (int64_t)post->created_at;
    serialized.bumped_at = (int64_t)post->bumped_at;
    serialized.tag_count = (uint32_t)post->tag_count;
    if (serialized.tag_count > SSH_CHATTER_BBS_MAX_TAGS) {
      serialized.tag_count = SSH_CHATTER_BBS_MAX_TAGS;
    }
    serialized.comment_count = (uint32_t)post->comment_count;
    if (serialized.comment_count > SSH_CHATTER_BBS_MAX_COMMENTS) {
      serialized.comment_count = SSH_CHATTER_BBS_MAX_COMMENTS;
    }

    snprintf(serialized.author, sizeof(serialized.author), "%s", post->author);
    snprintf(serialized.title, sizeof(serialized.title), "%s", post->title);
    snprintf(serialized.body, sizeof(serialized.body), "%s", post->body);

    for (size_t tag = 0U; tag < serialized.tag_count; ++tag) {
      snprintf(serialized.tags[tag], sizeof(serialized.tags[tag]), "%s", post->tags[tag]);
    }

    for (size_t comment = 0U; comment < serialized.comment_count; ++comment) {
      snprintf(serialized.comments[comment].author, sizeof(serialized.comments[comment].author), "%s",
               post->comments[comment].author);
      snprintf(serialized.comments[comment].text, sizeof(serialized.comments[comment].text), "%s",
               post->comments[comment].text);
      serialized.comments[comment].created_at = (int64_t)post->comments[comment].created_at;
    }

    if (fwrite(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      break;
    }
  }

  if (success && fflush(fp) != 0) {
    success = false;
  }

  if (success) {
    int file_descriptor = fileno(fp);
    if (file_descriptor >= 0 && fsync(file_descriptor) != 0) {
      success = false;
    }
  }

  if (fclose(fp) != 0) {
    success = false;
  }

  if (!success) {
    humanized_log_error("host", "failed to write bbs state file", errno);
    unlink(temp_path);
    return;
  }

  if (chmod(temp_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to tighten temporary bbs state permissions", errno != 0 ? errno : EACCES);
    unlink(temp_path);
    return;
  }

  if (rename(temp_path, host->bbs_state_file_path) != 0) {
    humanized_log_error("host", "failed to update bbs state file", errno);
    unlink(temp_path);
  } else if (chmod(host->bbs_state_file_path, S_IRUSR | S_IWUSR) != 0) {
    humanized_log_error("host", "failed to tighten bbs state permissions", errno != 0 ? errno : EACCES);
  }
}

static void host_bbs_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->bbs_state_file_path[0] == '\0') {
    return;
  }

  if (!host_ensure_private_data_path(host, host->bbs_state_file_path, false)) {
    return;
  }

  FILE *fp = fopen(host->bbs_state_file_path, "rb");
  if (fp == NULL) {
    return;
  }

  bbs_state_header_t header = {0};
  if (fread(&header, sizeof(header), 1U, fp) != 1U) {
    fclose(fp);
    return;
  }

  if (header.magic != BBS_STATE_MAGIC) {
    fclose(fp);
    return;
  }

  if (header.version == 0U || header.version > BBS_STATE_VERSION) {
    fclose(fp);
    return;
  }

  pthread_mutex_lock(&host->lock);

  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    host->bbs_posts[idx].in_use = false;
    host->bbs_posts[idx].id = 0U;
    host->bbs_posts[idx].author[0] = '\0';
    host->bbs_posts[idx].title[0] = '\0';
    host->bbs_posts[idx].body[0] = '\0';
    host->bbs_posts[idx].tag_count = 0U;
    host->bbs_posts[idx].created_at = 0;
    host->bbs_posts[idx].bumped_at = 0;
    host->bbs_posts[idx].comment_count = 0U;
    for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
      host->bbs_posts[idx].comments[comment].author[0] = '\0';
      host->bbs_posts[idx].comments[comment].text[0] = '\0';
      host->bbs_posts[idx].comments[comment].created_at = 0;
    }
  }
  host->bbs_post_count = 0U;

  uint64_t max_id = 0U;
  bool success = true;

  for (uint32_t idx = 0U; idx < header.post_count; ++idx) {
    bbs_state_post_entry_t serialized = {0};
    if (header.version == 1U) {
      bbs_state_post_entry_v1_t legacy = {0};
      if (fread(&legacy, sizeof(legacy), 1U, fp) != 1U) {
        success = false;
        break;
      }

      serialized.id = legacy.id;
      serialized.created_at = legacy.created_at;
      serialized.bumped_at = legacy.bumped_at;
      serialized.tag_count = legacy.tag_count;
      serialized.comment_count = legacy.comment_count;
      snprintf(serialized.author, sizeof(serialized.author), "%s", legacy.author);
      snprintf(serialized.title, sizeof(serialized.title), "%s", legacy.title);
      snprintf(serialized.body, sizeof(serialized.body), "%s", legacy.body);
      for (size_t tag = 0U; tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
        snprintf(serialized.tags[tag], sizeof(serialized.tags[tag]), "%s", legacy.tags[tag]);
      }
      for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
        snprintf(serialized.comments[comment].author, sizeof(serialized.comments[comment].author), "%s",
                 legacy.comments[comment].author);
        snprintf(serialized.comments[comment].text, sizeof(serialized.comments[comment].text), "%s",
                 legacy.comments[comment].text);
        serialized.comments[comment].created_at = legacy.comments[comment].created_at;
      }
    } else if (header.version == 2U) {
      bbs_state_post_entry_v2_t legacy = {0};
      if (fread(&legacy, sizeof(legacy), 1U, fp) != 1U) {
        success = false;
        break;
      }

      serialized.id = legacy.id;
      serialized.created_at = legacy.created_at;
      serialized.bumped_at = legacy.bumped_at;
      serialized.tag_count = legacy.tag_count;
      serialized.comment_count = legacy.comment_count;
      snprintf(serialized.author, sizeof(serialized.author), "%s", legacy.author);
      snprintf(serialized.title, sizeof(serialized.title), "%s", legacy.title);
      snprintf(serialized.body, sizeof(serialized.body), "%s", legacy.body);
      for (size_t tag = 0U; tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
        snprintf(serialized.tags[tag], sizeof(serialized.tags[tag]), "%s", legacy.tags[tag]);
      }
      for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
        snprintf(serialized.comments[comment].author, sizeof(serialized.comments[comment].author), "%s",
                 legacy.comments[comment].author);
        snprintf(serialized.comments[comment].text, sizeof(serialized.comments[comment].text), "%s",
                 legacy.comments[comment].text);
        serialized.comments[comment].created_at = legacy.comments[comment].created_at;
      }
    } else {
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }
    }

    if (serialized.id > max_id) {
      max_id = serialized.id;
    }

    if (idx >= SSH_CHATTER_BBS_MAX_POSTS) {
      continue;
    }

    bbs_post_t *post = &host->bbs_posts[host->bbs_post_count];
    memset(post, 0, sizeof(*post));
    post->in_use = true;
    post->id = serialized.id;
    post->created_at = (time_t)serialized.created_at;
    post->bumped_at = (time_t)serialized.bumped_at;
    snprintf(post->author, sizeof(post->author), "%s", serialized.author);
    snprintf(post->title, sizeof(post->title), "%s", serialized.title);
    snprintf(post->body, sizeof(post->body), "%s", serialized.body);
    host_strip_column_reset(post->author);
    host_strip_column_reset(post->title);
    host_strip_column_reset(post->body);

    size_t tag_limit = serialized.tag_count;
    if (tag_limit > SSH_CHATTER_BBS_MAX_TAGS) {
      tag_limit = SSH_CHATTER_BBS_MAX_TAGS;
    }
    post->tag_count = tag_limit;
    for (size_t tag = 0U; tag < tag_limit; ++tag) {
      snprintf(post->tags[tag], sizeof(post->tags[tag]), "%s", serialized.tags[tag]);
      host_strip_column_reset(post->tags[tag]);
    }

    size_t comment_limit = serialized.comment_count;
    if (comment_limit > SSH_CHATTER_BBS_MAX_COMMENTS) {
      comment_limit = SSH_CHATTER_BBS_MAX_COMMENTS;
    }
    post->comment_count = comment_limit;
    for (size_t comment = 0U; comment < comment_limit; ++comment) {
      snprintf(post->comments[comment].author, sizeof(post->comments[comment].author), "%s",
               serialized.comments[comment].author);
      snprintf(post->comments[comment].text, sizeof(post->comments[comment].text), "%s",
               serialized.comments[comment].text);
      post->comments[comment].created_at = (time_t)serialized.comments[comment].created_at;
      host_strip_column_reset(post->comments[comment].author);
      host_strip_column_reset(post->comments[comment].text);
    }

    ++host->bbs_post_count;
  }

  if (success) {
    host->next_bbs_id = header.next_id;
    if (host->next_bbs_id == 0U || host->next_bbs_id <= max_id) {
      host->next_bbs_id = max_id + 1U;
    }
  } else {
    for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
      host->bbs_posts[idx].in_use = false;
      host->bbs_posts[idx].id = 0U;
      host->bbs_posts[idx].author[0] = '\0';
      host->bbs_posts[idx].title[0] = '\0';
      host->bbs_posts[idx].body[0] = '\0';
      host->bbs_posts[idx].tag_count = 0U;
      host->bbs_posts[idx].created_at = 0;
      host->bbs_posts[idx].bumped_at = 0;
      host->bbs_posts[idx].comment_count = 0U;
      for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
        host->bbs_posts[idx].comments[comment].author[0] = '\0';
        host->bbs_posts[idx].comments[comment].text[0] = '\0';
        host->bbs_posts[idx].comments[comment].created_at = 0;
      }
    }
    host->bbs_post_count = 0U;
    host->next_bbs_id = 1U;
  }

  pthread_mutex_unlock(&host->lock);
  fclose(fp);
}

static void host_bbs_watchdog_scan(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (!atomic_load(&host->eliza_enabled)) {
    return;
  }

  if (!atomic_load(&host->security_ai_enabled)) {
    return;
  }

  bbs_post_t snapshot[SSH_CHATTER_BBS_MAX_POSTS];
  size_t snapshot_count = 0U;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (!host->bbs_posts[idx].in_use) {
      continue;
    }

    if (snapshot_count < SSH_CHATTER_BBS_MAX_POSTS) {
      snapshot[snapshot_count++] = host->bbs_posts[idx];
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (snapshot_count == 0U) {
    return;
  }

  for (size_t idx = 0U; idx < snapshot_count; ++idx) {
    const bbs_post_t *post = &snapshot[idx];

    char content[SSH_CHATTER_BBS_BODY_LEN +
                 (SSH_CHATTER_BBS_COMMENT_LEN * SSH_CHATTER_BBS_MAX_COMMENTS) + 1024U];
    int written = snprintf(content, sizeof(content),
                          "Title: %s\nTags: ",
                          post->title[0] != '\0' ? post->title : "(untitled)");
    if (written < 0) {
      continue;
    }

    size_t offset = (size_t)written;
    if (offset >= sizeof(content)) {
      offset = sizeof(content) - 1U;
    }

    for (size_t tag = 0U; tag < post->tag_count; ++tag) {
      const char *prefix = (tag == 0U) ? "" : ",";
      int tag_written = snprintf(content + offset, sizeof(content) - offset, "%s%s", prefix,
                                 post->tags[tag]);
      if (tag_written < 0) {
        break;
      }
      offset += (size_t)tag_written;
      if (offset >= sizeof(content)) {
        offset = sizeof(content) - 1U;
        break;
      }
    }

    if (offset + 2U < sizeof(content)) {
      content[offset++] = '\n';
      content[offset++] = '\n';
      content[offset] = '\0';
    } else {
      content[sizeof(content) - 1U] = '\0';
      offset = sizeof(content) - 1U;
    }

    int body_written = snprintf(content + offset, sizeof(content) - offset,
                                "Body:\n%s",
                                post->body[0] != '\0' ? post->body : "(empty)");
    if (body_written < 0) {
      continue;
    }
    offset += (size_t)body_written;
    if (offset >= sizeof(content)) {
      offset = sizeof(content) - 1U;
    }

    for (size_t comment = 0U; comment < post->comment_count; ++comment) {
      if (offset + 2U >= sizeof(content)) {
        break;
      }
      content[offset++] = '\n';
      content[offset++] = '\n';
      content[offset] = '\0';

      const bbs_comment_t *entry = &post->comments[comment];
      int comment_written = snprintf(content + offset, sizeof(content) - offset,
                                     "Comment by %s:\n%s",
                                     entry->author[0] != '\0' ? entry->author : "(anonymous)",
                                     entry->text[0] != '\0' ? entry->text : "(empty)");
      if (comment_written < 0) {
        break;
      }
      offset += (size_t)comment_written;
      if (offset >= sizeof(content)) {
        offset = sizeof(content) - 1U;
        break;
      }
    }

    bool blocked = false;
    char reason[256];
    reason[0] = '\0';
    if (!translator_moderate_text("bbs_post", content, &blocked, reason, sizeof(reason))) {
      const char *error = translator_last_error();
      if (error != NULL && error[0] != '\0') {
        printf("[bbs] moderation unavailable for post #%" PRIu64 ": %s\n", post->id, error);
      } else {
        printf("[bbs] moderation unavailable for post #%" PRIu64 "\n", post->id);
      }
      break;
    }

    if (!blocked) {
      continue;
    }

    trim_whitespace_inplace(reason);
    const char *diagnostic = (reason[0] != '\0') ? reason : "policy violation";

    pthread_mutex_lock(&host->lock);
    bbs_post_t *live = host_find_bbs_post_locked(host, post->id);
    if (live != NULL) {
      host_clear_bbs_post_locked(host, live);
      host_bbs_state_save_locked(host);
    }
    pthread_mutex_unlock(&host->lock);

    if (live == NULL) {
      continue;
    }

    printf("[bbs] removed post #%" PRIu64 " by %s (%s)\n", post->id,
           post->author[0] != '\0' ? post->author : "unknown", diagnostic);

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice),
             "* [eliza] removed BBS post #%" PRIu64 " by %s (%s).",
             post->id,
             post->author[0] != '\0' ? post->author : "unknown",
             diagnostic);
    host_history_record_system(host, notice);
    chat_room_broadcast(&host->room, notice, NULL);
  }

}

static void *host_bbs_watchdog_thread(void *arg) {
  host_t *host = (host_t *)arg;
  if (host == NULL) {
    return NULL;
  }

  atomic_store(&host->bbs_watchdog_thread_running, true);
  printf("[bbs] watchdog thread started\n");

  while (!atomic_load(&host->bbs_watchdog_thread_stop)) {
    host_bbs_watchdog_scan(host);

    clock_gettime(CLOCK_MONOTONIC, &host->bbs_watchdog_last_run);

    unsigned int remaining = SSH_CHATTER_BBS_REVIEW_INTERVAL_SECONDS;
    while (remaining > 0U && !atomic_load(&host->bbs_watchdog_thread_stop)) {
      unsigned int chunk = remaining > SSH_CHATTER_BBS_WATCHDOG_SLEEP_SECONDS
                               ? SSH_CHATTER_BBS_WATCHDOG_SLEEP_SECONDS
                               : remaining;
      struct timespec pause = {
          .tv_sec = (time_t)chunk,
          .tv_nsec = 0L,
      };
      nanosleep(&pause, NULL);
      if (remaining <= chunk) {
        remaining = 0U;
      } else {
        remaining -= chunk;
      }
    }
  }

  atomic_store(&host->bbs_watchdog_thread_running, false);
  printf("[bbs] watchdog thread stopped\n");
  return NULL;
}

static void host_bbs_start_watchdog(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->bbs_watchdog_thread_initialized) {
    return;
  }

  atomic_store(&host->bbs_watchdog_thread_stop, false);
  atomic_store(&host->bbs_watchdog_thread_running, false);

  int error = pthread_create(&host->bbs_watchdog_thread, NULL, host_bbs_watchdog_thread, host);
  if (error != 0) {
    printf("[bbs] failed to start watchdog thread: %s\n", strerror(error));
    return;
  }

  host->bbs_watchdog_thread_initialized = true;
}
static void session_apply_saved_preferences(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  user_preference_t snapshot = (user_preference_t){0};
  bool has_snapshot = false;

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_find_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    snapshot = *pref;
    has_snapshot = true;
  }
  pthread_mutex_unlock(&host->lock);

  ctx->translation_caption_spacing = 0U;
  ctx->translation_enabled = false;
  ctx->output_translation_enabled = false;
  ctx->output_translation_language[0] = '\0';
  ctx->input_translation_enabled = false;
  ctx->input_translation_language[0] = '\0';
  ctx->last_detected_input_language[0] = '\0';

  if (has_snapshot) {
    if (snapshot.has_user_theme) {
      const char *color_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                                 snapshot.user_color_name);
      const char *highlight_code = lookup_color_code(
          HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), snapshot.user_highlight_name);
      if (color_code != NULL && highlight_code != NULL) {
        ctx->user_color_code = color_code;
        ctx->user_highlight_code = highlight_code;
        ctx->user_is_bold = snapshot.user_is_bold;
        snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", snapshot.user_color_name);
        snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", snapshot.user_highlight_name);
      }
    }

    if (snapshot.has_system_theme) {
      const char *fg_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]),
                                              snapshot.system_fg_name);
      const char *bg_code = lookup_color_code(
          HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), snapshot.system_bg_name);
      if (fg_code != NULL && bg_code != NULL) {
        const char *highlight_code = ctx->system_highlight_code;
        if (snapshot.system_highlight_name[0] != '\0') {
          const char *candidate = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                   sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                   snapshot.system_highlight_name);
          if (candidate != NULL) {
            highlight_code = candidate;
          }
        }

        ctx->system_fg_code = fg_code;
        ctx->system_bg_code = bg_code;
        ctx->system_highlight_code = highlight_code;
        ctx->system_is_bold = snapshot.system_is_bold;
        snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", snapshot.system_fg_name);
        snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", snapshot.system_bg_name);
        if (snapshot.system_highlight_name[0] != '\0') {
          snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s",
                   snapshot.system_highlight_name);
        }
      }
    }

    if (snapshot.os_name[0] != '\0') {
      snprintf(ctx->os_name, sizeof(ctx->os_name), "%s", snapshot.os_name);
    }
    ctx->daily_year = snapshot.daily_year;
    ctx->daily_yday = snapshot.daily_yday;
    if (snapshot.daily_function[0] != '\0') {
      snprintf(ctx->daily_function, sizeof(ctx->daily_function), "%s", snapshot.daily_function);
    }
    ctx->has_birthday = snapshot.has_birthday;
    if (ctx->has_birthday) {
      snprintf(ctx->birthday, sizeof(ctx->birthday), "%s", snapshot.birthday);
    } else {
      ctx->birthday[0] = '\0';
    }

    ctx->translation_caption_spacing = snapshot.translation_caption_spacing;
    if (ctx->translation_caption_spacing > 8U) {
      ctx->translation_caption_spacing = 8U;
    }

    if (snapshot.translation_master_explicit) {
      ctx->translation_enabled = snapshot.translation_master_enabled;
    }

    ctx->output_translation_enabled = snapshot.output_translation_enabled;
    snprintf(ctx->output_translation_language, sizeof(ctx->output_translation_language), "%s",
             snapshot.output_translation_language);
    ctx->input_translation_enabled = snapshot.input_translation_enabled;
    snprintf(ctx->input_translation_language, sizeof(ctx->input_translation_language), "%s",
             snapshot.input_translation_language);
  }

  (void)session_user_data_load(ctx);
  session_force_dark_mode_foreground(ctx);
}

static bool session_argument_is_disable(const char *token) {
  if (token == NULL) {
    return false;
  }

  return strcasecmp(token, "off") == 0 || strcasecmp(token, "none") == 0 || strcasecmp(token, "disable") == 0 ||
         strcasecmp(token, "stop") == 0;
}

static void session_language_normalize(const char *input, char *normalized, size_t length) {
  if (normalized == NULL || length == 0U) {
    return;
  }

  normalized[0] = '\0';
  if (input == NULL) {
    return;
  }

  size_t out_idx = 0U;
  for (size_t idx = 0U; input[idx] != '\0'; ++idx) {
    unsigned char ch = (unsigned char)input[idx];
    if (isspace(ch)) {
      continue;
    }

    char lowered = (char)tolower(ch);
    if (lowered == '_') {
      lowered = '-';
    }

    if (out_idx + 1U >= length) {
      break;
    }

    normalized[out_idx++] = lowered;
  }

  if (out_idx < length) {
    normalized[out_idx] = '\0';
  } else {
    normalized[length - 1U] = '\0';
  }
}

static bool session_language_equals(const char *lhs, const char *rhs) {
  if (lhs == NULL || rhs == NULL) {
    return false;
  }

  char normalized_lhs[SSH_CHATTER_LANG_NAME_LEN];
  char normalized_rhs[SSH_CHATTER_LANG_NAME_LEN];
  session_language_normalize(lhs, normalized_lhs, sizeof(normalized_lhs));
  session_language_normalize(rhs, normalized_rhs, sizeof(normalized_rhs));

  return strcmp(normalized_lhs, normalized_rhs) == 0;
}

typedef enum translation_job_type {
  TRANSLATION_JOB_CAPTION = 0,
  TRANSLATION_JOB_INPUT,
  TRANSLATION_JOB_PRIVATE_MESSAGE,
} translation_job_type_t;

typedef struct translation_job {
  translation_job_type_t type;
  char target_language[SSH_CHATTER_LANG_NAME_LEN];
  size_t placeholder_lines;
  struct translation_job *next;
  union {
    struct {
      char sanitized[SSH_CHATTER_TRANSLATION_WORKING_LEN];
      translation_placeholder_t placeholders[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
      size_t placeholder_count;
    } caption;
    struct {
      char original[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    } input;
    struct {
      char original[SSH_CHATTER_TRANSLATION_WORKING_LEN];
      char target_name[SSH_CHATTER_USERNAME_LEN];
      char to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
      char to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
    } pm;
  } data;
} translation_job_t;

typedef struct translation_result {
  translation_job_type_t type;
  bool success;
  size_t placeholder_lines;
  char translated[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  char detected_language[SSH_CHATTER_LANG_NAME_LEN];
  char original[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  char error_message[128];
  char pm_target_name[SSH_CHATTER_USERNAME_LEN];
  char pm_to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
  char pm_to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
  struct translation_result *next;
} translation_result_t;

static bool session_translation_worker_ensure(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (!ctx->translation_mutex_initialized) {
    if (pthread_mutex_init(&ctx->translation_mutex, NULL) != 0) {
      return false;
    }
    ctx->translation_mutex_initialized = true;
  }

  if (!ctx->translation_cond_initialized) {
    if (pthread_cond_init(&ctx->translation_cond, NULL) != 0) {
      pthread_mutex_destroy(&ctx->translation_mutex);
      ctx->translation_mutex_initialized = false;
      return false;
    }
    ctx->translation_cond_initialized = true;
  }

  if (!ctx->translation_thread_started) {
    ctx->translation_thread_stop = false;
    if (pthread_create(&ctx->translation_thread, NULL, session_translation_worker, ctx) != 0) {
      pthread_cond_destroy(&ctx->translation_cond);
      ctx->translation_cond_initialized = false;
      pthread_mutex_destroy(&ctx->translation_mutex);
      ctx->translation_mutex_initialized = false;
      return false;
    }
    ctx->translation_thread_started = true;
  }

  return true;
}

static void session_translation_clear_queue(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->translation_mutex_initialized) {
    return;
  }

  translation_job_t *pending = NULL;
  translation_result_t *ready = NULL;

  pthread_mutex_lock(&ctx->translation_mutex);
  pending = ctx->translation_pending_head;
  ctx->translation_pending_head = NULL;
  ctx->translation_pending_tail = NULL;
  ready = ctx->translation_ready_head;
  ctx->translation_ready_head = NULL;
  ctx->translation_ready_tail = NULL;
  pthread_mutex_unlock(&ctx->translation_mutex);

  while (pending != NULL) {
    translation_job_t *next = pending->next;
    free(pending);
    pending = next;
  }

  while (ready != NULL) {
    translation_result_t *next = ready->next;
    free(ready);
    ready = next;
  }

  ctx->translation_placeholder_active_lines = 0U;
}

static bool session_translation_queue_caption(session_ctx_t *ctx, const char *message, size_t placeholder_lines) {
  if (ctx == NULL || message == NULL) {
    return false;
  }

  char stripped[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  if (translation_strip_no_translate_prefix(message, stripped, sizeof(stripped))) {
    return false;
  }

  if (!ctx->translation_enabled || !ctx->output_translation_enabled ||
      ctx->output_translation_language[0] == '\0' || message[0] == '\0') {
    return false;
  }

  if (!session_translation_worker_ensure(ctx)) {
    return false;
  }

  translation_job_t *job = calloc(1U, sizeof(*job));
  if (job == NULL) {
    return false;
  }

  size_t placeholder_count = 0U;
  if (!translation_prepare_text(message, job->data.caption.sanitized, sizeof(job->data.caption.sanitized),
                                job->data.caption.placeholders, &placeholder_count)) {
    free(job);
    return false;
  }

  if (job->data.caption.sanitized[0] == '\0') {
    free(job);
    return false;
  }

  job->type = TRANSLATION_JOB_CAPTION;
  job->data.caption.placeholder_count = placeholder_count;
  job->placeholder_lines = placeholder_lines;
  snprintf(job->target_language, sizeof(job->target_language), "%s", ctx->output_translation_language);

  pthread_mutex_lock(&ctx->translation_mutex);
  job->next = NULL;
  if (ctx->translation_pending_tail != NULL) {
    ctx->translation_pending_tail->next = job;
  } else {
    ctx->translation_pending_head = job;
  }
  ctx->translation_pending_tail = job;
  pthread_cond_signal(&ctx->translation_cond);
  pthread_mutex_unlock(&ctx->translation_mutex);

  return true;
}

static void session_translation_reserve_placeholders(session_ctx_t *ctx, size_t placeholder_lines) {
  if (ctx == NULL || !session_transport_active(ctx) || placeholder_lines == 0U) {
    return;
  }

  for (size_t idx = 0U; idx < placeholder_lines; ++idx) {
    session_write_rendered_line(ctx, "");
  }

  if (SIZE_MAX - ctx->translation_placeholder_active_lines < placeholder_lines) {
    ctx->translation_placeholder_active_lines = SIZE_MAX;
  } else {
    ctx->translation_placeholder_active_lines += placeholder_lines;
  }

  if (ctx->history_scroll_position == 0U) {
    session_refresh_input_line(ctx);
  }
}

static bool session_translation_push_scope_override(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  bool previous = ctx->translation_manual_scope_override;
  ctx->translation_manual_scope_override = true;
  return previous;
}

static void session_translation_pop_scope_override(session_ctx_t *ctx, bool previous) {
  if (ctx == NULL) {
    return;
  }

  ctx->translation_manual_scope_override = previous;
}

static void session_translation_queue_block(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || text == NULL || text[0] == '\0') {
    return;
  }

  if (translator_should_limit_to_chat_bbs() && !ctx->translation_manual_scope_override) {
    return;
  }

  (void)session_translation_queue_caption(ctx, text, 0U);
}

static bool session_translation_queue_private_message(session_ctx_t *ctx, session_ctx_t *target, const char *message) {
  if (ctx == NULL || target == NULL || message == NULL) {
    return false;
  }

  if (!ctx->translation_enabled || !ctx->input_translation_enabled || ctx->input_translation_language[0] == '\0' ||
      message[0] == '\0') {
    return false;
  }

  if (!session_translation_worker_ensure(ctx)) {
    return false;
  }

  translation_job_t *job = calloc(1U, sizeof(*job));
  if (job == NULL) {
    return false;
  }

  job->type = TRANSLATION_JOB_PRIVATE_MESSAGE;
  job->placeholder_lines = 0U;
  snprintf(job->target_language, sizeof(job->target_language), "%s", ctx->input_translation_language);
  snprintf(job->data.pm.original, sizeof(job->data.pm.original), "%s", message);
  snprintf(job->data.pm.target_name, sizeof(job->data.pm.target_name), "%s", target->user.name);
  snprintf(job->data.pm.to_target_label, sizeof(job->data.pm.to_target_label), "%s -> you", ctx->user.name);
  snprintf(job->data.pm.to_sender_label, sizeof(job->data.pm.to_sender_label), "you -> %s", target->user.name);

  pthread_mutex_lock(&ctx->translation_mutex);
  job->next = NULL;
  if (ctx->translation_pending_tail != NULL) {
    ctx->translation_pending_tail->next = job;
  } else {
    ctx->translation_pending_head = job;
  }
  ctx->translation_pending_tail = job;
  pthread_cond_signal(&ctx->translation_cond);
  pthread_mutex_unlock(&ctx->translation_mutex);

  return true;
}

static bool session_translation_queue_input(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || text == NULL || text[0] == '\0') {
    return false;
  }

  if (!ctx->translation_enabled || !ctx->input_translation_enabled || ctx->input_translation_language[0] == '\0') {
    return false;
  }

  if (!session_translation_worker_ensure(ctx)) {
    return false;
  }

  translation_job_t *job = calloc(1U, sizeof(*job));
  if (job == NULL) {
    return false;
  }

  job->type = TRANSLATION_JOB_INPUT;
  job->placeholder_lines = 0U;
  snprintf(job->target_language, sizeof(job->target_language), "%s", ctx->input_translation_language);
  snprintf(job->data.input.original, sizeof(job->data.input.original), "%s", text);

  pthread_mutex_lock(&ctx->translation_mutex);
  job->next = NULL;
  if (ctx->translation_pending_tail != NULL) {
    ctx->translation_pending_tail->next = job;
  } else {
    ctx->translation_pending_head = job;
  }
  ctx->translation_pending_tail = job;
  pthread_cond_signal(&ctx->translation_cond);
  pthread_mutex_unlock(&ctx->translation_mutex);

  return true;
}

static void session_translation_normalize_output(char *text) {
  if (text == NULL) {
    return;
  }

  size_t length = strlen(text);
  size_t idx = 0U;
  while (idx < length) {
    char ch = text[idx];
    if ((ch == 'u' || ch == 'U') && idx + 4U < length && text[idx + 1U] == '0' && text[idx + 2U] == '0' &&
        text[idx + 3U] == '3' && (text[idx + 4U] == 'c' || text[idx + 4U] == 'C' || text[idx + 4U] == 'e' ||
                                   text[idx + 4U] == 'E')) {
      char replacement = (text[idx + 4U] == 'c' || text[idx + 4U] == 'C') ? '<' : '>';
      size_t remove_start = idx;
      if (remove_start > 0U && text[remove_start - 1U] == '\\') {
        --remove_start;
      }

      size_t remove_end = idx + 5U;
      size_t removed = remove_end - remove_start;
      text[remove_start] = replacement;
      memmove(text + remove_start + 1U, text + remove_end, length - remove_end + 1U);
      length -= (removed - 1U);
      idx = remove_start + 1U;
      continue;
    }

    ++idx;
  }
}

static bool host_motd_contains_translation_notice(const char *motd_text) {
  if (motd_text == NULL) {
    return false;
  }

  const size_t notice_length = strlen(kTranslationQuotaNotice);
  const char *cursor = motd_text;
  while (*cursor != '\0') {
    size_t skip = host_column_reset_sequence_length(cursor);
    if (skip > 0U) {
      cursor += skip;
      continue;
    }
    if (*cursor == '\r' || *cursor == '\n') {
      ++cursor;
      continue;
    }
    if (strncmp(cursor, kTranslationQuotaNotice, notice_length) == 0) {
      return true;
    }
    while (*cursor != '\0' && *cursor != '\n') {
      ++cursor;
    }
  }

  return false;
}

static void host_prepend_translation_notice_in_memory(host_t *host, const char *existing_motd) {
  if (host == NULL) {
    return;
  }

  char updated[sizeof(host->motd)];
  if (existing_motd != NULL && existing_motd[0] != '\0') {
    snprintf(updated, sizeof(updated), "%s\n\n%s", kTranslationQuotaNotice, existing_motd);
  } else {
    snprintf(updated, sizeof(updated), "%s\n", kTranslationQuotaNotice);
  }

  pthread_mutex_lock(&host->lock);
  snprintf(host->motd_base, sizeof(host->motd_base), "%s", updated);
  host_refresh_motd_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static void host_handle_translation_quota_exhausted(host_t *host) {
  if (host == NULL) {
    return;
  }

  bool already_marked = false;
  char motd_path[PATH_MAX];
  motd_path[0] = '\0';
  char motd_snapshot[sizeof(host->motd_base)];
  motd_snapshot[0] = '\0';

  pthread_mutex_lock(&host->lock);
  if (host->translation_quota_exhausted) {
    already_marked = true;
  } else {
    host->translation_quota_exhausted = true;
    if (host->motd_has_file && host->motd_path[0] != '\0') {
      snprintf(motd_path, sizeof(motd_path), "%s", host->motd_path);
    }
    snprintf(motd_snapshot, sizeof(motd_snapshot), "%s", host->motd_base);
  }
  pthread_mutex_unlock(&host->lock);

  if (already_marked) {
    return;
  }

  if (motd_path[0] == '\0') {
    if (host_motd_contains_translation_notice(motd_snapshot)) {
      host_refresh_motd(host);
      return;
    }
    host_prepend_translation_notice_in_memory(host, motd_snapshot);
    return;
  }

  char existing[8192];
  existing[0] = '\0';
  size_t existing_len = 0U;

  FILE *motd_file = fopen(motd_path, "rb");
  if (motd_file != NULL) {
    existing_len = fread(existing, 1U, sizeof(existing) - 1U, motd_file);
    if (ferror(motd_file)) {
      const int read_error = errno;
      humanized_log_error("host", "failed to read motd file", read_error);
      existing_len = 0U;
      existing[0] = '\0';
    }
    existing[existing_len] = '\0';
    if (fclose(motd_file) != 0) {
      const int close_error = errno;
      humanized_log_error("host", "failed to close motd file", close_error);
    }
  } else {
    host_prepend_translation_notice_in_memory(host, motd_snapshot);
    return;
  }

  const char *existing_start = existing;
  while (*existing_start == '\n' || *existing_start == '\r') {
    ++existing_start;
  }

  if (strncmp(existing_start, kTranslationQuotaNotice, strlen(kTranslationQuotaNotice)) == 0) {
    (void)host_try_load_motd_from_path(host, motd_path);
    return;
  }

  FILE *out = fopen(motd_path, "wb");
  if (out == NULL) {
    const int write_error = errno != 0 ? errno : EIO;
    humanized_log_error("host", "failed to update motd file", write_error);
    host_prepend_translation_notice_in_memory(host, motd_snapshot);
    return;
  }

  (void)fprintf(out, "%s\n", kTranslationQuotaNotice);
  if (existing[0] != '\0') {
    fputc('\n', out);
    (void)fwrite(existing, 1U, existing_len, out);
  }

  if (fclose(out) != 0) {
    const int close_error = errno;
    humanized_log_error("host", "failed to close motd file", close_error);
  }

  (void)host_try_load_motd_from_path(host, motd_path);
}

static void session_handle_translation_quota_exhausted(session_ctx_t *ctx, const char *error_detail) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_handle_translation_quota_exhausted(ctx->owner);

  const bool was_enabled = ctx->translation_enabled || ctx->output_translation_enabled ||
                           ctx->input_translation_enabled;
  ctx->translation_enabled = false;
  ctx->output_translation_enabled = false;
  ctx->input_translation_enabled = false;

  if (was_enabled) {
    host_store_translation_preferences(ctx->owner, ctx);
  }

  if (!ctx->translation_quota_notified) {
    char message[256];
    if (error_detail != NULL && error_detail[0] != '\0') {
      (void)snprintf(message, sizeof(message), "%s (%s)", kTranslationQuotaSystemMessage, error_detail);
    } else {
      (void)snprintf(message, sizeof(message), "%s", kTranslationQuotaSystemMessage);
    }
    session_send_system_line(ctx, message);
    ctx->translation_quota_notified = true;
  }
}

static void session_translation_flush_ready(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->translation_mutex_initialized) {
    return;
  }

  translation_result_t *ready = NULL;

  pthread_mutex_lock(&ctx->translation_mutex);
  ready = ctx->translation_ready_head;
  ctx->translation_ready_head = NULL;
  ctx->translation_ready_tail = NULL;
  pthread_mutex_unlock(&ctx->translation_mutex);

  if (ready == NULL) {
    return;
  }

  const bool translation_active = ctx->translation_enabled && ctx->output_translation_enabled &&
                                  ctx->output_translation_language[0] != '\0';

  bool refreshed = false;
  while (ready != NULL) {
    translation_result_t *next = ready->next;
    if (ready->type == TRANSLATION_JOB_INPUT) {
      if (ready->success) {
        if (ready->detected_language[0] != '\0') {
          snprintf(ctx->last_detected_input_language, sizeof(ctx->last_detected_input_language), "%s",
                   ready->detected_language);
        }
        session_deliver_outgoing_message(ctx, ready->translated);
      } else {
        const char *error_message = ready->error_message[0] != '\0'
                                        ? ready->error_message
                                        : "Translation failed; sending your original message.";
        session_send_system_line(ctx, error_message);
        session_deliver_outgoing_message(ctx, ready->original);
      }
      refreshed = true;
      free(ready);
      ready = next;
      continue;
    }

    if (ready->type == TRANSLATION_JOB_PRIVATE_MESSAGE) {
      session_ctx_t *target = NULL;
      if (ctx->owner != NULL && ready->pm_target_name[0] != '\0') {
        target = chat_room_find_user(&ctx->owner->room, ready->pm_target_name);
      }

      if (ready->success) {
        if (target != NULL) {
          session_send_private_message_line(target, ctx, ready->pm_to_target_label, ready->translated);
        } else if (ready->pm_target_name[0] != '\0') {
          char notice[SSH_CHATTER_MESSAGE_LIMIT];
          snprintf(notice, sizeof(notice), "User '%s' disconnected before your private message was delivered.",
                   ready->pm_target_name);
          session_send_system_line(ctx, notice);
        }
        session_send_private_message_line(ctx, ctx, ready->pm_to_sender_label, ready->translated);
      } else {
        const char *error_message = ready->error_message[0] != '\0'
                                        ? ready->error_message
                                        : "Translation failed; sending your original message.";
        session_send_system_line(ctx, error_message);
        if (target != NULL) {
          session_send_private_message_line(target, ctx, ready->pm_to_target_label, ready->original);
        } else if (ready->pm_target_name[0] != '\0') {
          char notice[SSH_CHATTER_MESSAGE_LIMIT];
          snprintf(notice, sizeof(notice), "User '%s' disconnected before your private message was delivered.",
                   ready->pm_target_name);
          session_send_system_line(ctx, notice);
        }
        session_send_private_message_line(ctx, ctx, ready->pm_to_sender_label, ready->original);
      }

      refreshed = true;
      free(ready);
      ready = next;
      continue;
    }

    size_t placeholder_lines = ready->placeholder_lines;
    size_t move_up = 0U;
    if (placeholder_lines > 0U && ctx->translation_placeholder_active_lines >= placeholder_lines) {
      size_t remaining_after = ctx->translation_placeholder_active_lines - placeholder_lines;
      move_up = remaining_after + 1U;
    }

    if (translation_active) {
      const char *body = ready->translated;
      if (body[0] == '\0') {
        body = "translation unavailable.";
      }

      const char *line_cursor = body;
      size_t line_index = 0U;
      while (line_cursor != NULL) {
        const char *line_end = strchr(line_cursor, '\n');
        size_t line_length = (line_end != NULL) ? (size_t)(line_end - line_cursor) : strlen(line_cursor);
        if (line_length >= SSH_CHATTER_TRANSLATION_WORKING_LEN) {
          line_length = SSH_CHATTER_TRANSLATION_WORKING_LEN - 1U;
        }

        char line_fragment[SSH_CHATTER_TRANSLATION_WORKING_LEN];
        memcpy(line_fragment, line_cursor, line_length);
        line_fragment[line_length] = '\0';

        char annotated[SSH_CHATTER_TRANSLATION_WORKING_LEN + 64U];
        snprintf(annotated, sizeof(annotated), "    \342\206\263 %s", line_fragment);
        session_render_caption_with_offset(ctx, annotated, line_index == 0U ? move_up : 0U);
        refreshed = true;

        if (line_end == NULL) {
          break;
        }

        line_cursor = line_end + 1;
        ++line_index;
      }
    }

    if (placeholder_lines > 0U) {
      if (ctx->translation_placeholder_active_lines >= placeholder_lines) {
        ctx->translation_placeholder_active_lines -= placeholder_lines;
      } else {
        ctx->translation_placeholder_active_lines = 0U;
      }
    }

    free(ready);
    ready = next;
  }

  if (refreshed && ctx->history_scroll_position == 0U) {
    session_refresh_input_line(ctx);
  }
}

static void session_translation_worker_shutdown(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->translation_mutex_initialized) {
    pthread_mutex_lock(&ctx->translation_mutex);
    if (ctx->translation_thread_started) {
      ctx->translation_thread_stop = true;
      pthread_cond_broadcast(&ctx->translation_cond);
      pthread_mutex_unlock(&ctx->translation_mutex);
      pthread_join(ctx->translation_thread, NULL);
      ctx->translation_thread_started = false;
    } else {
      pthread_mutex_unlock(&ctx->translation_mutex);
    }
  }

  session_translation_clear_queue(ctx);

  if (ctx->translation_cond_initialized) {
    pthread_cond_destroy(&ctx->translation_cond);
    ctx->translation_cond_initialized = false;
  }
  if (ctx->translation_mutex_initialized) {
    pthread_mutex_destroy(&ctx->translation_mutex);
    ctx->translation_mutex_initialized = false;
  }

  ctx->translation_thread_stop = false;
}

static void session_translation_publish_result(session_ctx_t *ctx, const translation_job_t *job,
                                               const char *payload, const char *detected_language,
                                               const char *error_message, bool success) {
  if (ctx == NULL || job == NULL) {
    return;
  }

  translation_result_t *result = calloc(1U, sizeof(*result));
  if (result == NULL) {
    return;
  }

  result->type = job->type;
  result->success = success;
  result->placeholder_lines = job->placeholder_lines;

  if (job->type == TRANSLATION_JOB_INPUT) {
    snprintf(result->original, sizeof(result->original), "%s", job->data.input.original);
    if (payload != NULL) {
      snprintf(result->translated, sizeof(result->translated), "%s", payload);
    } else {
      result->translated[0] = '\0';
    }
    if (detected_language != NULL) {
      snprintf(result->detected_language, sizeof(result->detected_language), "%s", detected_language);
    } else {
      result->detected_language[0] = '\0';
    }
    if (error_message != NULL) {
      snprintf(result->error_message, sizeof(result->error_message), "%s", error_message);
    } else {
      result->error_message[0] = '\0';
    }
    session_translation_normalize_output(result->translated);
  } else if (job->type == TRANSLATION_JOB_PRIVATE_MESSAGE) {
    snprintf(result->original, sizeof(result->original), "%s", job->data.pm.original);
    if (payload != NULL) {
      snprintf(result->translated, sizeof(result->translated), "%s", payload);
    } else {
      result->translated[0] = '\0';
    }
    if (error_message != NULL) {
      snprintf(result->error_message, sizeof(result->error_message), "%s", error_message);
    } else {
      result->error_message[0] = '\0';
    }
    result->detected_language[0] = '\0';
    snprintf(result->pm_target_name, sizeof(result->pm_target_name), "%s", job->data.pm.target_name);
    snprintf(result->pm_to_target_label, sizeof(result->pm_to_target_label), "%s", job->data.pm.to_target_label);
    snprintf(result->pm_to_sender_label, sizeof(result->pm_to_sender_label), "%s", job->data.pm.to_sender_label);
    session_translation_normalize_output(result->translated);
  } else {
    const char *message = payload;
    if (message == NULL || message[0] == '\0') {
      if (success) {
        message = "";
      } else {
        message = "⚠️ translation unavailable.";
      }
    }

    snprintf(result->translated, sizeof(result->translated), "%s", message);
    session_translation_normalize_output(result->translated);
    result->detected_language[0] = '\0';
    result->error_message[0] = '\0';
    result->original[0] = '\0';
  }

  pthread_mutex_lock(&ctx->translation_mutex);
  result->next = NULL;
  if (ctx->translation_ready_tail != NULL) {
    ctx->translation_ready_tail->next = result;
  } else {
    ctx->translation_ready_head = result;
  }
  ctx->translation_ready_tail = result;
  pthread_mutex_unlock(&ctx->translation_mutex);
}

static void session_translation_process_single_job(session_ctx_t *ctx, translation_job_t *job) {
  if (ctx == NULL || job == NULL) {
    return;
  }

  if (ctx->translation_thread_stop) {
    free(job);
    return;
  }

  if (job->type == TRANSLATION_JOB_INPUT || job->type == TRANSLATION_JOB_PRIVATE_MESSAGE) {
    char translated_body[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    char detected_language[SSH_CHATTER_LANG_NAME_LEN];
    translated_body[0] = '\0';
    detected_language[0] = '\0';

    const bool is_private_message = (job->type == TRANSLATION_JOB_PRIVATE_MESSAGE);
    const char *source_text =
        is_private_message ? job->data.pm.original : job->data.input.original;
    char *detected_target = is_private_message ? NULL : detected_language;
    size_t detected_length = is_private_message ? 0U : sizeof(detected_language);

    if (translator_translate_with_cancel(source_text, job->target_language, translated_body, sizeof(translated_body),
                                         detected_target, detected_length, &ctx->translation_thread_stop)) {
      if (ctx->translation_thread_stop) {
        free(job);
        return;
      }
      session_translation_publish_result(ctx, job, translated_body,
                                         is_private_message ? NULL : detected_language, NULL, true);
    } else {
      const char *error = translator_last_error();
      char message[128];
      const bool quota_failure = translator_last_error_was_quota();
      if (ctx->translation_thread_stop) {
        free(job);
        return;
      }
      if (quota_failure) {
        if (error != NULL && error[0] != '\0') {
          snprintf(message, sizeof(message),
                   "⚠️ translation unavailable (quota exhausted: %s); sending your original message.", error);
        } else {
          snprintf(message, sizeof(message),
                   "⚠️ translation unavailable (quota exhausted); sending your original message.");
        }
        session_handle_translation_quota_exhausted(ctx, error);
      } else if (error != NULL && error[0] != '\0') {
        snprintf(message, sizeof(message), "Translation failed (%s); sending your original message.", error);
      } else {
        snprintf(message, sizeof(message), "Translation failed; sending your original message.");
      }
      if (ctx->translation_thread_stop) {
        free(job);
        return;
      }
      session_translation_publish_result(ctx, job, NULL, NULL, message, false);
    }
    free(job);
    return;
  }

  char translated_body[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  char restored[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  translated_body[0] = '\0';
  restored[0] = '\0';

  bool success = false;
  char failure_message[128];
  failure_message[0] = '\0';
  const int max_attempts = 3;
  for (int attempt = 0; attempt < max_attempts && !success; ++attempt) {
    translated_body[0] = '\0';

    if (ctx->translation_thread_stop) {
      free(job);
      return;
    }

    if (!translator_translate_with_cancel(job->data.caption.sanitized, job->target_language, translated_body,
                                          sizeof(translated_body), NULL, 0U, &ctx->translation_thread_stop)) {
      const char *error = translator_last_error();
      const bool quota_failure = translator_last_error_was_quota();
      if (ctx->translation_thread_stop) {
        free(job);
        return;
      }
      if (quota_failure) {
        if (error != NULL && error[0] != '\0') {
          snprintf(failure_message, sizeof(failure_message),
                   "⚠️ translation unavailable (quota exhausted: %s)", error);
        } else {
          snprintf(failure_message, sizeof(failure_message), "⚠️ translation unavailable (quota exhausted).");
        }
        session_handle_translation_quota_exhausted(ctx, error);
        break;
      }

      if (error != NULL && error[0] != '\0') {
        snprintf(failure_message, sizeof(failure_message), "⚠️ translation failed: %s", error);
      } else {
        snprintf(failure_message, sizeof(failure_message), "⚠️ translation failed.");
      }

      if (attempt + 1 < max_attempts) {
        struct timespec retry_delay = {.tv_sec = 1, .tv_nsec = 0L};
        nanosleep(&retry_delay, NULL);
      }
      continue;
    }

    if (!translation_restore_text(translated_body, restored, sizeof(restored), job->data.caption.placeholders,
                                  job->data.caption.placeholder_count)) {
      snprintf(failure_message, sizeof(failure_message), "⚠️ translation post-processing failed.");
      break;
    }

    success = true;
    failure_message[0] = '\0';
  }

  if (!success && failure_message[0] == '\0') {
    snprintf(failure_message, sizeof(failure_message), "⚠️ translation unavailable.");
  }

  if (ctx->translation_thread_stop) {
    free(job);
    return;
  }

  if (success) {
    session_translation_publish_result(ctx, job, restored, NULL, NULL, true);
  } else {
    session_translation_publish_result(ctx, job, failure_message, NULL, NULL, false);
  }

  free(job);
}

static bool session_translation_process_batch(session_ctx_t *ctx, translation_job_t **jobs, size_t job_count) {
  if (ctx == NULL || jobs == NULL || job_count == 0U) {
    return false;
  }

  if (jobs[0] == NULL || jobs[0]->type != TRANSLATION_JOB_CAPTION) {
    return false;
  }

  if (ctx->translation_thread_stop) {
    for (size_t idx = 0U; idx < job_count; ++idx) {
      if (jobs[idx] != NULL) {
        free(jobs[idx]);
        jobs[idx] = NULL;
      }
    }
    return true;
  }

  char *combined = calloc(SSH_CHATTER_TRANSLATION_BATCH_BUFFER, sizeof(char));
  char *translated = calloc(SSH_CHATTER_TRANSLATION_BATCH_BUFFER, sizeof(char));
  if (combined == NULL || translated == NULL) {
    free(combined);
    free(translated);
    return false;
  }

  size_t offset = 0U;
  for (size_t idx = 0U; idx < job_count; ++idx) {
    if (ctx->translation_thread_stop) {
      for (size_t release = idx; release < job_count; ++release) {
        if (jobs[release] != NULL) {
          free(jobs[release]);
          jobs[release] = NULL;
        }
      }
      free(combined);
      free(translated);
      return true;
    }
    if (jobs[idx] == NULL || jobs[idx]->type != TRANSLATION_JOB_CAPTION) {
      free(combined);
      free(translated);
      return false;
    }

    char marker[32];
    int marker_len = snprintf(marker, sizeof(marker), "[[SEG%02zu]]\n", idx);
    if (marker_len < 0) {
      free(combined);
      free(translated);
      return false;
    }

    size_t marker_size = (size_t)marker_len;
    size_t text_len = strlen(jobs[idx]->data.caption.sanitized);
    if (offset + marker_size + text_len + 1U > SSH_CHATTER_TRANSLATION_BATCH_BUFFER) {
      free(combined);
      free(translated);
      return false;
    }

    memcpy(combined + offset, marker, marker_size);
    offset += marker_size;
    memcpy(combined + offset, jobs[idx]->data.caption.sanitized, text_len);
    offset += text_len;
    combined[offset++] = '\n';
  }
  combined[offset] = '\0';

  if (!translator_translate_with_cancel(combined, jobs[0]->target_language, translated,
                                        SSH_CHATTER_TRANSLATION_BATCH_BUFFER, NULL, 0U,
                                        &ctx->translation_thread_stop)) {
    if (ctx->translation_thread_stop) {
      for (size_t idx = 0U; idx < job_count; ++idx) {
        if (jobs[idx] != NULL) {
          free(jobs[idx]);
          jobs[idx] = NULL;
        }
      }
      free(combined);
      free(translated);
      return true;
    }
    free(combined);
    free(translated);
    return false;
  }

  if (ctx->translation_thread_stop) {
    for (size_t idx = 0U; idx < job_count; ++idx) {
      if (jobs[idx] != NULL) {
        free(jobs[idx]);
        jobs[idx] = NULL;
      }
    }
    free(combined);
    free(translated);
    return true;
  }

  char *segment_starts[SSH_CHATTER_TRANSLATION_BATCH_MAX] = {0};
  char *segment_ends[SSH_CHATTER_TRANSLATION_BATCH_MAX] = {0};

  char *search_cursor = translated;
  for (size_t idx = 0U; idx < job_count; ++idx) {
    char marker[32];
    int marker_len = snprintf(marker, sizeof(marker), "[[SEG%02zu]]", idx);
    if (marker_len < 0) {
      free(combined);
      free(translated);
      return false;
    }

    char *marker_pos = strstr(search_cursor, marker);
    if (marker_pos == NULL) {
      free(combined);
      free(translated);
      return false;
    }

    char *start = marker_pos + (size_t)marker_len;
    while (*start == '\r' || *start == '\n') {
      ++start;
    }

    segment_starts[idx] = start;
    search_cursor = start;
  }

  for (size_t idx = 0U; idx + 1U < job_count; ++idx) {
    char marker[32];
    int marker_len = snprintf(marker, sizeof(marker), "[[SEG%02zu]]", idx + 1U);
    if (marker_len < 0) {
      free(combined);
      free(translated);
      return false;
    }

    char *next_pos = strstr(segment_starts[idx], marker);
    if (next_pos == NULL) {
      free(combined);
      free(translated);
      return false;
    }

    char *end = next_pos;
    while (end > segment_starts[idx] && (end[-1] == '\r' || end[-1] == '\n')) {
      --end;
    }
    segment_ends[idx] = end;
  }

  char *last_end = translated + strlen(translated);
  while (last_end > segment_starts[job_count - 1U] && (last_end[-1] == '\r' || last_end[-1] == '\n')) {
    --last_end;
  }
  segment_ends[job_count - 1U] = last_end;

  char restored_segments[SSH_CHATTER_TRANSLATION_BATCH_MAX][SSH_CHATTER_TRANSLATION_WORKING_LEN];
  for (size_t idx = 0U; idx < job_count; ++idx) {
    if (segment_starts[idx] == NULL || segment_ends[idx] == NULL || segment_ends[idx] < segment_starts[idx]) {
      free(combined);
      free(translated);
      return false;
    }

    size_t segment_len = (size_t)(segment_ends[idx] - segment_starts[idx]);
    if (segment_len + 1U > SSH_CHATTER_TRANSLATION_WORKING_LEN) {
      free(combined);
      free(translated);
      return false;
    }

    char segment_buffer[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    memcpy(segment_buffer, segment_starts[idx], segment_len);
    segment_buffer[segment_len] = '\0';

    if (!translation_restore_text(segment_buffer, restored_segments[idx], sizeof(restored_segments[idx]),
                                  jobs[idx]->data.caption.placeholders, jobs[idx]->data.caption.placeholder_count)) {
      free(combined);
      free(translated);
      return false;
    }
  }

  if (ctx->translation_thread_stop) {
    for (size_t idx = 0U; idx < job_count; ++idx) {
      if (jobs[idx] != NULL) {
        free(jobs[idx]);
        jobs[idx] = NULL;
      }
    }
    free(combined);
    free(translated);
    return true;
  }

  for (size_t idx = 0U; idx < job_count; ++idx) {
    session_translation_publish_result(ctx, jobs[idx], restored_segments[idx], NULL, NULL, true);
    free(jobs[idx]);
  }

  free(combined);
  free(translated);
  return true;
}

static void *session_translation_worker(void *arg) {
  session_ctx_t *ctx = (session_ctx_t *)arg;
  if (ctx == NULL) {
    return NULL;
  }

  for (;;) {
    translation_job_t *batch[SSH_CHATTER_TRANSLATION_BATCH_MAX] = {0};
    size_t batch_count = 0U;

    pthread_mutex_lock(&ctx->translation_mutex);
    while (!ctx->translation_thread_stop && ctx->translation_pending_head == NULL) {
      pthread_cond_wait(&ctx->translation_cond, &ctx->translation_mutex);
    }

    if (ctx->translation_thread_stop) {
      pthread_mutex_unlock(&ctx->translation_mutex);
      break;
    }

    translation_job_t *job = ctx->translation_pending_head;
    if (job != NULL) {
      ctx->translation_pending_head = job->next;
      if (ctx->translation_pending_head == NULL) {
        ctx->translation_pending_tail = NULL;
      }
      job->next = NULL;
      batch[batch_count++] = job;
    }
    pthread_mutex_unlock(&ctx->translation_mutex);

    if (batch_count == 0U) {
      continue;
    }

    if (batch[0]->type == TRANSLATION_JOB_INPUT) {
      session_translation_process_single_job(ctx, batch[0]);
      continue;
    }

    size_t estimate = strlen(batch[0]->data.caption.sanitized) + SSH_CHATTER_TRANSLATION_SEGMENT_GUARD;

    if (batch_count == 1U) {
      bool delay_needed = false;
      pthread_mutex_lock(&ctx->translation_mutex);
      if (!ctx->translation_thread_stop && ctx->translation_pending_head == NULL) {
        delay_needed = true;
      }
      pthread_mutex_unlock(&ctx->translation_mutex);

      if (delay_needed) {
        struct timespec aggregation_delay = {.tv_sec = 0, .tv_nsec = SSH_CHATTER_TRANSLATION_BATCH_DELAY_NS};
        nanosleep(&aggregation_delay, NULL);
      }
    }

    pthread_mutex_lock(&ctx->translation_mutex);
    while (batch_count < SSH_CHATTER_TRANSLATION_BATCH_MAX && ctx->translation_pending_head != NULL) {
      translation_job_t *candidate = ctx->translation_pending_head;
      if (candidate == NULL) {
        break;
      }

      if (candidate->type != TRANSLATION_JOB_CAPTION) {
        break;
      }

      if (strcmp(candidate->target_language, batch[0]->target_language) != 0) {
        break;
      }

      size_t candidate_len = strlen(candidate->data.caption.sanitized) + SSH_CHATTER_TRANSLATION_SEGMENT_GUARD;
      if (estimate + candidate_len >= SSH_CHATTER_TRANSLATION_BATCH_BUFFER) {
        break;
      }

      ctx->translation_pending_head = candidate->next;
      if (ctx->translation_pending_head == NULL) {
        ctx->translation_pending_tail = NULL;
      }
      candidate->next = NULL;
      batch[batch_count++] = candidate;
      estimate += candidate_len;
    }
    pthread_mutex_unlock(&ctx->translation_mutex);

    bool processed = false;
    if (batch_count > 1U) {
      processed = session_translation_process_batch(ctx, batch, batch_count);
    }

    if (!processed) {
      for (size_t idx = 0U; idx < batch_count; ++idx) {
        session_translation_process_single_job(ctx, batch[idx]);
      }
    }
  }

  return NULL;
}

static void session_channel_log_write_failure(session_ctx_t *ctx, const char *reason) {
  if (ctx == NULL) {
    return;
  }

  if (reason == NULL || reason[0] == '\0') {
    reason = "transport write failure";
  }

  const char *username = ctx->user.name[0] != '\0' ? ctx->user.name : "unknown";
  printf("[session] transport write failure for %s: %s\n", username, reason);
}

static bool session_telnet_write_block(session_ctx_t *ctx, const unsigned char *data, size_t length) {
  if (ctx == NULL || data == NULL || length == 0U || ctx->telnet_fd < 0) {
    return true;
  }

  while (length > 0U) {
    size_t chunk = length;
    if (chunk > SSH_CHATTER_CHANNEL_WRITE_CHUNK) {
      chunk = SSH_CHATTER_CHANNEL_WRITE_CHUNK;
    }

    unsigned char buffer[SSH_CHATTER_CHANNEL_WRITE_CHUNK * 2U];
    size_t expanded = 0U;
    for (size_t idx = 0U; idx < chunk; ++idx) {
      unsigned char byte = data[idx];
      buffer[expanded++] = byte;
      if (byte == TELNET_IAC) {
        buffer[expanded++] = TELNET_IAC;
      }
    }

    size_t offset = 0U;
    while (offset < expanded) {
      ssize_t written = send(ctx->telnet_fd, buffer + offset, expanded - offset, MSG_NOSIGNAL);
      if (written < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      offset += (size_t)written;
    }

    data += chunk;
    length -= chunk;
  }

  return true;
}

static bool session_channel_wait_writable(session_ctx_t *ctx, int timeout_ms) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    if (ctx->telnet_fd < 0) {
      return false;
    }

    struct pollfd pfd = {
        .fd = ctx->telnet_fd,
        .events = POLLOUT,
        .revents = 0,
    };

    for (;;) {
      int result = poll(&pfd, 1, timeout_ms);
      if (result < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (result == 0) {
        return false;
      }
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return false;
      }
      if (pfd.revents & POLLOUT) {
        return true;
      }
      return false;
    }
  }

  if (ctx->session == NULL) {
    return false;
  }

  int fd = ssh_get_fd(ctx->session);
  if (fd < 0) {
    struct timespec backoff = {
        .tv_sec = 0,
        .tv_nsec = SSH_CHATTER_CHANNEL_WRITE_BACKOFF_NS,
    };
    nanosleep(&backoff, NULL);
    return true;
  }

  struct pollfd pfd = {
      .fd = fd,
      .events = POLLOUT,
      .revents = 0,
  };

  for (;;) {
    int result = poll(&pfd, 1, timeout_ms);
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (result == 0) {
      return false;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      return false;
    }
    if (pfd.revents & POLLOUT) {
      return true;
    }
    return false;
  }
}

static bool session_channel_write_all(session_ctx_t *ctx, const void *data, size_t length) {
  if (ctx == NULL || data == NULL || length == 0U || !session_transport_active(ctx)) {
    return true;
  }

  const unsigned char *cursor = (const unsigned char *)data;
  size_t remaining = length;
  unsigned int stalled = 0U;

  while (remaining > 0U) {
    if (!session_channel_wait_writable(ctx, SSH_CHATTER_CHANNEL_WRITE_TIMEOUT_MS)) {
      if (++stalled >= SSH_CHATTER_CHANNEL_WRITE_MAX_STALLS) {
        session_channel_log_write_failure(ctx, "write timed out");
        return false;
      }
      continue;
    }

    stalled = 0U;

    size_t chunk = remaining;
    if (chunk > SSH_CHATTER_CHANNEL_WRITE_CHUNK) {
      chunk = SSH_CHATTER_CHANNEL_WRITE_CHUNK;
    }

    if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
      if (!session_telnet_write_block(ctx, cursor, chunk)) {
        session_channel_log_write_failure(ctx, "telnet write error");
        return false;
      }
      cursor += chunk;
      remaining -= chunk;
      continue;
    }

    ssize_t written = ssh_channel_write(ctx->channel, cursor, (uint32_t)chunk);
    if (written == SSH_ERROR) {
      const char *error = ssh_get_error(ctx->session);
      session_channel_log_write_failure(ctx,
                                        (error != NULL && error[0] != '\0') ? error : "channel write error");
      return false;
    }

    if (written == 0) {
      if (ssh_channel_is_eof(ctx->channel) || !ssh_channel_is_open(ctx->channel)) {
        session_channel_log_write_failure(ctx, "channel closed during write");
        return false;
      }

      if (++stalled >= SSH_CHATTER_CHANNEL_WRITE_MAX_STALLS) {
        session_channel_log_write_failure(ctx, "channel write stalled");
        return false;
      }

      continue;
    }

    cursor += written;
    remaining -= (size_t)written;
  }

  return true;
}

static void session_channel_write(session_ctx_t *ctx, const void *data, size_t length) {
  if (ctx == NULL || data == NULL || length == 0U || ctx->should_exit || !session_transport_active(ctx)) {
    return;
  }

  if (!session_channel_write_all(ctx, data, length)) {
    ctx->should_exit = true;
  }
}

static void session_apply_background_fill(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const size_t bg_len = strlen(bg);

  if (bg_len > 0U) {
    session_channel_write(ctx, bg, bg_len);
  }

  session_channel_write(ctx, ANSI_CLEAR_LINE, sizeof(ANSI_CLEAR_LINE) - 1U);
  session_channel_write(ctx, "\r", 1U);

  if (bg_len > 0U) {
    session_channel_write(ctx, bg, bg_len);
  }
}

static void session_write_rendered_line(session_ctx_t *ctx, const char *render_source) {
  if (ctx == NULL || render_source == NULL || !session_transport_active(ctx)) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const size_t bg_len = strlen(bg);

  if (bg_len == 0U) {
    session_channel_write(ctx, render_source, strlen(render_source));
    session_channel_write(ctx, "\r\n", 2U);
    return;
  }

  session_channel_write(ctx, bg, bg_len);
  session_channel_write(ctx, ANSI_CLEAR_LINE, sizeof(ANSI_CLEAR_LINE) - 1U);
  session_channel_write(ctx, "\r", 1U);

  char expanded[SSH_CHATTER_TRANSLATION_WORKING_LEN + SSH_CHATTER_MESSAGE_LIMIT];
  size_t out_idx = 0U;
  const size_t length = strlen(render_source);

  for (size_t idx = 0U; idx < length && out_idx + 1U < sizeof(expanded);) {
    if (render_source[idx] == '\033' && idx + 3U < length && render_source[idx + 1U] == '[' &&
        render_source[idx + 2U] == '0' && render_source[idx + 3U] == 'm') {
      if (out_idx + 4U >= sizeof(expanded)) {
        break;
      }

      memcpy(expanded + out_idx, render_source + idx, 4U);
      out_idx += 4U;
      idx += 4U;

      if (out_idx + bg_len >= sizeof(expanded)) {
        break;
      }
      memcpy(expanded + out_idx, bg, bg_len);
      out_idx += bg_len;
      continue;
    }

    expanded[out_idx++] = render_source[idx++];
  }

  expanded[out_idx] = '\0';

  session_channel_write(ctx, expanded, out_idx);
  session_channel_write(ctx, "\r\n", 2U);
  session_channel_write(ctx, bg, bg_len);
}

static void session_send_caption_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || message == NULL || !session_transport_active(ctx)) {
    return;
  }

  session_channel_write(ctx, "\r", 1U);
  session_channel_write(ctx, ANSI_INSERT_LINE, sizeof(ANSI_INSERT_LINE) - 1U);

  session_write_rendered_line(ctx, message);
}

static void session_render_caption_with_offset(session_ctx_t *ctx, const char *message, size_t move_up) {
  if (ctx == NULL || message == NULL || !session_transport_active(ctx)) {
    return;
  }

  if (move_up == 0U) {
    session_send_caption_line(ctx, message);
    return;
  }

  session_channel_write(ctx, "\033[s", 3U);

  char command[32];
  int written = snprintf(command, sizeof(command), "\033[%zuA", move_up);
  if (written > 0 && (size_t)written < sizeof(command)) {
    session_channel_write(ctx, command, (size_t)written);
  }

  session_channel_write(ctx, "\r", 1U);
  session_write_rendered_line(ctx, message);
  session_channel_write(ctx, "\033[u", 3U);
}

static void session_telnet_send_option(session_ctx_t *ctx, unsigned char command, unsigned char option) {
  if (ctx == NULL || ctx->telnet_fd < 0) {
    return;
  }

  unsigned char payload[3] = {TELNET_IAC, command, option};
  send(ctx->telnet_fd, payload, sizeof(payload), MSG_NOSIGNAL);
}

static void session_telnet_handle_option(session_ctx_t *ctx, unsigned char command, unsigned char option) {
  if (ctx == NULL) {
    return;
  }

  switch (command) {
    case TELNET_CMD_DO:
      if (option == TELNET_OPT_SUPPRESS_GO_AHEAD || option == TELNET_OPT_ECHO) {
        session_telnet_send_option(ctx, TELNET_CMD_WILL, option);
      } else {
        session_telnet_send_option(ctx, TELNET_CMD_WONT, option);
      }
      break;
    case TELNET_CMD_DONT:
      session_telnet_send_option(ctx, TELNET_CMD_WONT, option);
      break;
    case TELNET_CMD_WILL:
      if (option == TELNET_OPT_SUPPRESS_GO_AHEAD) {
        session_telnet_send_option(ctx, TELNET_CMD_DO, option);
      } else {
        session_telnet_send_option(ctx, TELNET_CMD_DONT, option);
      }
      break;
    case TELNET_CMD_WONT:
      session_telnet_send_option(ctx, TELNET_CMD_DONT, option);
      break;
    default:
      break;
  }
}

static void session_telnet_initialize(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->telnet_fd < 0 || ctx->telnet_negotiated) {
    return;
  }

  session_telnet_send_option(ctx, TELNET_CMD_WILL, TELNET_OPT_ECHO);
  session_telnet_send_option(ctx, TELNET_CMD_WILL, TELNET_OPT_SUPPRESS_GO_AHEAD);
  session_telnet_send_option(ctx, TELNET_CMD_DO, TELNET_OPT_SUPPRESS_GO_AHEAD);
  session_telnet_send_option(ctx, TELNET_CMD_DONT, TELNET_OPT_LINEMODE);
  session_telnet_send_option(ctx, TELNET_CMD_WONT, TELNET_OPT_STATUS);
  session_telnet_send_option(ctx, TELNET_CMD_WONT, TELNET_OPT_TERMINAL_TYPE);
  session_telnet_send_option(ctx, TELNET_CMD_WONT, TELNET_OPT_TERMINAL_SPEED);
  session_telnet_send_option(ctx, TELNET_CMD_WONT, TELNET_OPT_NAWS);

  ctx->telnet_negotiated = true;
}

static int session_telnet_read_byte(session_ctx_t *ctx, unsigned char *out, int timeout_ms) {
  if (ctx == NULL || out == NULL || ctx->telnet_fd < 0) {
    return SSH_ERROR;
  }

  if (ctx->telnet_pending_valid) {
    ctx->telnet_pending_valid = false;
    *out = (unsigned char)ctx->telnet_pending_char;
    return 1;
  }

  for (;;) {
    struct pollfd pfd = {
        .fd = ctx->telnet_fd,
        .events = POLLIN,
        .revents = 0,
    };

    int poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result < 0) {
      if (errno == EINTR) {
        continue;
      }
      return SSH_ERROR;
    }
    if (poll_result == 0) {
      return SSH_AGAIN;
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      ctx->telnet_eof = true;
      return 0;
    }

    unsigned char byte = 0U;
    ssize_t read_result = recv(ctx->telnet_fd, &byte, 1, 0);
    if (read_result < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      return SSH_ERROR;
    }
    if (read_result == 0) {
      ctx->telnet_eof = true;
      return 0;
    }

    if (byte == TELNET_IAC) {
      unsigned char command = 0U;
      ssize_t command_result = recv(ctx->telnet_fd, &command, 1, 0);
      if (command_result <= 0) {
        if (command_result < 0 && errno == EINTR) {
          continue;
        }
        ctx->telnet_eof = (command_result == 0);
        return ctx->telnet_eof ? 0 : SSH_ERROR;
      }

      if (command == TELNET_IAC) {
        *out = TELNET_IAC;
        return 1;
      }

      if (command == TELNET_CMD_DO || command == TELNET_CMD_DONT || command == TELNET_CMD_WILL ||
          command == TELNET_CMD_WONT) {
        unsigned char option = 0U;
        ssize_t option_result = recv(ctx->telnet_fd, &option, 1, 0);
        if (option_result <= 0) {
          if (option_result < 0 && errno == EINTR) {
            continue;
          }
          ctx->telnet_eof = (option_result == 0);
          return ctx->telnet_eof ? 0 : SSH_ERROR;
        }
        session_telnet_handle_option(ctx, command, option);
        continue;
      }

      if (command == TELNET_CMD_SB) {
        unsigned char prev = 0U;
        for (;;) {
          unsigned char chunk = 0U;
          ssize_t chunk_result = recv(ctx->telnet_fd, &chunk, 1, 0);
          if (chunk_result < 0) {
            if (errno == EINTR) {
              continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              continue;
            }
            return SSH_ERROR;
          }
          if (chunk_result == 0) {
            ctx->telnet_eof = true;
            return 0;
          }
          if (prev == TELNET_IAC && chunk == TELNET_CMD_SE) {
            break;
          }
          prev = (chunk == TELNET_IAC) ? TELNET_IAC : 0U;
        }
        continue;
      }

      if (command == TELNET_CMD_NOP || command == TELNET_CMD_DM || command == TELNET_CMD_BREAK) {
        continue;
      }

      continue;
    }

    if (byte == '\r') {
      unsigned char next = 0U;
      ssize_t next_result = recv(ctx->telnet_fd, &next, 1, MSG_PEEK);
      if (next_result > 0) {
        if (next == '\n' || next == '\0') {
          recv(ctx->telnet_fd, &next, 1, 0);
        } else {
          recv(ctx->telnet_fd, &next, 1, 0);
          ctx->telnet_pending_char = (int)next;
          ctx->telnet_pending_valid = true;
        }
      }

      *out = '\n';
      return 1;
    }

    *out = byte;
    return 1;
  }
}

static int session_transport_read(session_ctx_t *ctx, void *buffer, size_t length, int timeout_ms) {
  if (ctx == NULL || buffer == NULL || length == 0U) {
    return SSH_ERROR;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    unsigned char *output = (unsigned char *)buffer;
    size_t produced = 0U;

    while (produced < length) {
      unsigned char byte = 0U;
      int read_result = session_telnet_read_byte(ctx, &byte, timeout_ms);
      if (read_result == SSH_AGAIN) {
        if (produced > 0U) {
          return (int)produced;
        }
        return SSH_AGAIN;
      }
      if (read_result <= 0) {
        if (produced > 0U) {
          return (int)produced;
        }
        return read_result;
      }

      output[produced++] = byte;
      if (timeout_ms >= 0) {
        break;
      }
    }

    return (int)produced;
  }

  const uint32_t chunk = (length > UINT32_MAX) ? UINT32_MAX : (uint32_t)length;

  if (timeout_ms >= 0) {
    return ssh_channel_read_timeout(ctx->channel, buffer, chunk, 0, timeout_ms);
  }

  return ssh_channel_read(ctx->channel, buffer, chunk, 0);
}

static void session_deliver_outgoing_message(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->owner == NULL || message == NULL) {
    return;
  }

  if (host_eliza_intervene(ctx, message, NULL, false)) {
    return;
  }

  size_t message_length = strnlen(message, SSH_CHATTER_MESSAGE_LIMIT);
  if (!session_security_check_text(ctx, "chat message", message, message_length)) {
    return;
  }

  chat_history_entry_t entry = {0};
  if (!host_history_record_user(ctx->owner, ctx, message, &entry)) {
    return;
  }

  session_send_history_entry(ctx, &entry);
  chat_room_broadcast_entry(&ctx->owner->room, &entry, ctx);
  host_notify_external_clients(ctx->owner, &entry);
}

// session_send_line writes a single line while preserving the session's
// background color even when individual strings reset their ANSI attributes by
// clearing the row with the palette tint before printing.
static void session_send_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || message == NULL) {
    return;
  }

  char buffer[SSH_CHATTER_MESSAGE_LIMIT + 1U];
  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, message, SSH_CHATTER_MESSAGE_LIMIT);
  buffer[SSH_CHATTER_MESSAGE_LIMIT] = '\0';

  char stripped[SSH_CHATTER_MESSAGE_LIMIT + 1U];
  bool suppress_translation = translation_strip_no_translate_prefix(buffer, stripped, sizeof(stripped));
  const char *render_text = suppress_translation ? stripped : buffer;

  session_write_rendered_line(ctx, render_text);

  size_t placeholder_lines = 0U;
  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && !suppress_translation &&
                                 !ctx->translation_suppress_output && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 render_text[0] != '\0';
  if (translation_ready && !ctx->in_bbs_mode && !ctx->in_rss_mode) {
    size_t spacing = ctx->translation_caption_spacing;
    if (spacing > 8U) {
      spacing = 8U;
    }
    placeholder_lines = spacing + 1U;
  }

  if (translation_ready && session_translation_queue_caption(ctx, render_text, placeholder_lines)) {
    if (placeholder_lines > 0U) {
      session_translation_reserve_placeholders(ctx, placeholder_lines);
    }
  }

  session_translation_flush_ready(ctx);
}

static size_t session_append_fragment(char *dest, size_t dest_size, size_t offset, const char *fragment) {
  if (dest == NULL || dest_size == 0U) {
    return offset;
  }

  if (offset >= dest_size) {
    return dest_size > 0U ? dest_size - 1U : offset;
  }

  if (fragment == NULL) {
    dest[offset] = '\0';
    return offset;
  }

  const size_t fragment_len = strlen(fragment);
  if (fragment_len == 0U) {
    return offset;
  }

  if (offset >= dest_size - 1U) {
    dest[dest_size - 1U] = '\0';
    return dest_size - 1U;
  }

  size_t available = dest_size - offset - 1U;
  if (fragment_len < available) {
    memcpy(dest + offset, fragment, fragment_len);
    offset += fragment_len;
  } else {
    memcpy(dest + offset, fragment, available);
    offset += available;
  }

  dest[offset] = '\0';
  return offset;
}

static void session_send_plain_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || message == NULL) {
    return;
  }

  static const char kCaptionPrefix[] = "    \342\206\263";
  if (strncmp(message, kCaptionPrefix, sizeof(kCaptionPrefix) - 1U) == 0) {
    session_send_caption_line(ctx, message);
    return;
  }

  session_send_line(ctx, message);
}

static void session_send_reply_tree(session_ctx_t *ctx, uint64_t parent_message_id, uint64_t parent_reply_id, size_t depth) {
  if (ctx == NULL || ctx->owner == NULL || parent_message_id == 0U) {
    return;
  }

  if (depth > 32U) {
    return;
  }

  host_t *host = ctx->owner;

  size_t match_count = 0U;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < host->reply_count; ++idx) {
    const chat_reply_entry_t *candidate = &host->replies[idx];
    if (!candidate->in_use) {
      continue;
    }
    if (candidate->parent_message_id == parent_message_id && candidate->parent_reply_id == parent_reply_id) {
      ++match_count;
    }
  }

  if (match_count == 0U) {
    pthread_mutex_unlock(&host->lock);
    return;
  }

  chat_reply_entry_t *snapshot = calloc(match_count, sizeof(*snapshot));
  if (snapshot == NULL) {
    pthread_mutex_unlock(&host->lock);
    return;
  }

  size_t copy_idx = 0U;
  for (size_t idx = 0U; idx < host->reply_count && copy_idx < match_count; ++idx) {
    const chat_reply_entry_t *candidate = &host->replies[idx];
    if (!candidate->in_use) {
      continue;
    }
    if (candidate->parent_message_id == parent_message_id && candidate->parent_reply_id == parent_reply_id) {
      snapshot[copy_idx++] = *candidate;
    }
  }
  pthread_mutex_unlock(&host->lock);

  for (size_t idx = 0U; idx < copy_idx; ++idx) {
    const chat_reply_entry_t *reply = &snapshot[idx];

    size_t indent_len = depth * 4U;
    char indent[128];
    if (indent_len >= sizeof(indent)) {
      indent_len = sizeof(indent) - 1U;
    }
    memset(indent, ' ', indent_len);
    indent[indent_len] = '\0';

    const char *target_prefix = (reply->parent_reply_id == 0U) ? "#" : "r#";
    uint64_t target_id = (reply->parent_reply_id == 0U) ? reply->parent_message_id : reply->parent_reply_id;

    char line[SSH_CHATTER_MESSAGE_LIMIT + 160];
    snprintf(line, sizeof(line), "%s↳ [r#%" PRIu64 " → %s%" PRIu64 "] %s: %s", indent, reply->reply_id, target_prefix,
             target_id, reply->username, reply->message);
    session_send_plain_line(ctx, line);

    session_send_reply_tree(ctx, parent_message_id, reply->reply_id, depth + 1U);
  }

  free(snapshot);
}

static bool host_lookup_member_ip(host_t *host, const char *username, char *ip, size_t length) {
  if (host == NULL || username == NULL || ip == NULL || length == 0U) {
    return false;
  }

  session_ctx_t *member = chat_room_find_user(&host->room, username);
  if (member == NULL || member->client_ip[0] == '\0') {
    return false;
  }

  snprintf(ip, length, "%s", member->client_ip);
  return true;
}

static bool session_detect_provider_ip(const char *ip, char *label, size_t length) {
  if (label != NULL && length > 0U) {
    label[0] = '\0';
  }

  if (ip == NULL || ip[0] == '\0' || label == NULL || length == 0U) {
    return false;
  }

  typedef struct provider_prefix {
    const char *prefix;
    const char *label;
  } provider_prefix_t;

  static const provider_prefix_t kProviderPrefixes[] = {
      {"39.7.", "Korean ISP"},       {"58.120.", "Korean ISP"}, {"59.0.", "Korean ISP"},
      {"61.32.", "Korean ISP"},      {"211.36.", "Korean ISP"}, {"218.144.", "Korean ISP"},
      {"73.", "US ISP"},             {"96.", "US ISP"},         {"107.", "US ISP"},
      {"174.", "US ISP"},            {"2600:", "US ISP"},       {"2604:", "US ISP"},
      {"2605:", "US ISP"},           {"2607:", "US ISP"},       {"2609:", "US ISP"},
      {"24.114.", "Canadian ISP"},   {"142.", "Canadian ISP"}, {"2603:", "Canadian ISP"},
      {"185.", "EU ISP"},            {"195.", "EU ISP"},       {"2a00:", "EU ISP"},
      {"2a02:", "EU ISP"},           {"2a03:", "EU ISP"},      {"2a09:", "EU ISP"},
      {"5.18.", "Russian ISP"},      {"37.", "Russian ISP"},   {"91.", "Russian ISP"},
      {"36.", "Chinese ISP"},        {"42.", "Chinese ISP"},   {"139.", "Chinese ISP"},
      {"2408:", "Chinese ISP"},      {"2409:", "Chinese ISP"}, {"49.", "Indian ISP"},
      {"103.", "Indian ISP"},        {"106.", "Indian ISP"},   {"2405:", "Indian ISP"},
      {"2406:", "Indian ISP"},       {"100.64.", "Carrier-grade NAT"}};

  for (size_t idx = 0U; idx < sizeof(kProviderPrefixes) / sizeof(kProviderPrefixes[0]); ++idx) {
    const provider_prefix_t *entry = &kProviderPrefixes[idx];
    size_t prefix_len = strlen(entry->prefix);
    if (strncasecmp(ip, entry->prefix, prefix_len) == 0) {
      snprintf(label, length, "%s", entry->label);
      return true;
    }
  }

  return false;
}

static bool session_blocklist_add(session_ctx_t *ctx, const char *ip, const char *username, bool ip_wide,
                                  bool *already_present) {
  if (ctx == NULL) {
    if (already_present != NULL) {
      *already_present = false;
    }
    return false;
  }

  if (already_present != NULL) {
    *already_present = false;
  }

  char normalized_ip[SSH_CHATTER_IP_LEN] = {0};
  char normalized_user[SSH_CHATTER_USERNAME_LEN] = {0};

  if (ip != NULL && ip[0] != '\0') {
    snprintf(normalized_ip, sizeof(normalized_ip), "%s", ip);
  }

  if (username != NULL && username[0] != '\0') {
    snprintf(normalized_user, sizeof(normalized_user), "%s", username);
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    if (ip_wide) {
      if (normalized_ip[0] != '\0' && strncmp(entry->ip, normalized_ip, SSH_CHATTER_IP_LEN) == 0) {
        if (already_present != NULL) {
          *already_present = true;
        }
        return false;
      }
    } else {
      if (normalized_user[0] != '\0' && strncmp(entry->username, normalized_user, SSH_CHATTER_USERNAME_LEN) == 0 &&
          !entry->ip_wide) {
        if (already_present != NULL) {
          *already_present = true;
        }
        return false;
      }
    }
  }

  size_t free_index = SSH_CHATTER_MAX_BLOCKED;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    if (!ctx->block_entries[idx].in_use) {
      free_index = idx;
      break;
    }
  }

  if (free_index >= SSH_CHATTER_MAX_BLOCKED) {
    return false;
  }

  session_block_entry_t *slot = &ctx->block_entries[free_index];
  memset(slot, 0, sizeof(*slot));
  slot->in_use = true;
  slot->ip_wide = ip_wide;
  if (normalized_ip[0] != '\0') {
    snprintf(slot->ip, sizeof(slot->ip), "%s", normalized_ip);
  }
  if (normalized_user[0] != '\0') {
    snprintf(slot->username, sizeof(slot->username), "%s", normalized_user);
  }

  if (ctx->block_entry_count < SSH_CHATTER_MAX_BLOCKED) {
    ctx->block_entry_count += 1U;
  }

  return true;
}

static bool session_blocklist_remove(session_ctx_t *ctx, const char *token) {
  if (ctx == NULL || token == NULL || token[0] == '\0') {
    return false;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    if ((entry->ip[0] != '\0' && strncmp(entry->ip, token, SSH_CHATTER_IP_LEN) == 0) ||
        (entry->username[0] != '\0' && strncmp(entry->username, token, SSH_CHATTER_USERNAME_LEN) == 0)) {
      memset(entry, 0, sizeof(*entry));
      if (ctx->block_entry_count > 0U) {
        ctx->block_entry_count -= 1U;
      }
      return true;
    }
  }

  return false;
}

static void session_blocklist_show(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->block_entry_count == 0U) {
    session_send_system_line(ctx, "No blocked users or IPs.");
    return;
  }

  session_send_system_line(ctx, "Blocked targets:");
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    const session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (entry->ip_wide && entry->ip[0] != '\0') {
      if (entry->username[0] != '\0') {
        snprintf(line, sizeof(line), "- %s (all users from this IP, originally [%s])", entry->ip, entry->username);
      } else {
        snprintf(line, sizeof(line), "- %s (all users from this IP)", entry->ip);
      }
    } else if (entry->username[0] != '\0') {
      if (entry->ip[0] != '\0') {
        snprintf(line, sizeof(line), "- [%s] (only this user, IP %s)", entry->username, entry->ip);
      } else {
        snprintf(line, sizeof(line), "- [%s]", entry->username);
      }
    } else {
      snprintf(line, sizeof(line), "- entry #%zu", idx + 1U);
    }
    session_send_system_line(ctx, line);
  }
}

static bool session_bbs_should_defer_breaking(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || message == NULL) {
    return false;
  }

  if (!ctx->bbs_post_pending || ctx->bbs_rendering_editor) {
    return false;
  }

  if (strstr(message, SSH_CHATTER_RSS_BREAKING_PREFIX) != NULL) {
    return true;
  }

  if (strcasestr(message, "breaking news") != NULL || strcasestr(message, "breaking:") != NULL ||
      strcasestr(message, "urgent") != NULL || strcasestr(message, "alert") != NULL) {
    return true;
  }

  if (strstr(message, "속보") != NULL || strstr(message, "速報") != NULL) {
    return true;
  }

  return false;
}

static void session_bbs_buffer_breaking_notice(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || message == NULL) {
    return;
  }

  size_t limit = SSH_CHATTER_BBS_BREAKING_MAX;
  if (limit == 0U) {
    return;
  }

  if (ctx->bbs_breaking_count < limit) {
    snprintf(ctx->bbs_breaking_messages[ctx->bbs_breaking_count],
             sizeof(ctx->bbs_breaking_messages[ctx->bbs_breaking_count]), "%s", message);
    ctx->bbs_breaking_count += 1U;
  } else {
    for (size_t idx = 1U; idx < limit; ++idx) {
      snprintf(ctx->bbs_breaking_messages[idx - 1U], sizeof(ctx->bbs_breaking_messages[idx - 1U]), "%s",
               ctx->bbs_breaking_messages[idx]);
    }
    snprintf(ctx->bbs_breaking_messages[limit - 1U], sizeof(ctx->bbs_breaking_messages[limit - 1U]), "%s", message);
  }

  session_bbs_render_editor(ctx, NULL);
}

static bool session_should_hide_entry(session_ctx_t *ctx, const chat_history_entry_t *entry) {
  if (ctx == NULL || entry == NULL) {
    return false;
  }

  if (!entry->is_user_message) {
    return false;
  }

  if (ctx->block_entry_count == 0U) {
    return false;
  }

  if (strncmp(entry->username, ctx->user.name, SSH_CHATTER_USERNAME_LEN) == 0) {
    return false;
  }

  char entry_ip[SSH_CHATTER_IP_LEN] = {0};
  if (ctx->owner != NULL) {
    host_lookup_member_ip(ctx->owner, entry->username, entry_ip, sizeof(entry_ip));
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    const session_block_entry_t *block = &ctx->block_entries[idx];
    if (!block->in_use) {
      continue;
    }

    bool ip_match = false;
    bool user_match = false;

    if (block->ip[0] != '\0' && entry_ip[0] != '\0' &&
        strncmp(block->ip, entry_ip, SSH_CHATTER_IP_LEN) == 0) {
      ip_match = true;
    }

    if (block->username[0] != '\0' &&
        strncmp(block->username, entry->username, SSH_CHATTER_USERNAME_LEN) == 0) {
      user_match = true;
    }

    if (block->ip_wide) {
      if (ip_match) {
        return true;
      }
      if (!ip_match && entry_ip[0] == '\0' && user_match) {
        return true;
      }
    } else {
      if (user_match) {
        return true;
      }
    }
  }

  return false;
}

static void session_send_system_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || message == NULL) {
    return;
  }

  if (session_bbs_should_defer_breaking(ctx, message)) {
    session_bbs_buffer_breaking_notice(ctx, message);
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  if (message[0] == '\0') {
    char formatted_empty[SSH_CHATTER_MESSAGE_LIMIT];
    size_t offset = 0U;
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, bg);
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, fg);
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, bold);
    session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, ANSI_RESET);
    session_send_line(ctx, formatted_empty);
    return;
  }

  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 !ctx->in_bbs_mode && !ctx->in_rss_mode;
  const bool multiline_message = strchr(message, '\n') != NULL;
  bool translation_block = false;
  bool previous_suppress = ctx->translation_suppress_output;
  if (translation_ready && multiline_message && !ctx->translation_suppress_output) {
    translation_block = true;
    ctx->translation_suppress_output = true;
  }

  const char *cursor = message;
  for (;;) {
    const char *newline = strchr(cursor, '\n');
    size_t segment_length = newline != NULL ? (size_t)(newline - cursor) : strlen(cursor);
    if (segment_length >= SSH_CHATTER_MESSAGE_LIMIT) {
      segment_length = SSH_CHATTER_MESSAGE_LIMIT - 1U;
    }

    char segment[SSH_CHATTER_MESSAGE_LIMIT];
    memcpy(segment, cursor, segment_length);
    segment[segment_length] = '\0';

    char formatted[SSH_CHATTER_MESSAGE_LIMIT];
    size_t offset = 0U;
    offset = session_append_fragment(formatted, sizeof(formatted), offset, bg);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, fg);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, bold);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, segment);
    session_append_fragment(formatted, sizeof(formatted), offset, ANSI_RESET);
    session_send_line(ctx, formatted);

    if (newline == NULL) {
      break;
    }

    cursor = newline + 1;
    if (*cursor == '\r') {
      ++cursor;
    }

    if (*cursor == '\0') {
      char formatted_empty[SSH_CHATTER_MESSAGE_LIMIT];
      size_t empty_offset = 0U;
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, bg);
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, fg);
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, bold);
      session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, ANSI_RESET);
      session_send_line(ctx, formatted_empty);
      break;
    }
  }

  if (translation_block) {
    ctx->translation_suppress_output = previous_suppress;
    if (!ctx->translation_suppress_output) {
      session_translation_queue_block(ctx, message);
      session_translation_flush_ready(ctx);
    }
    return;
  }

  ctx->translation_suppress_output = previous_suppress;
}

static void session_send_raw_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || !session_transport_active(ctx) || text == NULL) {
    return;
  }

  const char *cursor = text;
  while (*cursor != '\0') {
    const char *newline = strchr(cursor, '\n');
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (newline == NULL) {
      snprintf(line, sizeof(line), "%s", cursor);
      session_send_plain_line(ctx, line);
      break;
    }

    size_t length = (size_t)(newline - cursor);
    if (length >= sizeof(line)) {
      length = sizeof(line) - 1U;
    }
    memcpy(line, cursor, length);
    line[length] = '\0';
    session_send_plain_line(ctx, line);

    cursor = newline + 1;
    if (*cursor == '\r') {
      ++cursor;
    }
    if (*cursor == '\0') {
      session_send_plain_line(ctx, "");
    }
  }
}

static void session_send_raw_text_bulk(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || text == NULL) {
    return;
  }

  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 !ctx->in_bbs_mode && !ctx->in_rss_mode;

  bool previous_suppress = ctx->translation_suppress_output;
  if (translation_ready && !ctx->translation_suppress_output) {
    ctx->translation_suppress_output = true;
  }

  session_send_raw_text(ctx, text);

  ctx->translation_suppress_output = previous_suppress;

  if (translation_ready && !previous_suppress && text[0] != '\0') {
    session_translation_queue_block(ctx, text);
    session_translation_flush_ready(ctx);
  }
}

static void session_send_system_lines_bulk(session_ctx_t *ctx, const char *const *lines, size_t line_count) {
  if (ctx == NULL || lines == NULL || line_count == 0U) {
    return;
  }

  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 !ctx->in_bbs_mode && !ctx->in_rss_mode;

  bool previous_suppress = ctx->translation_suppress_output;
  if (translation_ready && !ctx->translation_suppress_output) {
    ctx->translation_suppress_output = true;
  }

  char payload[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  payload[0] = '\0';
  size_t offset = 0U;

  for (size_t idx = 0U; idx < line_count; ++idx) {
    const char *line = lines[idx] != NULL ? lines[idx] : "";
    session_send_system_line(ctx, line);

    if (translation_ready && !previous_suppress) {
      size_t needed = strlen(line);
      if (idx + 1U < line_count) {
        ++needed;
      }

      if (needed >= sizeof(payload)) {
        if (offset > 0U && payload[0] != '\0') {
          payload[offset < sizeof(payload) ? offset : sizeof(payload) - 1U] = '\0';
          session_translation_queue_block(ctx, payload);
          session_translation_flush_ready(ctx);
          payload[0] = '\0';
          offset = 0U;
        }

        session_translation_queue_block(ctx, line);
        session_translation_flush_ready(ctx);
        continue;
      }

      if (offset > 0U && offset + needed >= sizeof(payload)) {
        payload[offset < sizeof(payload) ? offset : sizeof(payload) - 1U] = '\0';
        session_translation_queue_block(ctx, payload);
        session_translation_flush_ready(ctx);
        payload[0] = '\0';
        offset = 0U;
      }

      offset = session_append_fragment(payload, sizeof(payload), offset, line);
      if (idx + 1U < line_count) {
        offset = session_append_fragment(payload, sizeof(payload), offset, "\n");
      }
    }
  }

  ctx->translation_suppress_output = previous_suppress;

  if (translation_ready && !previous_suppress) {
    if (offset > 0U && payload[0] != '\0') {
      payload[offset < sizeof(payload) ? offset : sizeof(payload) - 1U] = '\0';
      session_translation_queue_block(ctx, payload);
    }
    session_translation_flush_ready(ctx);
  }
}

static void session_format_separator_line(session_ctx_t *ctx, const char *label, char *out, size_t length) {
  if (out == NULL || length == 0U) {
    return;
  }

  out[0] = '\0';

  if (ctx == NULL || label == NULL) {
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  const size_t total_width = 80U;
  char label_block[96];
  snprintf(label_block, sizeof(label_block), " %s ", label);
  size_t label_len = strnlen(label_block, sizeof(label_block) - 1U);
  if (label_len > total_width) {
    label_len = total_width;
    label_block[label_len] = '\0';
  }

  size_t dash_total = total_width > label_len ? total_width - label_len : 0U;
  size_t left = dash_total / 2U;
  size_t right = dash_total - left;

  char body[128];
  size_t offset = 0U;
  for (size_t idx = 0U; idx < left && offset + 1U < sizeof(body); ++idx) {
    body[offset++] = '-';
  }
  if (offset + label_len < sizeof(body)) {
    memcpy(body + offset, label_block, label_len);
    offset += label_len;
  }
  for (size_t idx = 0U; idx < right && offset + 1U < sizeof(body); ++idx) {
    body[offset++] = '-';
  }
  body[offset] = '\0';

  snprintf(out, length, "%s%s%s%s%s", hl, fg, bold, body, ANSI_RESET);
}

static void session_render_separator(session_ctx_t *ctx, const char *label) {
  if (ctx == NULL || label == NULL) {
    return;
  }

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  session_format_separator_line(ctx, label, line, sizeof(line));
  if (line[0] != '\0') {
    session_send_line(ctx, line);
  }
}

static void session_clear_screen(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  static const char kClearSequence[] = "\033[2J\033[H";
  session_channel_write(ctx, kClearSequence, sizeof(kClearSequence) - 1U);
}

static void session_bbs_prepare_canvas(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_clear_screen(ctx);
  session_apply_background_fill(ctx);
}

static void session_bbs_recalculate_line_count(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  size_t count = 0U;
  if (ctx->pending_bbs_body_length > 0U) {
    count = 1U;
    for (size_t idx = 0U; idx < ctx->pending_bbs_body_length; ++idx) {
      if (ctx->pending_bbs_body[idx] == '\n') {
        ++count;
      }
    }
  }

  ctx->pending_bbs_line_count = count;
  if (ctx->pending_bbs_cursor_line > count) {
    ctx->pending_bbs_cursor_line = count;
    ctx->pending_bbs_editing_line = false;
  }
}

static bool session_bbs_get_line_range(const session_ctx_t *ctx, size_t line_index, size_t *start, size_t *length) {
  if (ctx == NULL || start == NULL || length == NULL) {
    return false;
  }

  if (line_index >= ctx->pending_bbs_line_count) {
    return false;
  }

  size_t offset = 0U;
  size_t current = 0U;
  while (current < line_index && offset < ctx->pending_bbs_body_length) {
    const char *newline = memchr(ctx->pending_bbs_body + offset, '\n', ctx->pending_bbs_body_length - offset);
    if (newline == NULL) {
      return false;
    }
    offset = (size_t)(newline - ctx->pending_bbs_body) + 1U;
    ++current;
  }

  if (offset > ctx->pending_bbs_body_length) {
    return false;
  }

  size_t end = ctx->pending_bbs_body_length;
  const char *newline = memchr(ctx->pending_bbs_body + offset, '\n', ctx->pending_bbs_body_length - offset);
  if (newline != NULL) {
    end = (size_t)(newline - ctx->pending_bbs_body);
  }

  *start = offset;
  *length = end - offset;
  return true;
}

static void session_bbs_copy_line(const session_ctx_t *ctx, size_t line_index, char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return;
  }

  buffer[0] = '\0';
  size_t start = 0U;
  size_t line_length = 0U;
  if (!session_bbs_get_line_range(ctx, line_index, &start, &line_length)) {
    return;
  }

  if (line_length >= length) {
    line_length = length - 1U;
  }

  if (line_length > 0U) {
    memcpy(buffer, ctx->pending_bbs_body + start, line_length);
  }
  buffer[line_length] = '\0';
}

static bool session_bbs_append_line(session_ctx_t *ctx, const char *line, char *status, size_t status_length) {
  if (ctx == NULL) {
    return false;
  }

  if (status != NULL && status_length > 0U) {
    status[0] = '\0';
  }

  if (line == NULL) {
    line = "";
  }

  size_t available = sizeof(ctx->pending_bbs_body) - ctx->pending_bbs_body_length - 1U;
  if (available == 0U) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Post body length limit reached. Additional text ignored.");
    }
    return false;
  }

  bool needs_newline = ctx->pending_bbs_body_length > 0U;
  if (needs_newline) {
    ctx->pending_bbs_body[ctx->pending_bbs_body_length++] = '\n';
    --available;
  }

  size_t line_length = strlen(line);
  if (line_length > available) {
    line_length = available;
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Line truncated to fit within the post size limit.");
    }
  }

  if (line_length > 0U) {
    memcpy(ctx->pending_bbs_body + ctx->pending_bbs_body_length, line, line_length);
    ctx->pending_bbs_body_length += line_length;
  }

  ctx->pending_bbs_body[ctx->pending_bbs_body_length] = '\0';
  session_bbs_recalculate_line_count(ctx);
  ctx->pending_bbs_cursor_line = ctx->pending_bbs_line_count;
  ctx->pending_bbs_editing_line = false;
  return true;
}

static bool session_bbs_replace_line(session_ctx_t *ctx, size_t line_index, const char *line, char *status,
                                     size_t status_length) {
  if (ctx == NULL || line == NULL) {
    return false;
  }

  if (status != NULL && status_length > 0U) {
    status[0] = '\0';
  }

  session_bbs_recalculate_line_count(ctx);
  if (line_index >= ctx->pending_bbs_line_count) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Unable to locate the selected line.");
    }
    return false;
  }

  size_t start = 0U;
  size_t old_length = 0U;
  if (!session_bbs_get_line_range(ctx, line_index, &start, &old_length)) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Unable to locate the selected line.");
    }
    return false;
  }

  size_t current_length = ctx->pending_bbs_body_length;
  size_t capacity = sizeof(ctx->pending_bbs_body) - 1U;
  size_t base_length = current_length - old_length;
  size_t max_allowed = capacity - base_length;

  size_t new_length = strlen(line);
  if (new_length > max_allowed) {
    new_length = max_allowed;
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Line truncated to fit within the post size limit.");
    }
  }

  size_t tail_offset = start + old_length;
  size_t tail_bytes = current_length - tail_offset + 1U;

  if (new_length > old_length) {
    size_t shift = new_length - old_length;
    memmove(ctx->pending_bbs_body + tail_offset + shift, ctx->pending_bbs_body + tail_offset, tail_bytes);
  } else if (old_length > new_length) {
    size_t shift = old_length - new_length;
    memmove(ctx->pending_bbs_body + tail_offset - shift, ctx->pending_bbs_body + tail_offset, tail_bytes);
    tail_offset -= shift;
  }

  if (new_length > 0U) {
    memcpy(ctx->pending_bbs_body + start, line, new_length);
  }

  ctx->pending_bbs_body_length = base_length + new_length;
  ctx->pending_bbs_body[ctx->pending_bbs_body_length] = '\0';

  session_bbs_recalculate_line_count(ctx);
  size_t updated_count = ctx->pending_bbs_line_count;
  if (line_index + 1U <= updated_count) {
    ctx->pending_bbs_cursor_line = line_index + 1U;
  } else {
    ctx->pending_bbs_cursor_line = updated_count;
  }
  ctx->pending_bbs_editing_line = false;
  return true;
}

static void session_bbs_render_editor(session_ctx_t *ctx, const char *status) {
  if (ctx == NULL) {
    return;
  }

  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;
  ctx->bbs_rendering_editor = true;

  session_bbs_prepare_canvas(ctx);

  char title_line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(title_line, sizeof(title_line), "Composing '%s'", ctx->pending_bbs_title);
  session_send_system_line(ctx, title_line);

  char tag_buffer[SSH_CHATTER_BBS_MAX_TAGS * (SSH_CHATTER_BBS_TAG_LEN + 2U)];
  tag_buffer[0] = '\0';
  size_t offset = 0U;
  for (size_t idx = 0U; idx < ctx->pending_bbs_tag_count; ++idx) {
    size_t remaining = sizeof(tag_buffer) - offset;
    if (remaining == 0U) {
      break;
    }
    int written = snprintf(tag_buffer + offset, remaining, "%s%s", idx > 0U ? "," : "", ctx->pending_bbs_tags[idx]);
    if (written < 0) {
      break;
    }
    if ((size_t)written >= remaining) {
      offset = sizeof(tag_buffer) - 1U;
      break;
    }
    offset += (size_t)written;
  }

  char tags_line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(tags_line, sizeof(tags_line), "Tags: %s", tag_buffer[0] != '\0' ? tag_buffer : "(none)");
  session_send_system_line(ctx, tags_line);

  session_send_system_line(ctx, SSH_CHATTER_BBS_EDITOR_BODY_DIVIDER);

  session_bbs_recalculate_line_count(ctx);
  if (ctx->pending_bbs_line_count == 0U) {
    const char *prefix = ctx->pending_bbs_editing_line ? "> " : "> ";
    session_send_line(ctx, prefix);
  } else {
    for (size_t idx = 0U; idx < ctx->pending_bbs_line_count; ++idx) {
      char line_buffer[SSH_CHATTER_MESSAGE_LIMIT];
      session_bbs_copy_line(ctx, idx, line_buffer, sizeof(line_buffer));
      bool selected = ctx->pending_bbs_editing_line && ctx->pending_bbs_cursor_line == idx;
      const char *prefix = selected ? "> " : "  ";
      char display[SSH_CHATTER_MESSAGE_LIMIT];
      if (line_buffer[0] == '\0') {
        snprintf(display, sizeof(display), "%s", prefix);
      } else {
        snprintf(display, sizeof(display), "%s%s", prefix, line_buffer);
      }
      session_send_line(ctx, display);
    }
    if (!ctx->pending_bbs_editing_line) {
      session_send_line(ctx, "> ");
    }
  }

  session_send_system_line(ctx, SSH_CHATTER_BBS_EDITOR_END_DIVIDER);

  size_t remaining = sizeof(ctx->pending_bbs_body) - ctx->pending_bbs_body_length - 1U;
  char remaining_line[64];
  snprintf(remaining_line, sizeof(remaining_line), "Remaining bytes: %zu", remaining);
  session_send_system_line(ctx, remaining_line);

  session_send_system_line(ctx,
                           "Ctrl+S inserts " SSH_CHATTER_BBS_TERMINATOR ". Ctrl+A cancels the draft.");
  session_send_system_line(ctx, "Use Up/Down arrows to revisit a saved line and press Enter to store changes.");
  session_send_system_line(ctx,
                           "Typing " SSH_CHATTER_BBS_TERMINATOR " on its own line will publish the post.");

  if (ctx->bbs_breaking_count > 0U) {
    session_send_system_line(ctx, "");
    session_send_system_line(ctx, "Breaking updates:");
    for (size_t idx = 0U; idx < ctx->bbs_breaking_count; ++idx) {
      session_send_system_line(ctx, ctx->bbs_breaking_messages[idx]);
    }
  }

  if (status != NULL && status[0] != '\0') {
    char working[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(working, sizeof(working), "%s", status);
    char *cursor = working;
    while (cursor != NULL && *cursor != '\0') {
      char *newline = strchr(cursor, '\n');
      if (newline != NULL) {
        *newline = '\0';
      }
      if (*cursor != '\0') {
        session_send_system_line(ctx, cursor);
      }
      if (newline == NULL) {
        break;
      }
      cursor = newline + 1;
    }
  }

  session_render_prompt(ctx, false);
  ctx->bbs_rendering_editor = false;
}

static void session_bbs_move_cursor(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || direction == 0) {
    return;
  }

  session_bbs_recalculate_line_count(ctx);
  size_t line_count = ctx->pending_bbs_line_count;

  if (line_count == 0U) {
    ctx->pending_bbs_cursor_line = 0U;
    ctx->pending_bbs_editing_line = false;
    session_set_input_text(ctx, "");
    session_bbs_render_editor(ctx, NULL);
    return;
  }

  size_t target = ctx->pending_bbs_cursor_line;
  bool editing = ctx->pending_bbs_editing_line;
  if (target > line_count) {
    target = line_count;
  }

  if (direction < 0) {
    if (!editing) {
      target = line_count - 1U;
      editing = true;
    } else {
      if (target > 0U) {
        --target;
      }
    }
  } else {
    if (editing) {
      if (target + 1U < line_count) {
        ++target;
      } else {
        target = line_count;
        editing = false;
      }
    }
  }

  ctx->pending_bbs_cursor_line = target;
  ctx->pending_bbs_editing_line = editing;

  char status[64];
  status[0] = '\0';

  if (editing && target < line_count) {
    char line_buffer[SSH_CHATTER_MAX_INPUT_LEN];
    session_bbs_copy_line(ctx, target, line_buffer, sizeof(line_buffer));
    session_set_input_text(ctx, line_buffer);
    snprintf(status, sizeof(status), "Editing line %zu of %zu.", target + 1U, line_count);
  } else {
    session_set_input_text(ctx, "");
    snprintf(status, sizeof(status), "Editing new line %zu.", line_count + 1U);
  }

  session_bbs_render_editor(ctx, status);
}

static void session_render_banner(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_apply_background_fill(ctx);

  static const char *kBanner[] = {
    "\033[1;35m+===================================================================+\033[0m",
    "\033[1;36m|  ██████╗██╗  ██╗ █████╗ ████████╗████████╗███████╗██████╗         |\033[0m",
    "\033[1;36m| ██╔════╝██║  ██║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗        |\033[0m",
    "\033[1;34m| ██║     ███████║███████║   ██║      ██║   █████╗  ██████╔╝        |\033[0m",
    "\033[1;34m| ██║     ██╔══██║██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗        |\033[0m",
    "\033[1;32m| ╚██████╗██║  ██║██║  ██║   ██║      ██║   ███████╗██║  ██║        |\033[0m",
    "\033[1;32m|  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝        |\033[0m",
    "\033[1;35m+===================================================================+\033[0m",
    "\033[1;36m|        *** Welcome to CHATTER (2025) ***                          |\033[0m",
    "\033[1;35m|   Cute and tiny SSH chat written in C.                            |\033[0m",
    "\033[1;36m|   Type \033[1;33m/help\033[1;36m to see available commands.                           |\033[0m",
    "\033[1;36m|   Type \033[1;33m/mode\033[1;36m to switch input modes.                               |\033[0m",
    "\033[1;35m+===================================================================+\033[0m",
  };

  for (size_t idx = 0; idx < sizeof(kBanner) / sizeof(kBanner[0]); ++idx) {
    session_send_system_line(ctx, kBanner[idx]);
  }

  char welcome[SSH_CHATTER_MESSAGE_LIMIT];
  size_t name_len = 0;
  if (ctx->user.name[0] != '\0')
    name_len = strlen(ctx->user.name);
  int welcome_padding = 55 - (int)name_len;
  if (welcome_padding < 0) {
    welcome_padding = 0;
  }

  snprintf(welcome, sizeof(welcome), "\033[1;32m|  Welcome, %s!%*s|\033[0m", ctx->user.name, welcome_padding, "");
  session_send_system_line(ctx, welcome);

  char version_line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t version_len = strlen(ctx->owner->version);
  int version_padding = 65 - (int)version_len;
  if (version_padding < 0) {
    version_padding = 0;
  }
  snprintf(version_line, sizeof(version_line), "\033[1;32m|  %s%*s|\033[0m", ctx->owner->version, version_padding, "");
  session_send_system_line(ctx, version_line);
  session_send_system_line(ctx, "\033[1;32m+===================================================================+\033[0m");
  session_render_separator(ctx, "Chatroom");
}

static void session_render_prompt(session_ctx_t *ctx, bool include_separator) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  if (include_separator) {
    session_render_separator(ctx, "Input");
  }

  session_apply_background_fill(ctx);

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const char *mode_prompt = ctx->input_mode == SESSION_INPUT_MODE_COMMAND ? "│ cmd> " : "│ > ";

  char prompt[128];
  size_t offset = 0U;
  offset = session_append_fragment(prompt, sizeof(prompt), offset, hl);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, fg);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, bold);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, mode_prompt);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, ANSI_RESET);
  if (bg[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, bg);
  }
  if (fg[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, fg);
  }
  if (bold[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, bold);
  }

  session_channel_write(ctx, prompt, offset);
  if (ctx->input_length > 0U) {
    session_channel_write(ctx, ctx->input_buffer, ctx->input_length);
  }
}

static void session_refresh_input_line(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  if (bg[0] != '\0') {
    session_channel_write(ctx, bg, strlen(bg));
  }

  static const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);

  if (bg[0] != '\0') {
    session_channel_write(ctx, bg, strlen(bg));
  }

  session_render_prompt(ctx, false);
}

static void session_set_input_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));

  if (text != NULL && text[0] != '\0') {
    const size_t len = strnlen(text, sizeof(ctx->input_buffer) - 1U);
    memcpy(ctx->input_buffer, text, len);
    ctx->input_buffer[len] = '\0';
    ctx->input_length = len;
  }

  session_refresh_input_line(ctx);
}

static void session_local_echo_char(session_ctx_t *ctx, char ch) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  if (ch == '\r' || ch == '\n') {
    session_channel_write(ctx, "\r\n", 2U);
    return;
  }

  session_channel_write(ctx, &ch, 1U);
}

static size_t session_utf8_prev_char_len(const char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return 0U;
  }

  size_t idx = length;
  while (idx > 0U) {
    --idx;
    const unsigned char byte = (unsigned char)buffer[idx];
    if ((byte & 0xC0U) != 0x80U) {
      const size_t seq_len = length - idx;
      size_t expected = 1U;
      if ((byte & 0x80U) == 0U) {
        expected = 1U;
      } else if ((byte & 0xE0U) == 0xC0U) {
        expected = 2U;
      } else if ((byte & 0xF0U) == 0xE0U) {
        expected = 3U;
      } else if ((byte & 0xF8U) == 0xF0U) {
        expected = 4U;
      } else {
        expected = 1U;
      }

      if (seq_len < expected) {
        return seq_len;
      }
      return expected;
    }
  }

  return 1U;
}

static int session_utf8_char_width(const char *bytes, size_t length) {
  if (bytes == NULL || length == 0U) {
    return 0;
  }

  mbstate_t state;
  memset(&state, 0, sizeof(state));

  wchar_t wc;
  const size_t result = mbrtowc(&wc, bytes, length, &state);
  if (result == (size_t)-1 || result == (size_t)-2) {
    return 1;
  }

  const int width = wcwidth(wc);
  if (width < 0) {
    return 1;
  }

  return width;
}

static void session_local_backspace(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx) || ctx->input_length == 0U) {
    return;
  }

  const size_t char_len = session_utf8_prev_char_len(ctx->input_buffer, ctx->input_length);
  if (char_len == 0U || char_len > ctx->input_length) {
    return;
  }

  const size_t char_start = ctx->input_length - char_len;
  const int display_width = session_utf8_char_width(&ctx->input_buffer[char_start], char_len);

  ctx->input_length = char_start;
  ctx->input_buffer[ctx->input_length] = '\0';

  const int width = display_width > 0 ? display_width : 1;
  const char sequence[] = "\b \b";
  for (int idx = 0; idx < width; ++idx) {
    session_channel_write(ctx, sequence, sizeof(sequence) - 1U);
  }
}

static void session_clear_input(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));
  ctx->input_history_position = -1;
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (!ctx->bracket_paste_active) {
    session_refresh_input_line(ctx);
  }
}

static bool session_try_command_completion(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->input_length == 0U) {
    return false;
  }

  size_t first_visible = 0U;
  while (first_visible < ctx->input_length && isspace((unsigned char)ctx->input_buffer[first_visible])) {
    ++first_visible;
  }
  if (first_visible >= ctx->input_length) {
    return false;
  }

  const bool has_slash = ctx->input_buffer[first_visible] == '/';
  if (!has_slash && ctx->input_mode != SESSION_INPUT_MODE_COMMAND) {
    return false;
  }

  size_t command_start = first_visible + (has_slash ? 1U : 0U);
  if (command_start > ctx->input_length) {
    command_start = ctx->input_length;
  }

  size_t command_end = command_start;
  while (command_end < ctx->input_length && !isspace((unsigned char)ctx->input_buffer[command_end])) {
    ++command_end;
  }

  const size_t token_len = command_end - command_start;
  char prefix[SSH_CHATTER_MAX_INPUT_LEN];
  size_t copy_len = token_len < sizeof(prefix) - 1U ? token_len : sizeof(prefix) - 1U;
  if (copy_len > 0U) {
    memcpy(prefix, &ctx->input_buffer[command_start], copy_len);
  }
  prefix[copy_len] = '\0';

  const size_t prefix_len = strlen(prefix);
  const char *matches[SSH_CHATTER_COMMAND_COUNT];
  size_t match_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_COMMAND_COUNT; ++idx) {
    const char *candidate = kSessionCommandNames[idx];
    if (prefix_len == 0U || strncasecmp(candidate, prefix, prefix_len) == 0) {
      matches[match_count++] = candidate;
    }
  }

  if (match_count == 0U) {
    if (session_transport_active(ctx)) {
      const char bell = '\a';
      session_channel_write(ctx, &bell, 1U);
    }
    session_refresh_input_line(ctx);
    return true;
  }

  char updated[SSH_CHATTER_MAX_INPUT_LEN];
  size_t updated_len = 0U;
  const size_t prefix_copy_len = command_start < sizeof(updated) ? command_start : sizeof(updated) - 1U;
  if (prefix_copy_len > 0U) {
    memcpy(updated, ctx->input_buffer, prefix_copy_len);
    updated_len = prefix_copy_len;
  }

  if (match_count == 1U) {
    const char *completion = matches[0];
    size_t completion_len = strlen(completion);
    if (updated_len + completion_len >= sizeof(updated)) {
      completion_len = sizeof(updated) - 1U - updated_len;
    }
    memcpy(&updated[updated_len], completion, completion_len);
    updated_len += completion_len;

    size_t suffix_len = ctx->input_length - command_end;
    if (suffix_len > 0U) {
      size_t copy_suffix = suffix_len;
      if (updated_len + copy_suffix >= sizeof(updated)) {
        copy_suffix = sizeof(updated) - 1U - updated_len;
      }
      memcpy(&updated[updated_len], &ctx->input_buffer[command_end], copy_suffix);
      updated_len += copy_suffix;
    } else if (updated_len + 1U < sizeof(updated)) {
      updated[updated_len++] = ' ';
    }

    updated[updated_len] = '\0';
    session_set_input_text(ctx, updated);
    ctx->input_history_position = -1;
    ctx->history_scroll_position = 0U;
    return true;
  }

  size_t common_len = strlen(matches[0]);
  for (size_t idx = 1U; idx < match_count && common_len > 0U; ++idx) {
    const char *candidate = matches[idx];
    size_t candidate_len = strlen(candidate);
    if (candidate_len < common_len) {
      common_len = candidate_len;
    }
    size_t compare_len = common_len;
    size_t match_prefix = 0U;
    for (; match_prefix < compare_len; ++match_prefix) {
      unsigned char lhs = (unsigned char)tolower((unsigned char)matches[0][match_prefix]);
      unsigned char rhs = (unsigned char)tolower((unsigned char)candidate[match_prefix]);
      if (lhs != rhs) {
        break;
      }
    }
    common_len = match_prefix;
  }

  if (common_len > prefix_len) {
    size_t completion_len = common_len;
    if (updated_len + completion_len >= sizeof(updated)) {
      completion_len = sizeof(updated) - 1U - updated_len;
    }
    memcpy(&updated[updated_len], matches[0], completion_len);
    updated_len += completion_len;

    size_t suffix_len = ctx->input_length - command_end;
    if (suffix_len > 0U) {
      size_t copy_suffix = suffix_len;
      if (updated_len + copy_suffix >= sizeof(updated)) {
        copy_suffix = sizeof(updated) - 1U - updated_len;
      }
      memcpy(&updated[updated_len], &ctx->input_buffer[command_end], copy_suffix);
      updated_len += copy_suffix;
    }

    updated[updated_len] = '\0';
    session_set_input_text(ctx, updated);
    ctx->input_history_position = -1;
    ctx->history_scroll_position = 0U;
    return true;
  }

  session_send_system_line(ctx, "Possible commands:");
  char line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t offset = 0U;
  for (size_t idx = 0U; idx < match_count; ++idx) {
    char entry[64];
    snprintf(entry, sizeof(entry), "/%s", matches[idx]);
    size_t entry_len = strlen(entry);
    if (offset != 0U) {
      if (offset + 1U >= sizeof(line)) {
        line[offset] = '\0';
        session_send_system_line(ctx, line);
        offset = 0U;
      }
      line[offset++] = ' ';
    }
    if (entry_len >= sizeof(line)) {
      session_send_system_line(ctx, entry);
      offset = 0U;
      continue;
    }
    if (offset + entry_len >= sizeof(line)) {
      line[offset] = '\0';
      session_send_system_line(ctx, line);
      offset = 0U;
    }
    memcpy(&line[offset], entry, entry_len);
    offset += entry_len;
  }
  if (offset > 0U) {
    line[offset] = '\0';
    session_send_system_line(ctx, line);
  }
  session_refresh_input_line(ctx);
  return true;
}

static void session_history_record(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL) {
    return;
  }

  bool has_visible = false;
  for (const char *cursor = line; *cursor != '\0'; ++cursor) {
    if (!isspace((unsigned char)*cursor)) {
      has_visible = true;
      break;
    }
  }

  if (!has_visible) {
    ctx->input_history_position = -1;
    return;
  }

  if (ctx->input_history_count > 0U) {
    const size_t last_index = ctx->input_history_count - 1U;
    if (strncmp(ctx->input_history[last_index], line, sizeof(ctx->input_history[last_index])) == 0) {
      ctx->input_history_position = -1;
      return;
    }
  }

  if (ctx->input_history_count < SSH_CHATTER_INPUT_HISTORY_LIMIT) {
    snprintf(ctx->input_history[ctx->input_history_count], sizeof(ctx->input_history[0]), "%s", line);
    ++ctx->input_history_count;
  } else {
    memmove(ctx->input_history, ctx->input_history + 1,
            sizeof(ctx->input_history) - sizeof(ctx->input_history[0]));
    snprintf(ctx->input_history[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U], sizeof(ctx->input_history[0]), "%s", line);
  }

  ctx->input_history_position = -1;
  ctx->history_scroll_position = 0U;
}

static void session_history_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || direction == 0) {
    return;
  }

  ctx->history_scroll_position = 0U;

  if (ctx->input_history_count == 0U) {
    ctx->input_history_position = (int)ctx->input_history_count;
    session_set_input_text(ctx, "");
    return;
  }

  int position = ctx->input_history_position;
  if (position < 0 || position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  position += direction;
  if (position < 0) {
    position = 0;
  }
  if (position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  ctx->input_history_position = position;

  if (position == (int)ctx->input_history_count) {
    session_set_input_text(ctx, "");
  } else {
    session_set_input_text(ctx, ctx->input_history[position]);
  }
}

static void session_scrollback_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || ctx->owner == NULL || !session_transport_active(ctx) || direction == 0) {
    return;
  }

  size_t total = host_history_total(ctx->owner);
  if (total == 0U) {
    session_send_system_line(ctx, "No chat history available yet.");
    return;
  }

  bool suppress_translation = translator_should_skip_scrollback_translation();
  bool previous_translation_suppress = ctx->translation_suppress_output;
  if (suppress_translation) {
    ctx->translation_suppress_output = true;
  }

  const size_t step = SSH_CHATTER_SCROLLBACK_CHUNK > 0 ? SSH_CHATTER_SCROLLBACK_CHUNK : 1U;
  if (ctx->history_scroll_position >= total) {
    ctx->history_scroll_position = total > 0U ? total - 1U : 0U;
  }
  size_t position = ctx->history_scroll_position;
  size_t new_position = position;
  bool reached_oldest = false;

  const size_t max_position = total > 0U ? total - 1U : 0U;

  if (direction > 0) {
    size_t current_newest_visible = 0U;
    if (position < total) {
      current_newest_visible = total - 1U - position;
    }

    size_t current_chunk = step;
    if (current_chunk > current_newest_visible + 1U) {
      current_chunk = current_newest_visible + 1U;
    }
    if (current_chunk == 0U) {
      current_chunk = 1U;
    }

    const size_t current_oldest_visible =
        (current_newest_visible + 1U > current_chunk) ? (current_newest_visible + 1U - current_chunk) : 0U;

    if (current_oldest_visible == 0U) {
      reached_oldest = true;
    } else if (new_position < max_position) {
      size_t advance = step;
      if (advance > max_position - new_position) {
        advance = max_position - new_position;
      }
      if (advance == 0U) {
        reached_oldest = true;
      } else {
        new_position += advance;
      }
    } else {
      reached_oldest = true;
    }
  } else if (direction < 0) {
    if (new_position > 0U) {
      size_t retreat = step;
      if (retreat > new_position) {
        retreat = new_position;
      }
      new_position -= retreat;
    }
  }

  bool at_boundary = (new_position == position);
  ctx->history_scroll_position = new_position;

  const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);
  session_channel_write(ctx, "\r\n", 2U);

  if (direction < 0 && at_boundary && new_position == 0U) {
    if (position == 0U) {
      session_send_system_line(ctx, "Already at the latest messages.");
    }
    session_render_prompt(ctx, false);
    goto cleanup;
  }

  const size_t newest_visible = total - 1U - new_position;
  size_t chunk = step;
  if (chunk > newest_visible + 1U) {
    chunk = newest_visible + 1U;
  }
  if (chunk == 0U) {
    chunk = 1U;
  }

  const size_t oldest_visible = (newest_visible + 1U > chunk) ? (newest_visible + 1U - chunk) : 0U;

  if (direction > 0 && (reached_oldest || (at_boundary && new_position == max_position))) {
    session_send_system_line(ctx, "Reached the oldest stored message.");
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Scrollback (%zu-%zu of %zu)", oldest_visible + 1U, newest_visible + 1U, total);
  session_send_system_line(ctx, header);

  chat_history_entry_t buffer[SSH_CHATTER_SCROLLBACK_CHUNK];
  size_t request = chunk;
  if (request > SSH_CHATTER_SCROLLBACK_CHUNK) {
    request = SSH_CHATTER_SCROLLBACK_CHUNK;
  }
  size_t copied = host_history_copy_range(ctx->owner, oldest_visible, buffer, request);
  if (copied == 0U) {
    session_send_system_line(ctx, "Unable to read chat history right now.");
    session_render_prompt(ctx, false);
    goto cleanup;
  }

  for (size_t idx = 0; idx < copied; ++idx) {
    session_send_history_entry(ctx, &buffer[idx]);
  }

  if (direction < 0 && new_position == 0U) {
    session_send_system_line(ctx, "End of scrollback.");
  }

  session_render_prompt(ctx, false);

cleanup:
  if (suppress_translation) {
    ctx->translation_suppress_output = previous_translation_suppress;
  }
}

static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch) {
  if (ctx == NULL) {
    return false;
  }

  if (!ctx->input_escape_active) {
    if (ch == 0x1b) {
      ctx->input_escape_active = true;
      ctx->input_escape_length = 0U;
      if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
        ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
      }
      return true;
    }
    return false;
  }

  if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
    ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
  }

  const char *sequence = ctx->input_escape_buffer;
  const size_t length = ctx->input_escape_length;

  if (length == 1U) {
    return true;
  }

  if (length == 2U) {
    if (sequence[1] == '[') {
      return true;
    }
    if (sequence[1] == 'k') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
      } else {
        if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
          ctx->input_escape_active = false;
          ctx->input_escape_length = 0U;
          return true;
        }
        session_history_navigate(ctx, -1);
      }
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[1] == 'j') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
      } else {
        if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
          ctx->input_escape_active = false;
          ctx->input_escape_length = 0U;
          return true;
        }
        session_history_navigate(ctx, 1);
      }
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if ((sequence[1] == 'l' || sequence[1] == 'L') && ctx->game.active && ctx->game.type == SESSION_GAME_ALPHA) {
      session_game_alpha_manual_lock(ctx);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == '[') {
    int dx = 0;
    int dy = 0;
    switch (sequence[2]) {
      case 'A':
        dy = -1;
        break;
      case 'B':
        dy = 1;
        break;
      case 'C':
        dx = 1;
        break;
      case 'D':
        dx = -1;
        break;
      default:
        break;
    }
    if ((dx != 0 || dy != 0) && session_game_alpha_handle_arrow(ctx, dx, dy)) {
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'A') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == 'O') {
    int dx = 0;
    int dy = 0;
    switch (sequence[2]) {
      case 'A':
        dy = -1;
        break;
      case 'B':
        dy = 1;
        break;
      case 'C':
        dx = 1;
        break;
      case 'D':
        dx = -1;
        break;
      default:
        break;
    }
    if ((dx != 0 || dy != 0) && session_game_alpha_handle_arrow(ctx, dx, dy)) {
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'A') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 4U && sequence[1] == '[' && sequence[3] == '~') {
    if (sequence[2] == '5') {
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 0U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == '6') {
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 0U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  const bool bracket_sequence = (length >= 2U && sequence[1] == '[');
  if (bracket_sequence) {
    const char final = sequence[length - 1U];
    if (final != '~' && !(length == 3U && isalpha((unsigned char)sequence[2]))) {
      return true;
    }
    if (final == '~') {
      if (length >= 5U && strncmp(&sequence[2], "200", 3) == 0) {
        ctx->bracket_paste_active = true;
      } else if (length >= 5U && strncmp(&sequence[2], "201", 3) == 0) {
        ctx->bracket_paste_active = false;
        session_refresh_input_line(ctx);
      }
    }
  }

  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (bracket_sequence) {
    return true;
  }
  return ch == 0x1b;
}

static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source, const char *label,
                                              const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || color_source == NULL || label == NULL || message == NULL) {
    return;
  }

  const char *highlight = color_source->user_highlight_code != NULL ? color_source->user_highlight_code : "";
  const char *color = color_source->user_color_code != NULL ? color_source->user_color_code : "";
  const char *bold = color_source->user_is_bold ? ANSI_BOLD : "";

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color, label, ANSI_RESET, message);
  session_send_line(ctx, line);

  if (ctx != color_source && ctx->history_scroll_position == 0U) {
    session_refresh_input_line(ctx);
  }
}

static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry) {
  if (ctx == NULL || !session_transport_active(ctx) || entry == NULL) {
    return;
  }

  if (session_should_hide_entry(ctx, entry)) {
    return;
  }

  if (entry->is_user_message) {
    bool previous_override = session_translation_push_scope_override(ctx);
    const char *highlight = entry->user_highlight_code != NULL ? entry->user_highlight_code : "";
    const char *color = entry->user_color_code != NULL ? entry->user_color_code : "";
    const char *bold = entry->user_is_bold ? ANSI_BOLD : "";

    const char *message_text = entry->message;
    char fallback[SSH_CHATTER_MESSAGE_LIMIT + 64];
    if ((message_text == NULL || message_text[0] == '\0') && entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(fallback, sizeof(fallback), "shared a %s", label);
      message_text = fallback;
    } else if (message_text == NULL) {
      message_text = "";
    }

    bool multiline_message = strchr(message_text, '\n') != NULL;
    const char *header_body = message_text;
    if (multiline_message) {
      header_body = "shared ASCII art:";
    }

    char header[SSH_CHATTER_MESSAGE_LIMIT + 128];
    if (entry->message_id > 0U) {
      snprintf(header, sizeof(header), "[#%" PRIu64 "] %s%s%s[%s]%s %s", entry->message_id, highlight, bold, color,
               entry->username, ANSI_RESET, header_body);
    } else {
      snprintf(header, sizeof(header), "%s%s%s[%s]%s %s", highlight, bold, color, entry->username, ANSI_RESET,
               header_body);
    }
    session_send_plain_line(ctx, header);

    if (multiline_message) {
      const char *line_start = message_text;
      while (line_start != NULL) {
        const char *newline = strchr(line_start, '\n');
        size_t segment_length = newline != NULL ? (size_t)(newline - line_start) : strlen(line_start);
        char line[SSH_CHATTER_MESSAGE_LIMIT + 1U];
        if (segment_length >= sizeof(line)) {
          segment_length = sizeof(line) - 1U;
        }
        if (segment_length > 0U) {
          memcpy(line, line_start, segment_length);
        }
        line[segment_length] = '\0';
        session_send_plain_line(ctx, line);
        if (newline == NULL) {
          break;
        }
        line_start = newline + 1;
      }
    }

    char attachment_line[SSH_CHATTER_ATTACHMENT_TARGET_LEN + 64];
    if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(attachment_line, sizeof(attachment_line), "    ↳ %s: %s", label, entry->attachment_target);
      session_send_plain_line(ctx, attachment_line);
    }

    char caption_line[SSH_CHATTER_ATTACHMENT_CAPTION_LEN + 32];
    if (entry->attachment_caption[0] != '\0') {
      snprintf(caption_line, sizeof(caption_line), "    ↳ note: %s", entry->attachment_caption);
      session_send_plain_line(ctx, caption_line);
    }

    char reactions_line[SSH_CHATTER_MESSAGE_LIMIT];
    if (chat_history_entry_build_reaction_summary(entry, reactions_line, sizeof(reactions_line))) {
      char summary_line[SSH_CHATTER_MESSAGE_LIMIT + 32];
      snprintf(summary_line, sizeof(summary_line), "    ↳ reactions: %s", reactions_line);
      session_send_plain_line(ctx, summary_line);
    }

    if (entry->attachment_type == CHAT_ATTACHMENT_IMAGE && entry->message_id > 0U) {
      char hint[SSH_CHATTER_MESSAGE_LIMIT];
      session_send_plain_line(ctx, hint);
    }

    if (entry->message_id > 0U) {
      session_send_reply_tree(ctx, entry->message_id, 0U, 1U);
    }

    session_translation_pop_scope_override(ctx, previous_override);
  } else {
    session_send_system_line(ctx, entry->message);
  }
}

// Present a summary of a poll, optionally showing the label used for named polls.
static void session_send_poll_summary_generic(session_ctx_t *ctx, const poll_state_t *poll, const char *label) {
  if (ctx == NULL || poll == NULL) {
    return;
  }

  if (!poll->active || poll->option_count == 0U) {
    if (label == NULL) {
      session_send_system_line(ctx, "No active poll right now.");
    } else {
      char message[128];
      snprintf(message, sizeof(message), "Poll '%s' is not active.", label);
      session_send_system_line(ctx, message);
    }
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT + 64];
  const char *mode_suffix = poll->allow_multiple ? " (multiple choice)" : "";
  if (label == NULL) {
    snprintf(header, sizeof(header), "Poll #%" PRIu64 ": %s%s", poll->id, poll->question, mode_suffix);
  } else {
    snprintf(header, sizeof(header), "Poll [%s] #%" PRIu64 ": %s%s", label, poll->id, poll->question, mode_suffix);
  }
  session_send_system_line(ctx, header);

  for (size_t idx = 0U; idx < poll->option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT + 64];
    uint32_t votes = poll->options[idx].votes;
    if (label == NULL) {
      snprintf(option_line, sizeof(option_line), "  /%zu - %s (%u vote%s)", idx + 1U, poll->options[idx].text, votes,
               votes == 1U ? "" : "s");
    } else {
      snprintf(option_line, sizeof(option_line), "  /%zu %s - %s (%u vote%s)", idx + 1U, label, poll->options[idx].text, votes,
               votes == 1U ? "" : "s");
    }
    session_send_system_line(ctx, option_line);
  }

  if (label == NULL) {
    if (poll->allow_multiple) {
      session_send_system_line(ctx, "Vote with /1 through /5 (multiple selections allowed).");
    } else {
      session_send_system_line(ctx, "Vote with /1 through /5.");
    }
  } else {
    char footer[192];
    if (poll->allow_multiple) {
      snprintf(footer, sizeof(footer), "Vote with /1 %s through /%zu %s (multiple selections allowed).", label,
               poll->option_count, label);
    } else {
      snprintf(footer, sizeof(footer), "Vote with /1 %s through /%zu %s.", label, poll->option_count, label);
    }
    session_send_system_line(ctx, footer);
  }
}

// Gather the main poll and any named polls and present summaries to the caller.
static void session_send_poll_summary(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  poll_state_t main_snapshot = {0};
  named_poll_state_t named_snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
  size_t named_count = 0U;

  pthread_mutex_lock(&host->lock);
  main_snapshot = host->poll;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] == '\0') {
      continue;
    }
    named_snapshot[named_count++] = host->named_polls[idx];
    if (named_count >= SSH_CHATTER_MAX_NAMED_POLLS) {
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  session_send_poll_summary_generic(ctx, &main_snapshot, NULL);

  size_t active_named = 0U;
  for (size_t idx = 0U; idx < named_count; ++idx) {
    if (named_snapshot[idx].poll.active && named_snapshot[idx].poll.option_count > 0U) {
      if (active_named == 0U) {
        session_send_system_line(ctx, "Active named polls:");
      }
      session_send_poll_summary_generic(ctx, &named_snapshot[idx].poll, named_snapshot[idx].label);
      ++active_named;
    }
  }

  if (active_named == 0U) {
    session_send_system_line(ctx,
                             "No active named polls. Use /vote <label> <question>|<option1>|<option2> or /vote-single for a "
                             "single-choice poll.");
  }
}

// Provide a lightweight overview of every named poll regardless of status.
static void session_list_named_polls(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  named_poll_state_t snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
  size_t count = 0U;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] == '\0') {
      continue;
    }
    snapshot[count++] = host->named_polls[idx];
    if (count >= SSH_CHATTER_MAX_NAMED_POLLS) {
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (count == 0U) {
    session_send_system_line(ctx,
                             "No named polls exist. Start one with /vote <label> <question>|<option1>|<option2> or /vote-single "
                             "for single-choice voting.");
    return;
  }

  session_send_system_line(ctx, "Named polls overview:");
  for (size_t idx = 0U; idx < count; ++idx) {
    const named_poll_state_t *entry = &snapshot[idx];
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *status = entry->poll.active ? "active" : "inactive";
    const char *mode = entry->poll.allow_multiple ? "multiple choice" : "single choice";
    snprintf(line, sizeof(line), "- [%s] %s (options: %zu, %s, %s)", entry->label, entry->poll.question,
             entry->poll.option_count, status, mode);
    session_send_system_line(ctx, line);
  }
}

static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length) {
  if (entry == NULL || buffer == NULL || length == 0U) {
    return false;
  }

  buffer[0] = '\0';
  bool any = false;
  size_t offset = 0U;

  for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
    uint32_t count = entry->reaction_counts[idx];
    if (count == 0U) {
      continue;
    }

    const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
    char chunk[64];
    snprintf(chunk, sizeof(chunk), "%s x%u", descriptor->icon, count);

    size_t chunk_len = strlen(chunk);
    if (chunk_len + 1U >= length - offset) {
      break;
    }

    if (any) {
      buffer[offset++] = ' ';
    }
    memcpy(buffer + offset, chunk, chunk_len);
    offset += chunk_len;
    buffer[offset] = '\0';
    any = true;
  }

  return any;
}

static const char *chat_attachment_type_label(chat_attachment_type_t type) {
  switch (type) {
  case CHAT_ATTACHMENT_IMAGE:
    return "image";
  case CHAT_ATTACHMENT_VIDEO:
    return "video";
  case CHAT_ATTACHMENT_AUDIO:
    return "audio";
  case CHAT_ATTACHMENT_FILE:
    return "file";
  case CHAT_ATTACHMENT_NONE:
  default:
    return "attachment";
  }
}

static void session_send_history(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL || !session_transport_active(ctx)) {
    return;
  }

  size_t total = host_history_total(ctx->owner);
  if (total == 0U) {
    return;
  }

  size_t window = SSH_CHATTER_SCROLLBACK_CHUNK;
  if (window == 0U) {
    window = 1U;
  }
  if (window > total) {
    window = total;
  }

  chat_history_entry_t snapshot[SSH_CHATTER_SCROLLBACK_CHUNK];
  size_t start_index = total - window;
  size_t copied = host_history_copy_range(ctx->owner, start_index, snapshot, window);
  if (copied == 0U) {
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  if (total > copied) {
    snprintf(header, sizeof(header), "Recent activity (last %zu of %zu messages):", copied, total);
  } else {
    snprintf(header, sizeof(header), "Recent activity (last %zu message%s):", copied, copied == 1U ? "" : "s");
  }
  session_render_separator(ctx, "Recent activity");
  session_send_system_line(ctx, header);

  for (size_t idx = 0; idx < copied; ++idx) {
    session_send_history_entry(ctx, &snapshot[idx]);
  }

  session_send_system_line(ctx, "Use the Up/Down arrow keys to browse stored chat history.");
  session_render_separator(ctx, "Chatroom");
  ctx->history_scroll_position = 0U;
}

static bool session_handle_service_request(ssh_message message) {
  if (message == NULL) {
    return false;
  }

  const char *service = ssh_message_service_service(message);
  if (service == NULL) {
    return false;
  }

  if (strcmp(service, "ssh-userauth") == 0 || strcmp(service, "ssh-connection") == 0) {
    ssh_message_service_reply_success(message);
    return true;
  }

  return false;
}

static int session_authenticate(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool authenticated = false;

  while (!authenticated && (message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    switch (message_type) {
      case SSH_REQUEST_SERVICE:
        if (!session_handle_service_request(message)) {
          ssh_message_reply_default(message);
        }
        break;
      case SSH_REQUEST_AUTH:
        {
          const char *username = ssh_message_auth_user(message);
          if (username != NULL && username[0] != '\0') {
            snprintf(ctx->user.name, sizeof(ctx->user.name), "%.*s", SSH_CHATTER_USERNAME_LEN - 1, username);
          }
        }
        ssh_message_auth_reply_success(message, 0);
        authenticated = true;
        break;
      default:
        ssh_message_reply_default(message);
        break;
    }
    ssh_message_free(message);
  }

  return authenticated ? 0 : -1;
}

static int session_accept_channel(session_ctx_t *ctx) {
  ssh_message message = NULL;

  while ((message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    if (message_type == SSH_REQUEST_SERVICE) {
      if (!session_handle_service_request(message)) {
        ssh_message_reply_default(message);
      }
      ssh_message_free(message);
      continue;
    }

    if (message_type == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
      ssh_channel channel = ssh_message_channel_request_open_reply_accept(message);
      if (channel == NULL) {
        accept_channel_fn_t accept_channel = resolve_accept_channel_fn();
        if (accept_channel != NULL) {
          channel = ssh_channel_new(ctx->session);
          if (channel != NULL) {
            if (accept_channel(message, channel) != SSH_OK) {
              ssh_channel_free(channel);
              channel = NULL;
            }
          }
        }
      }

      if (channel != NULL) {
        ctx->channel = channel;
        ssh_message_free(message);
        break;
      }

      ssh_message_reply_default(message);
      ssh_message_free(message);
      continue;
    }

    ssh_message_reply_default(message);
    ssh_message_free(message);
  }

  return session_transport_active(ctx) ? 0 : -1;
}

static int session_prepare_shell(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool shell_ready = false;

  while (!shell_ready && (message = ssh_message_get(ctx->session)) != NULL) {
    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
      const int subtype = ssh_message_subtype(message);
      if (subtype == SSH_CHANNEL_REQUEST_PTY || subtype == SSH_CHANNEL_REQUEST_SHELL) {
        ssh_message_channel_request_reply_success(message);
        if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
          shell_ready = true;
        }
      } else {
        ssh_message_reply_default(message);
      }
    } else {
      ssh_message_reply_default(message);
    }
    ssh_message_free(message);
  }

  return shell_ready ? 0 : -1;
}

static void host_update_last_captcha_prompt(host_t *host, const captcha_prompt_t *prompt) {
  if (host == NULL || prompt == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  char combined_question[sizeof(prompt->question_en) + sizeof(prompt->question_ko) + sizeof(prompt->question_ru) +
                         sizeof(prompt->question_zh) + 48];
  snprintf(combined_question, sizeof(combined_question),
           "캡챠: %s\nCaptcha: %s\n驗證碼: %s\nКапча: %s", prompt->question_ko, prompt->question_en, prompt->question_zh,
           prompt->question_ru);
  snprintf(host->last_captcha_question, sizeof(host->last_captcha_question), "%s", combined_question);
  snprintf(host->last_captcha_answer, sizeof(host->last_captcha_answer), "%s", prompt->answer);
  host->has_last_captcha = host->last_captcha_question[0] != '\0' && host->last_captcha_answer[0] != '\0';
  if (host->has_last_captcha) {
    if (clock_gettime(CLOCK_REALTIME, &host->last_captcha_generated) != 0) {
      host->last_captcha_generated.tv_sec = time(NULL);
      host->last_captcha_generated.tv_nsec = 0L;
    }
  } else {
    host->last_captcha_generated.tv_sec = 0;
    host->last_captcha_generated.tv_nsec = 0L;
  }
  pthread_mutex_unlock(&host->lock);
}

static bool session_run_captcha(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return false;
  }

  captcha_prompt_t prompt;
  session_build_captcha_prompt(ctx, &prompt);
  host_update_last_captcha_prompt(ctx->owner, &prompt);
  session_send_system_line(ctx, "Before entering the room, solve this small puzzle.");
  char korean_prompt_line[sizeof(prompt.question_ko) + 16];
  snprintf(korean_prompt_line, sizeof(korean_prompt_line), "캡챠: %s", prompt.question_ko);
  session_send_system_line(ctx, korean_prompt_line);
  char english_prompt_line[sizeof(prompt.question_en) + 16];
  snprintf(english_prompt_line, sizeof(english_prompt_line), "Captcha: %s", prompt.question_en);
  session_send_system_line(ctx, english_prompt_line);
  char chinese_prompt_line[sizeof(prompt.question_zh) + 16];
  snprintf(chinese_prompt_line, sizeof(chinese_prompt_line), "驗證碼: %s", prompt.question_zh);
  session_send_system_line(ctx, chinese_prompt_line);
  char russian_prompt_line[sizeof(prompt.question_ru) + 16];
  snprintf(russian_prompt_line, sizeof(russian_prompt_line), "Капча: %s", prompt.question_ru);
  session_send_system_line(ctx, russian_prompt_line);
  session_send_system_line(ctx, "Type your answer and press Enter:");

  char answer[sizeof(prompt.answer)];
  size_t length = 0U;
  while (length + 1U < sizeof(answer)) {
    char ch = '\0';
    const int read_result = session_transport_read(ctx, &ch, 1, -1);
    if (read_result <= 0) {
      return false;
    }

    if (ch == '\r' || ch == '\n') {
      session_local_echo_char(ctx, '\n');
      break;
    }

    if (ch == '\b' || (unsigned char)ch == 0x7fU) {
      if (length > 0U) {
        --length;
        session_send_raw_text(ctx, "\b \b");
      }
      continue;
    }

    if ((unsigned char)ch < 0x20U) {
      continue;
    }

    answer[length++] = ch;
    session_local_echo_char(ctx, ch);
  }
  answer[length] = '\0';
  trim_whitespace_inplace(answer);

  if (answer[0] == '\0') {
    session_send_system_line(ctx, "Captcha answer missing. Disconnecting.");
    return false;
  }

  if (strcasecmp(prompt.answer, "dog") == 0 && strcmp(answer, "개") == 0) {
    snprintf(answer, sizeof(answer), "%s", "dog");
  }

  if (strcasecmp(answer, prompt.answer) == 0) {
    session_send_system_line(ctx, "Captcha solved. Welcome aboard!");
    return true;
  }

  session_send_system_line(ctx, "Captcha failed. Disconnecting.");
  return false;
}

static bool session_is_captcha_exempt(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->user.name[0] == '\0') {
    return false;
  }

  char lowered[sizeof(ctx->user.name)];
  size_t idx = 0U;
  for (; idx + 1U < sizeof(lowered) && ctx->user.name[idx] != '\0'; ++idx) {
    lowered[idx] = (char)tolower((unsigned char)ctx->user.name[idx]);
  }
  if (idx < sizeof(lowered)) {
    lowered[idx] = '\0';
  } else {
    lowered[sizeof(lowered) - 1U] = '\0';
  }

  return strcmp(lowered, "gpt") == 0;
}

static void session_print_help(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  static const char *kHelpLines[] = {
      "Available commands:",
      "/help                 - show this message",
      "/exit                 - leave the chat",
      "/nick <name>          - change your display name",
      "/pm <username> <message> - send a private message",
      "/motd                - view the message of the day",
      "/status <message|clear> - set your profile status",
      "/showstatus <username> - view someone else's status",
      "/users               - announce the number of connected users",
      "/search <text>       - search for users whose name matches text",
      "/chat <message-id>   - show a past message by its identifier",
      "/reply <message-id|r<reply-id>> <text> - reply to a message or reply",
      "/image <url> [caption] - share an image link",
      "/video <url> [caption] - share a video link",
      "/audio <url> [caption] - share an audio clip",
      "/files <url> [caption] - share a downloadable file",
      "/mail [inbox|send <user> <message>|clear] - manage your mailbox",
      "/profilepic            - open the ASCII art profile picture composer",
      "/asciiart           - open the ASCII art composer (max 128 lines, 1/10 min per IP)",
      "/game <tetris|liargame|alpha> - start a minigame in the chat (use /suspend! or Ctrl+Z to exit)",
      "Up/Down arrows           - scroll chat (chat mode) or browse command history (command mode)",
      "/color (text;highlight[;bold]) - style your handle",
      "/systemcolor (fg;background[;highlight][;bold]) - style the interface (third value may be highlight or bold; use /systemcolor reset to restore defaults)",
      "/set-trans-lang <language|off> - translate terminal output to a target language",
      "/set-target-lang <language|off> - translate your outgoing messages",
      "/weather <region> <city> - show the weather for a region and city",
      "/translate <on|off>    - enable or disable translation after configuring languages",
      "/translate-scope <chat|chat-nohistory|all> - limit translation to chat/BBS, optionally skipping scrollback (operator only)",
      "/gemini <on|off>       - toggle Gemini provider (operator only)",
      "/gemini-unfreeze      - clear automatic Gemini cooldown (operator only)",
      "/eliza <on|off>        - toggle the eliza moderator persona (operator only)",
      "/eliza-chat <message>  - chat with eliza using shared memories",
      "/chat-spacing <0-5>    - reserve blank lines before translated captions in chat",
      "/mode <chat|command|toggle> - switch between chat mode and command mode (no '/' needed in command mode)",
      "/palette <name>        - apply a predefined interface palette (/palette list)",
      "/today               - discover today's function (once per day)",
      "/date <timezone>     - view the server time in another timezone",
      "/os <name>           - record the operating system you use",
      "/getos <username>    - look up someone else's recorded operating system",
      "/birthday YYYY-MM-DD - register your birthday",
      "/soulmate            - list users sharing your birthday",
      "/pair                - list users sharing your recorded OS",
      "/connected           - privately list everyone connected",
      "/grant <ip>          - grant operator access to an IP (LAN only)",
      "/revoke <ip>         - revoke an IP's operator access (LAN top admin)",
      "/poll <question>|<option...> - start or view a poll",
      "/vote <label> <question>|<option...> - start or inspect a multiple-choice named poll (use /vote @close <label> to end it)",
      "/vote-single <label> <question>|<option...> - start or inspect a single-choice named poll",
      "/elect <label> <choice> - vote in a named poll by label",
      "/poke <username>      - send a bell to call a user",
      "/kick <username>      - disconnect a user (operator only)",
      "/ban <username>       - ban a user (operator only)",
      "/banlist             - list active bans (operator only)",
      "/delete-msg <id|start-end> - remove chat history messages (operator only)",
      "/block <user|ip>      - hide messages from a user or IP locally (/block list to review)",
      "/unblock <target|all> - remove a local block entry",
      "/pardon <user|ip>     - remove a ban (operator only)",
      "/good|/sad|/cool|/angry|/checked|/love|/wtf <id> - react to a message by number",
      "/1 .. /5             - vote for an option in the active poll",
      "/bbs [list|read|post|comment|regen|delete] - open the bulletin board system (see /bbs for details, finish "
      SSH_CHATTER_BBS_TERMINATOR " to post)",
      "/rss list             - list saved RSS feeds",
      "/rss read <tag>       - open a saved feed in the inline reader",
      "/rss add <url> <tag>  - register a feed (operator only)",
      "/rss del <tag>        - delete a feed (operator only)",
      "/suspend!            - suspend the active game (Ctrl+Z while playing)",
      "Regular messages are shared with everyone.",
  };

  session_send_system_lines_bulk(ctx, kHelpLines, sizeof(kHelpLines) / sizeof(kHelpLines[0]));
}

static bool session_line_is_exit_command(const char *line) {
  if (line == NULL) {
    return false;
  }

  if (strncmp(line, "/exit", 5) != 0) {
    return false;
  }

  const char trailing = line[5];
  if (trailing == '\0') {
    return true;
  }

  if (!isspace((unsigned char)trailing)) {
    return false;
  }

  for (size_t idx = 6U; line[idx] != '\0'; ++idx) {
    if (!isspace((unsigned char)line[idx])) {
      return false;
    }
  }

  return true;
}

static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL) {
    return;
  }

  if (session_line_is_exit_command(line)) {
    session_handle_exit(ctx);
    return;
  }

  char reminder[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(reminder, sizeof(reminder), "The username '%s' is already in use.", ctx->user.name);
  session_send_system_line(ctx, reminder);
  session_send_system_line(ctx,
                           "Reconnect with a different username by running: ssh newname@<server> (or ssh -l newname <server>)");
  session_send_system_line(ctx, "Type /exit to quit.");
}

static void session_process_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL) {
    return;
  }

  char normalized[SSH_CHATTER_MAX_INPUT_LEN];
  snprintf(normalized, sizeof(normalized), "%s", line);
  session_normalize_newlines(normalized);

  if (ctx->asciiart_pending) {
    session_asciiart_capture_text(ctx, normalized);
    return;
  }

  if (ctx->bbs_post_pending) {
    session_bbs_capture_body_text(ctx, normalized);
    return;
  }

  if (normalized[0] == '\0') {
    return;
  }

  if (ctx->game.active) {
    if (strcmp(normalized, "/suspend!") == 0) {
      session_game_suspend(ctx, "Game suspended.");
      return;
    }

    if (normalized[0] == '/') {
      session_send_system_line(ctx, "Finish the current game with /suspend! first.");
      return;
    }

    if (ctx->game.type == SESSION_GAME_TETRIS) {
      session_game_tetris_handle_line(ctx, normalized);
    } else if (ctx->game.type == SESSION_GAME_LIARGAME) {
      session_game_liar_handle_line(ctx, normalized);
    } else if (ctx->game.type == SESSION_GAME_ALPHA) {
      session_game_alpha_handle_line(ctx, normalized);
    }
    return;
  }

  if (ctx->in_rss_mode) {
    if (strcmp(normalized, "/exit") == 0) {
      session_rss_exit(ctx, NULL);
    } else {
      const char *rss_args = NULL;
      if (session_parse_command(normalized, "/rss", &rss_args)) {
        session_rss_exit(ctx, NULL);
        session_handle_rss(ctx, rss_args);
      } else {
        session_send_system_line(ctx, "RSS reader active. Use /exit or Ctrl+Z to return to chat.");
      }
    }
    return;
  }

  bool translation_bypass = false;
  char bypass_buffer[SSH_CHATTER_MAX_INPUT_LEN];
  if (translation_strip_no_translate_prefix(normalized, bypass_buffer, sizeof(bypass_buffer))) {
    translation_bypass = true;
    snprintf(normalized, sizeof(normalized), "%s", bypass_buffer);
  }

  if (normalized[0] == '\0') {
    return;
  }

  printf("[%s] %s\n", ctx->user.name, normalized);

  const struct timespec tiny_delay = {.tv_sec = 0, .tv_nsec = 5000000L};
  nanosleep(&tiny_delay, NULL);

  if (ctx->username_conflict) {
    session_handle_username_conflict_input(ctx, normalized);
    return;
  }

  if (!translation_bypass && normalized[0] == '/') {
    session_dispatch_command(ctx, normalized);
    return;
  }

  const char *trimmed = normalized;
  while (*trimmed == ' ' || *trimmed == '\t') {
    ++trimmed;
  }

  if (!translation_bypass && ctx->input_mode == SESSION_INPUT_MODE_COMMAND && *trimmed != '\0') {
    const char *command_text = trimmed;
    char command_buffer[SSH_CHATTER_MAX_INPUT_LEN];
    if (command_text[0] != '/') {
      command_buffer[0] = '/';
      size_t command_len = strnlen(command_text, sizeof(command_buffer) - 2U);
      memcpy(&command_buffer[1], command_text, command_len);
      command_buffer[command_len + 1U] = '\0';
      command_text = command_buffer;
    }
    session_dispatch_command(ctx, command_text);
    return;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  const bool asciiart_active = ctx->asciiart_pending;
  bool ascii_profile_command = asciiart_active;
  if (!ascii_profile_command && normalized[0] == '/') {
    const char *command_args = NULL;
    if (session_parse_command(normalized, "/asciiart", &command_args) ||
        session_parse_command(normalized, "/profilepic", &command_args)) {
      ascii_profile_command = true;
    }
  }

  const bool translation_throttle =
      ctx->translation_enabled && ctx->input_translation_enabled && ctx->input_translation_language[0] != '\0';
  const bool chat_throttle = ctx->input_mode == SESSION_INPUT_MODE_CHAT;
  if ((translation_throttle || chat_throttle) && ctx->has_last_message_time) {
    time_t sec_delta = now.tv_sec - ctx->last_message_time.tv_sec;
    long nsec_delta = now.tv_nsec - ctx->last_message_time.tv_nsec;
    if (nsec_delta < 0L) {
      --sec_delta;
      nsec_delta += 1000000000L;
    }
    if (translation_throttle && (sec_delta < 0 || (sec_delta == 0 && nsec_delta < 1000000000L))) {
      session_send_system_line(ctx, "Please wait at least one second before sending another message.");
      return;
    }
    if (!translation_throttle && chat_throttle && !ascii_profile_command && !ctx->bracket_paste_active &&
        (sec_delta < 0 || (sec_delta == 0 && nsec_delta < 300000000L))) {
      session_send_system_line(ctx, "Please wait at least 300 milliseconds before sending another chat message.");
      return;
    }
  }

  ctx->last_message_time = now;
  ctx->has_last_message_time = true;

  if (!translation_bypass && ctx->translation_enabled && ctx->input_translation_enabled &&
      ctx->input_translation_language[0] != '\0') {
    if (session_translation_queue_input(ctx, normalized)) {
      return;
    }
    session_send_system_line(ctx, "Translation unavailable; sending your original message.");
  }

  session_deliver_outgoing_message(ctx, normalized);
}

static void session_handle_kick(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to kick users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /kick <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /kick <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, message);
    return;
  }

  if (target == ctx) {
    session_send_system_line(ctx, "You cannot kick yourself.");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [%s] has been kicked by [%s]", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);

  const bool target_active = session_transport_active(target);
  if (!target_active || (target->transport_kind == SESSION_TRANSPORT_SSH && target->session == NULL)) {
    target->should_exit = true;
    target->has_joined_room = false;
    chat_room_remove(&ctx->owner->room, target);
    session_send_system_line(ctx, "User removed from the chat.");
  } else {
    session_send_system_line(target, "You have been kicked by an operator.");
    target->should_exit = true;
    session_transport_request_close(target);
    target->has_joined_room = false;
    chat_room_remove(&ctx->owner->room, target);
    session_send_system_line(ctx, "User removed from the chat.");
  }

  printf("[kick] %s kicked %s\n", ctx->user.name, target->user.name);
}

static void session_handle_ban(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to ban users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    unsigned char inet_buffer[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, target_name, inet_buffer) == 1 || inet_pton(AF_INET6, target_name, inet_buffer) == 1) {
      if (host_add_ban_entry(ctx->owner, "", target_name)) {
        char notice[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(notice, sizeof(notice), "IP '%s' has been banned.", target_name);
        session_send_system_line(ctx, notice);
      } else {
        session_send_system_line(ctx, "Unable to add ban entry (list full?).");
      }
    } else {
      char not_found[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
      session_send_system_line(ctx, not_found);
    }
    return;
  }

  if (target->user.is_lan_operator) {
    session_send_system_line(ctx, "LAN operators cannot be banned.");
    return;
  }

  const char *target_ip = target->client_ip[0] != '\0' ? target->client_ip : "";
  if (!host_add_ban_entry(ctx->owner, target->user.name, target_ip)) {
    session_send_system_line(ctx, "Unable to add ban entry (list full?).");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [%s] has been banned by [%s]", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
  session_send_system_line(ctx, "Ban applied.");
  printf("[ban] %s banned %s (%s)\n", ctx->user.name, target->user.name, target_ip[0] != '\0' ? target_ip : "unknown");

  if (session_transport_active(target)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "You have been banned by [%s].", ctx->user.name);
    session_send_system_line(target, message);
    target->should_exit = true;
    session_transport_request_close(target);
  }
}

static void session_handle_ban_list(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to view the ban list.");
    return;
  }

  if (arguments != NULL) {
    while (*arguments != '\0' && isspace((unsigned char)*arguments)) {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /banlist");
      return;
    }
  }

  host_t *host = ctx->owner;
  if (host == NULL) {
    session_send_system_line(ctx, "Host unavailable.");
    return;
  }

  typedef struct ban_snapshot {
    char username[SSH_CHATTER_USERNAME_LEN];
    char ip[SSH_CHATTER_IP_LEN];
  } ban_snapshot_t;

  ban_snapshot_t entries[SSH_CHATTER_MAX_BANS];
  size_t entry_count = 0U;

  pthread_mutex_lock(&host->lock);
  entry_count = host->ban_count;
  if (entry_count > SSH_CHATTER_MAX_BANS) {
    entry_count = SSH_CHATTER_MAX_BANS;
  }
  for (size_t idx = 0U; idx < entry_count; ++idx) {
    snprintf(entries[idx].username, sizeof(entries[idx].username), "%s", host->bans[idx].username);
    snprintf(entries[idx].ip, sizeof(entries[idx].ip), "%s", host->bans[idx].ip);
  }
  pthread_mutex_unlock(&host->lock);

  if (entry_count == 0U) {
    session_send_system_line(ctx, "No active bans.");
    return;
  }

  session_send_system_line(ctx, "Active bans:");
  for (size_t idx = 0U; idx < entry_count; ++idx) {
    const char *username = entries[idx].username;
    const char *ip = entries[idx].ip;
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    if (username[0] != '\0' && ip[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. user: %s, ip: %s", idx + 1U, username, ip);
    } else if (username[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. user: %s", idx + 1U, username);
    } else if (ip[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. ip: %s", idx + 1U, ip);
    } else {
      snprintf(message, sizeof(message), "%zu. <empty>", idx + 1U);
    }
    session_send_system_line(ctx, message);
  }
}

static void session_handle_poke(session_ctx_t *ctx, const char *arguments) {
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /poke <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, arguments);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", arguments);
    session_send_system_line(ctx, message);
    return;
  }

  printf("[poke] %s pokes %s\n", ctx->user.name, target->user.name);
  session_channel_write(target, "\a", 1U);
  session_send_system_line(ctx, "Poke sent.");
}

static void session_handle_block(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /block <username|ip|list|confirm <username> <only|ip>>";

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (strcasecmp(working, "list") == 0) {
    session_blocklist_show(ctx);
    return;
  }

  if (strncasecmp(working, "confirm", 7) == 0 &&
      (working[7] == '\0' || isspace((unsigned char)working[7]))) {
    char *cursor = working + 7;
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
      ++cursor;
    }

    if (*cursor == '\0') {
      session_send_system_line(ctx, kUsage);
      return;
    }

    char username[SSH_CHATTER_USERNAME_LEN];
    size_t name_len = 0U;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor) && name_len + 1U < sizeof(username)) {
      username[name_len++] = *cursor++;
    }
    username[name_len] = '\0';

    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
      ++cursor;
    }

    if (*cursor == '\0') {
      session_send_system_line(ctx, kUsage);
      return;
    }

    char mode[16];
    size_t mode_len = 0U;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor) && mode_len + 1U < sizeof(mode)) {
      mode[mode_len++] = *cursor++;
    }
    mode[mode_len] = '\0';

    if (!ctx->block_pending.active) {
      session_send_system_line(ctx, "No provider block is awaiting confirmation.");
      return;
    }

    if (strncmp(ctx->block_pending.username, username, SSH_CHATTER_USERNAME_LEN) != 0) {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Pending block is for [%s], not [%s].", ctx->block_pending.username, username);
      session_send_system_line(ctx, message);
      return;
    }

    bool block_ip = false;
    if (strcasecmp(mode, "ip") == 0 || strcasecmp(mode, "all") == 0 || strcasecmp(mode, "full") == 0) {
      block_ip = true;
    } else if (strcasecmp(mode, "only") == 0 || strcasecmp(mode, "user") == 0 || strcasecmp(mode, "name") == 0) {
      block_ip = false;
    } else {
      session_send_system_line(ctx, kUsage);
      return;
    }

    bool already_present = false;
    if (!session_blocklist_add(ctx, ctx->block_pending.ip, ctx->block_pending.username, block_ip, &already_present)) {
      if (already_present) {
        session_send_system_line(ctx, "That target is already blocked.");
      } else {
        session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
      }
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      if (block_ip) {
        snprintf(message, sizeof(message), "Blocking all users from %.63s.", ctx->block_pending.ip);
      } else {
        snprintf(message, sizeof(message), "Blocking [%.23s] only (IP %.63s).", ctx->block_pending.username,
                 ctx->block_pending.ip);
      }
      session_send_system_line(ctx, message);
    }

    ctx->block_pending.active = false;
    ctx->block_pending.username[0] = '\0';
    ctx->block_pending.ip[0] = '\0';
    ctx->block_pending.provider_label[0] = '\0';
    return;
  }

  unsigned char inet_buffer[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET, working, inet_buffer) == 1 || inet_pton(AF_INET6, working, inet_buffer) == 1) {
    bool already_present = false;
    char label[64];
    bool provider = session_detect_provider_ip(working, label, sizeof(label));
    if (!session_blocklist_add(ctx, working, "", true, &already_present)) {
      if (already_present) {
        session_send_system_line(ctx, "That IP is already blocked.");
      } else {
        session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
      }
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Blocking all users from %.256s.", working);
      session_send_system_line(ctx, message);
      if (provider && label[0] != '\0') {
        char warning[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(warning, sizeof(warning),
                 "Warning: %.256s is flagged as %.63s; other people may also be hidden.", working, label);
        session_send_system_line(ctx, warning);
      }
    }
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Block list unavailable right now.");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, working);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%.256s' is not connected.", working);
    session_send_system_line(ctx, message);
    return;
  }

  if (target == ctx) {
    session_send_system_line(ctx, "You do not need to block yourself.");
    return;
  }

  if (target->client_ip[0] == '\0') {
    session_send_system_line(ctx, "Unable to identify that user's IP address right now.");
    return;
  }

  char label[64];
  if (session_detect_provider_ip(target->client_ip, label, sizeof(label))) {
    memset(&ctx->block_pending, 0, sizeof(ctx->block_pending));
    ctx->block_pending.active = true;
    snprintf(ctx->block_pending.username, sizeof(ctx->block_pending.username), "%s", target->user.name);
    snprintf(ctx->block_pending.ip, sizeof(ctx->block_pending.ip), "%s", target->client_ip);
    snprintf(ctx->block_pending.provider_label, sizeof(ctx->block_pending.provider_label), "%.31s", label);

    char warning[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(warning, sizeof(warning), "%.63s appears to belong to %.63s.", target->client_ip, label);
    session_send_system_line(ctx, warning);

    char prompt[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(prompt, sizeof(prompt),
             "Use /block confirm %.23s only to hide just [%.23s] or /block confirm %.23s ip to hide everyone from that IP.",
             target->user.name, target->user.name, target->user.name);
    session_send_system_line(ctx, prompt);
    return;
  }

  bool already_present = false;
  if (!session_blocklist_add(ctx, target->client_ip, target->user.name, true, &already_present)) {
    if (already_present) {
      session_send_system_line(ctx, "That address is already blocked.");
    } else {
      session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
    }
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Blocking all users from %.63s (triggered by [%.23s]).", target->client_ip,
             target->user.name);
    session_send_system_line(ctx, message);
  }
}

static void session_handle_unblock(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /unblock <username|ip|all>";

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (strcasecmp(working, "all") == 0) {
    size_t removed = 0U;
    for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
      if (ctx->block_entries[idx].in_use) {
        memset(&ctx->block_entries[idx], 0, sizeof(ctx->block_entries[idx]));
        ++removed;
      }
    }
    ctx->block_entry_count = 0U;
    ctx->block_pending.active = false;
    ctx->block_pending.username[0] = '\0';
    ctx->block_pending.ip[0] = '\0';
    ctx->block_pending.provider_label[0] = '\0';

    if (removed == 0U) {
      session_send_system_line(ctx, "No blocked entries to remove.");
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Removed %zu blocked entr%s.", removed, removed == 1U ? "y" : "ies");
      session_send_system_line(ctx, message);
    }
    return;
  }

  if (session_blocklist_remove(ctx, working)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Removed block for %.256s.", working);
    session_send_system_line(ctx, message);
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No block entry matched '%.256s'.", working);
    session_send_system_line(ctx, message);
  }
}

static void session_handle_pm(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /pm <username> <message>";

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Private messages are unavailable right now.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *cursor = working;
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  *cursor = '\0';
  char *message = cursor + 1;
  while (*message != '\0' && isspace((unsigned char)*message)) {
    ++message;
  }

  if (*message == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%.*s", (int)sizeof(target_name) - 1, working);

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  const bool target_is_eliza = strcasecmp(target_name, "eliza") == 0;
  const bool eliza_active = target_is_eliza && atomic_load(&ctx->owner->eliza_enabled);

  if (target == NULL) {
    if (target_is_eliza) {
      if (!eliza_active) {
        session_send_system_line(ctx, "eliza isn't around right now.");
        return;
      }
      session_send_system_line(ctx, "Connecting you with eliza...");
    } else {
      char not_found[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
      session_send_system_line(ctx, not_found);
      return;
    }
  }

  char prepared[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(prepared, sizeof(prepared), "%s", message);

  char stripped[SSH_CHATTER_MESSAGE_LIMIT];
  bool translation_bypass = translation_strip_no_translate_prefix(prepared, stripped, sizeof(stripped));
  const char *deliver_body = translation_bypass ? stripped : prepared;

  const char *target_display = target != NULL ? target->user.name : target_name;
  printf("[pm] %s -> %s: %s\n", ctx->user.name, target_display, deliver_body);

  char to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_target_label, sizeof(to_target_label), "%s -> you", ctx->user.name);

  char to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_sender_label, sizeof(to_sender_label), "you -> %s", target_display);

  bool attempt_translation = (target != NULL) && !translation_bypass && ctx->translation_enabled &&
                             ctx->input_translation_enabled && ctx->input_translation_language[0] != '\0';

  if (attempt_translation) {
    if (session_translation_queue_private_message(ctx, target, deliver_body)) {
      return;
    }
    session_send_system_line(ctx, "Translation unavailable; sending your original message.");
  }

  if (target != NULL) {
    session_send_private_message_line(target, ctx, to_target_label, deliver_body);
    session_send_private_message_line(ctx, ctx, to_sender_label, deliver_body);
    return;
  }

  session_send_private_message_line(ctx, ctx, to_sender_label, deliver_body);
  host_eliza_handle_private_message(ctx, deliver_body);
}

static bool username_contains(const char *username, const char *needle) {
  if (username == NULL || needle == NULL) {
    return false;
  }

  const size_t needle_len = strlen(needle);
  if (needle_len == 0U) {
    return false;
  }

  const size_t name_len = strlen(username);
  if (needle_len > name_len) {
    return false;
  }

  for (size_t offset = 0U; offset + needle_len <= name_len; ++offset) {
    bool match = true;
    for (size_t idx = 0U; idx < needle_len; ++idx) {
      const unsigned char user_ch = (unsigned char)username[offset + idx];
      const unsigned char needle_ch = (unsigned char)needle[idx];
      if (tolower(user_ch) != tolower(needle_ch)) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }

  return false;
}

static void session_handle_search(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Search is unavailable at the moment.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char query[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(query, sizeof(query), "%s", arguments);
  trim_whitespace_inplace(query);

  if (query[0] == '\0') {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char listing[SSH_CHATTER_MESSAGE_LIMIT];
  listing[0] = '\0';
  size_t match_count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL) {
      continue;
    }
    if (!username_contains(member->user.name, query)) {
      continue;
    }

    char name[SSH_CHATTER_USERNAME_LEN];
    snprintf(name, sizeof(name), "%s", member->user.name);
    size_t current_len = strnlen(listing, sizeof(listing));
    size_t name_len = strnlen(name, sizeof(name));
    size_t prefix_len = (match_count == 0U) ? 0U : 2U;

    if (current_len + prefix_len + name_len >= sizeof(listing)) {
      continue;
    }

    if (match_count > 0U) {
      listing[current_len++] = ',';
      listing[current_len++] = ' ';
    }
    memcpy(listing + current_len, name, name_len);
    listing[current_len + name_len] = '\0';
    ++match_count;
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  if (match_count == 0U) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    char display_query[64];
    size_t copy_len = strnlen(query, sizeof(display_query) - 1U);
    memcpy(display_query, query, copy_len);
    display_query[copy_len] = '\0';
    snprintf(message, sizeof(message), "No users matching '%s'.", display_query);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Matching users (%zu):", match_count);
  session_send_system_line(ctx, header);
  session_send_system_line(ctx, listing);
}

static void session_handle_chat_lookup(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /chat <message-id>";

  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[64];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *endptr = NULL;
  unsigned long long parsed = strtoull(working, &endptr, 10);
  if (parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  uint64_t message_id = (uint64_t)parsed;
  chat_history_entry_t entry = {0};
  if (!host_history_find_entry_by_id(ctx->owner, message_id, &entry)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Message #%" PRIu64 " was not found.", message_id);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Message #%" PRIu64 ":", message_id);
  session_send_system_line(ctx, header);
  session_send_history_entry(ctx, &entry);
  session_send_reply_tree(ctx, entry.message_id, 0U, 1U);
}

static void session_handle_reply(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /reply <message-id|r<reply-id>> <text>";

  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *target = strtok_r(working, " \t", &saveptr);
  if (target == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *text = NULL;
  if (saveptr != NULL) {
    text = saveptr;
    while (*text == ' ' || *text == '\t') {
      ++text;
    }
  }

  if (text == NULL || *text == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  bool targeting_reply = false;
  if (*target == '#') {
    ++target;
  }
  if (*target == 'r' || *target == 'R') {
    targeting_reply = true;
    ++target;
  }

  if (*target == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *endptr = NULL;
  unsigned long long parsed = strtoull(target, &endptr, 10);
  if (parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  uint64_t identifier = (uint64_t)parsed;

  chat_reply_entry_t parent_reply = {0};
  uint64_t parent_reply_id = 0U;
  uint64_t parent_message_id = 0U;

  if (targeting_reply) {
    if (!host_replies_find_entry_by_id(ctx->owner, identifier, &parent_reply)) {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Reply r#%" PRIu64 " was not found.", identifier);
      session_send_system_line(ctx, message);
      return;
    }
    parent_message_id = parent_reply.parent_message_id;
    parent_reply_id = parent_reply.reply_id;
  } else {
    chat_history_entry_t parent_entry = {0};
    if (host_history_find_entry_by_id(ctx->owner, identifier, &parent_entry)) {
      parent_message_id = parent_entry.message_id;
    } else if (host_replies_find_entry_by_id(ctx->owner, identifier, &parent_reply)) {
      parent_message_id = parent_reply.parent_message_id;
      parent_reply_id = parent_reply.reply_id;
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Message or reply #%" PRIu64 " was not found.", identifier);
      session_send_system_line(ctx, message);
      return;
    }
  }

  if (parent_message_id == 0U) {
    session_send_system_line(ctx, "Unable to determine reply target.");
    return;
  }

  char normalized[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(normalized, sizeof(normalized), "%s", text);
  session_normalize_newlines(normalized);
  trim_whitespace_inplace(normalized);
  for (size_t idx = 0U; normalized[idx] != '\0'; ++idx) {
    if (normalized[idx] == '\n') {
      normalized[idx] = ' ';
    }
  }
  trim_whitespace_inplace(normalized);

  if (normalized[0] == '\0') {
    session_send_system_line(ctx, "Reply text cannot be empty.");
    return;
  }

  chat_reply_entry_t entry = {0};
  entry.parent_message_id = parent_message_id;
  entry.parent_reply_id = parent_reply_id;
  entry.created_at = time(NULL);
  snprintf(entry.username, sizeof(entry.username), "%s", ctx->user.name);
  snprintf(entry.message, sizeof(entry.message), "%s", normalized);

  chat_reply_entry_t stored = {0};
  if (!host_replies_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record reply.");
    return;
  }

  host_broadcast_reply(ctx->owner, &stored);
}

static void session_handle_image(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /image <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Image URL is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared an image");
  entry.attachment_type = CHAT_ATTACHMENT_IMAGE;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record image message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
  host_notify_external_clients(ctx->owner, &stored);
}

static void session_handle_video(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /video <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Video link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared a video");
  entry.attachment_type = CHAT_ATTACHMENT_VIDEO;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record video message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
  host_notify_external_clients(ctx->owner, &stored);
}

static void session_handle_audio(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /audio <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "Audio link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared an audio clip");
  entry.attachment_type = CHAT_ATTACHMENT_AUDIO;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record audio message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
  host_notify_external_clients(ctx->owner, &stored);
}

static void session_handle_files(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /files <url> [caption]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *url = strtok_r(working, " \t", &saveptr);
  if (url == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *caption = NULL;
  if (saveptr != NULL) {
    caption = saveptr;
    while (*caption == ' ' || *caption == '\t') {
      ++caption;
    }
    if (*caption == '\0') {
      caption = NULL;
    }
  }

  if (strnlen(url, SSH_CHATTER_ATTACHMENT_TARGET_LEN) >= SSH_CHATTER_ATTACHMENT_TARGET_LEN) {
    session_send_system_line(ctx, "File link is too long.");
    return;
  }

  chat_history_entry_t entry;
  chat_history_entry_prepare_user(&entry, ctx, "shared a file");
  entry.attachment_type = CHAT_ATTACHMENT_FILE;
  snprintf(entry.attachment_target, sizeof(entry.attachment_target), "%s", url);
  if (caption != NULL) {
    trim_whitespace_inplace(caption);
    snprintf(entry.attachment_caption, sizeof(entry.attachment_caption), "%s", caption);
  }

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(ctx->owner, &entry, &stored)) {
    session_send_system_line(ctx, "Unable to record file message.");
    return;
  }

  session_send_history_entry(ctx, &stored);
  chat_room_broadcast_entry(&ctx->owner->room, &stored, ctx);
  host_notify_external_clients(ctx->owner, &stored);
}

static void session_mail_render_inbox(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (!session_user_data_load(ctx)) {
    session_send_system_line(ctx, "Mailbox storage is unavailable.");
    return;
  }

  if (ctx->user_data.mailbox_count == 0U) {
    session_send_system_line(ctx, "Your mailbox is empty.");
    return;
  }

  char header[128];
  snprintf(header, sizeof(header), "Mailbox (%u message%s):", (unsigned int)ctx->user_data.mailbox_count,
           ctx->user_data.mailbox_count == 1U ? "" : "s");
  session_send_system_line(ctx, header);

  for (size_t idx = 0U; idx < ctx->user_data.mailbox_count; ++idx) {
    const user_data_mail_entry_t *entry = &ctx->user_data.mailbox[idx];
    time_t stamp = (time_t)entry->timestamp;
    struct tm when;
    char stamp_text[32];
    if (stamp != 0 && localtime_r(&stamp, &when) != NULL) {
      if (strftime(stamp_text, sizeof(stamp_text), "%Y-%m-%d %H:%M", &when) == 0U) {
        snprintf(stamp_text, sizeof(stamp_text), "%s", "(time unknown)");
      }
    } else {
      snprintf(stamp_text, sizeof(stamp_text), "%s", "(time unknown)");
    }

    char body[USER_DATA_MAILBOX_MESSAGE_LEN];
    snprintf(body, sizeof(body), "%s", entry->message);
    for (size_t pos = 0U; body[pos] != '\0'; ++pos) {
      unsigned char ch = (unsigned char)body[pos];
      if (ch < ' ' && ch != '\n' && ch != '\t') {
        body[pos] = ' ';
      }
      if (body[pos] == '\n') {
        body[pos] = ' ';
      }
    }

    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "[%s] %s: %s", stamp_text,
             entry->sender[0] != '\0' ? entry->sender : "(unknown)", body);
    session_send_system_line(ctx, line);
  }
}

static void session_handle_mail(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!session_user_data_available(ctx) && !ctx->owner->user_data_ready) {
    session_send_system_line(ctx, "Mailbox storage is unavailable.");
    return;
  }

  const char *cursor = arguments != NULL ? arguments : "";
  char command[16];
  cursor = session_consume_token(cursor, command, sizeof(command));

  if (command[0] == '\0' || strcasecmp(command, "inbox") == 0) {
    session_mail_render_inbox(ctx);
    return;
  }

  if (strcasecmp(command, "send") == 0) {
    char target[SSH_CHATTER_USERNAME_LEN];
    cursor = session_consume_token(cursor, target, sizeof(target));
    if (target[0] == '\0' || cursor == NULL || cursor[0] == '\0') {
      session_send_system_line(ctx, "Usage: /mail send <user> <message>");
      return;
    }

    char message[USER_DATA_MAILBOX_MESSAGE_LEN];
    snprintf(message, sizeof(message), "%s", cursor);
    trim_whitespace_inplace(message);
    if (message[0] == '\0') {
      session_send_system_line(ctx, "Mailbox message cannot be empty.");
      return;
    }

    char error[128];
    if (!host_user_data_send_mail(ctx->owner, target, ctx->user.name, message, error, sizeof(error))) {
      if (error[0] != '\0') {
        session_send_system_line(ctx, error);
      } else {
        session_send_system_line(ctx, "Unable to deliver mailbox message.");
      }
      return;
    }

    if (strcasecmp(target, ctx->user.name) == 0) {
      (void)session_user_data_load(ctx);
    }

    char confirmation[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(confirmation, sizeof(confirmation), "Delivered mailbox message to %s.", target);
    session_send_system_line(ctx, confirmation);
    return;
  }

  if (strcasecmp(command, "clear") == 0) {
    if (!session_user_data_load(ctx)) {
      session_send_system_line(ctx, "Mailbox storage is unavailable.");
      return;
    }

    ctx->user_data.mailbox_count = 0U;
    memset(ctx->user_data.mailbox, 0, sizeof(ctx->user_data.mailbox));
    if (session_user_data_commit(ctx)) {
      session_send_system_line(ctx, "Mailbox cleared.");
    } else {
      session_send_system_line(ctx, "Failed to update mailbox.");
    }
    return;
  }

  session_send_system_line(ctx, "Usage: /mail [inbox|send <user> <message>|clear]");
}

static void session_profile_picture_normalize(const char *input, char *output, size_t length) {
  if (output == NULL || length == 0U) {
    return;
  }

  output[0] = '\0';
  if (input == NULL) {
    return;
  }

  size_t out_idx = 0U;
  size_t idx = 0U;
  while (input[idx] != '\0') {
    size_t skip = host_column_reset_sequence_length(&input[idx]);
    if (skip > 0U) {
      idx += skip;
      continue;
    }

    unsigned char ch = (unsigned char)input[idx];
    ++idx;
    if (ch == '\r') {
      continue;
    }
    if (ch >= 32U || ch == '\n' || ch == '\t') {
      if (out_idx + 1U < length) {
        output[out_idx++] = (char)ch;
      }
    }
  }

  if (out_idx < length) {
    output[out_idx] = '\0';
  } else {
    output[length - 1U] = '\0';
  }
}

static void session_handle_profile_picture(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!session_user_data_available(ctx) && !ctx->owner->user_data_ready) {
    session_send_system_line(ctx, "Profile storage is unavailable.");
    return;
  }

  const char *cursor = arguments != NULL ? arguments : "";
  char mode[16];
  cursor = session_consume_token(cursor, mode, sizeof(mode));

  if (mode[0] != '\0' && strcasecmp(mode, "ascii") != 0) {
    session_send_system_line(ctx, "Usage: /profilepic");
    return;
  }

  if (cursor != NULL && *cursor != '\0') {
    session_send_system_line(ctx, "Usage: /profilepic");
    return;
  }

  session_asciiart_begin(ctx, SESSION_ASCIIART_TARGET_PROFILE_PICTURE);
}

static void session_handle_reaction(session_ctx_t *ctx, size_t reaction_index, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL || reaction_index >= SSH_CHATTER_REACTION_KIND_COUNT) {
    return;
  }

  const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[reaction_index];

  char usage[64];
  snprintf(usage, sizeof(usage), "Usage: /%s <message-id>", descriptor->command);

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[64];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *endptr = NULL;
  unsigned long long parsed = strtoull(working, &endptr, 10);
  if (parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, usage);
    return;
  }

  uint64_t message_id = (uint64_t)parsed;
  chat_history_entry_t updated = {0};
  if (!host_history_apply_reaction(ctx->owner, message_id, reaction_index, &updated)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Message #%" PRIu64 " was not found or cannot be reacted to.", message_id);
    session_send_system_line(ctx, message);
    return;
  }

  char confirmation[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(confirmation, sizeof(confirmation), "Added %s %s to message #%" PRIu64 ".", descriptor->icon, descriptor->label,
           message_id);
  session_send_system_line(ctx, confirmation);
  chat_room_broadcast_reaction_update(ctx->owner, &updated);
  host_notify_external_clients(ctx->owner, &updated);
}

static void session_handle_usercount(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  size_t count = 0U;
  pthread_mutex_lock(&ctx->owner->room.lock);
  count = ctx->owner->room.member_count;
  pthread_mutex_unlock(&ctx->owner->room.lock);

  const bool eliza_active = atomic_load(&ctx->owner->eliza_enabled);
  size_t displayed = count;
  if (eliza_active) {
    if (SIZE_MAX - displayed > 0U) {
      ++displayed;
    }
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  if (eliza_active && displayed > count) {
    snprintf(message, sizeof(message), "There %s currently %zu user%s connected (including eliza).",
             displayed == 1U ? "is" : "are", displayed, displayed == 1U ? "" : "s");
  } else {
    snprintf(message, sizeof(message), "There %s currently %zu user%s connected.",
             displayed == 1U ? "is" : "are", displayed, displayed == 1U ? "" : "s");
  }

  host_history_record_system(ctx->owner, message);
  chat_room_broadcast(&ctx->owner->room, message, NULL);
}

static void session_handle_today(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  time_t now = time(NULL);
  struct tm tm_now;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
  if (localtime_r(&now, &tm_now) == NULL) {
    session_send_system_line(ctx, "Unable to determine local time.");
    return;
  }
#else
  struct tm *tmp = localtime(&now);
  if (tmp == NULL) {
    session_send_system_line(ctx, "Unable to determine local time.");
    return;
  }
  tm_now = *tmp;
#endif

  int year = tm_now.tm_year + 1900;
  int yday = tm_now.tm_yday;

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Unable to track today's function right now.");
    return;
  }

  if (!host->random_seeded) {
    unsigned seed = (unsigned)(now ^ (time_t)getpid());
    srand(seed);
    host->random_seeded = true;
  }

  const char *chosen = NULL;
  bool already = false;
  if (pref->daily_year == year && pref->daily_yday == yday && pref->daily_function[0] != '\0') {
    chosen = pref->daily_function;
    already = true;
  } else {
    const size_t function_count = sizeof(DAILY_FUNCTIONS) / sizeof(DAILY_FUNCTIONS[0]);
    if (function_count == 0U) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "No functions available today.");
      return;
    }
    size_t index = (size_t)rand() % function_count;
    chosen = DAILY_FUNCTIONS[index];
    pref->daily_year = year;
    pref->daily_yday = yday;
    snprintf(pref->daily_function, sizeof(pref->daily_function), "%s", chosen);
  }

  ctx->daily_year = pref->daily_year;
  ctx->daily_yday = pref->daily_yday;
  snprintf(ctx->daily_function, sizeof(ctx->daily_function), "%s", chosen);

  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  if (already) {
    snprintf(message, sizeof(message), "You've already discovered today's function: %s", chosen);
  } else {
    snprintf(message, sizeof(message), "Today's function for you is: %s", chosen);
  }
  session_send_system_line(ctx, message);
}

static void session_handle_date(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /date <Area/Location>";

  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char sanitized[PATH_MAX];
  if (!timezone_sanitize_identifier(working, sanitized, sizeof(sanitized))) {
    session_send_system_line(ctx, "Timezone names may only include letters, numbers, '/', '_', '-', '+', or '.'.");
    return;
  }

  char resolved[PATH_MAX];
  if (!timezone_resolve_identifier(sanitized, resolved, sizeof(resolved))) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown timezone '%.128s'.", working);
    session_send_system_line(ctx, message);
    return;
  }

  const char *previous_tz = getenv("TZ");
  char previous_copy[PATH_MAX];
  bool had_previous = false;
  if (previous_tz != NULL) {
    int prev_written = snprintf(previous_copy, sizeof(previous_copy), "%s", previous_tz);
    if (prev_written >= 0 && (size_t)prev_written < sizeof(previous_copy)) {
      had_previous = true;
    }
  }

  bool tz_applied = false;

  if (setenv("TZ", resolved, 1) != 0) {
    session_send_system_line(ctx, "Unable to adjust timezone right now.");
    return;
  }

  tzset();
  tz_applied = true;

  time_t now = time(NULL);
  if (now == (time_t)-1) {
    session_send_system_line(ctx, "Unable to determine current time.");
    goto cleanup;
  }

  struct tm tm_now;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
  if (localtime_r(&now, &tm_now) == NULL) {
    session_send_system_line(ctx, "Unable to compute the requested local time.");
    goto cleanup;
  }
#else
  struct tm *tmp = localtime(&now);
  if (tmp == NULL) {
    session_send_system_line(ctx, "Unable to compute the requested local time.");
    goto cleanup;
  }
  tm_now = *tmp;
#endif

  char formatted[128];
  if (strftime(formatted, sizeof(formatted), "%Y-%m-%d %H:%M:%S %Z (UTC%z)", &tm_now) == 0) {
    session_send_system_line(ctx, "Unable to format the requested time.");
    goto cleanup;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%.128s -> %s", resolved, formatted);
  session_send_system_line(ctx, message);

cleanup:
  if (tz_applied) {
    if (had_previous) {
      setenv("TZ", previous_copy, 1);
    } else {
      unsetenv("TZ");
    }
    tzset();
  }
}

static void session_handle_os(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage =
      "Usage: /os <windows|macos|linux|freebsd|ios|android|watchos|solaris|openbsd|netbsd|dragonflybsd|reactos|tyzen|kdos|pcdos|msdos|drdos|bsd|haiku|zealos|templeos>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_OS_NAME_LEN];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  for (size_t idx = 0U; working[idx] != '\0'; ++idx) {
    working[idx] = (char)tolower((unsigned char)working[idx]);
  }

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(working);
  if (descriptor == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  snprintf(ctx->os_name, sizeof(ctx->os_name), "%s", descriptor->name);
  host_store_user_os(ctx->owner, ctx);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Recorded your operating system as %s.", descriptor->display);
  session_send_system_line(ctx, message);
}

static void session_handle_getos(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /getos <username>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char target[SSH_CHATTER_USERNAME_LEN];
  snprintf(target, sizeof(target), "%s", arguments);
  trim_whitespace_inplace(target);
  if (target[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char os_buffer[SSH_CHATTER_OS_NAME_LEN];
  if (!host_lookup_user_os(ctx->owner, target, os_buffer, sizeof(os_buffer))) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No operating system is recorded for %s.", target);
    session_send_system_line(ctx, message);
    return;
  }

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(os_buffer);
  const char *display = descriptor != NULL ? descriptor->display : os_buffer;

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%s reports using %s.", target, display);
  session_send_system_line(ctx, message);
}

static void session_handle_pair(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (ctx->os_name[0] == '\0') {
    session_send_system_line(ctx, "Set your operating system first with /os <name>.");
    return;
  }

  char matches[SSH_CHATTER_MESSAGE_LIMIT];
  matches[0] = '\0';
  size_t offset = 0U;
  size_t match_count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL || member == ctx) {
      continue;
    }
    if (member->os_name[0] == '\0') {
      continue;
    }
    if (strcasecmp(member->os_name, ctx->os_name) != 0) {
      continue;
    }

    size_t name_len = strnlen(member->user.name, sizeof(member->user.name));
    const size_t prefix = match_count == 0U ? 0U : 2U;
    if (offset + prefix + name_len >= sizeof(matches)) {
      break;
    }
    if (match_count > 0U) {
      matches[offset++] = ',';
      matches[offset++] = ' ';
    }
    memcpy(matches + offset, member->user.name, name_len);
    offset += name_len;
    matches[offset] = '\0';
    ++match_count;
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  const os_descriptor_t *descriptor = session_lookup_os_descriptor(ctx->os_name);
  const char *display = descriptor != NULL ? descriptor->display : ctx->os_name;

  if (match_count == 0U) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No connected users currently share your %s setup.", display);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Users sharing your %s setup:", display);
  session_send_system_line(ctx, header);
  session_send_system_line(ctx, matches);
}

static void session_handle_connected(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  char buffer[SSH_CHATTER_MESSAGE_LIMIT];
  size_t offset = 0U;
  size_t count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL) {
      continue;
    }

    const size_t prefix = count == 0U ? 0U : 2U;
    size_t name_len = strnlen(member->user.name, sizeof(member->user.name));
    if (offset + prefix + name_len >= sizeof(buffer)) {
      break;
    }
    if (count > 0U) {
      buffer[offset++] = ',';
      buffer[offset++] = ' ';
    }
    memcpy(buffer + offset, member->user.name, name_len);
    offset += name_len;
    buffer[offset] = '\0';
    ++count;
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Connected users (%zu):", count);
  session_send_system_line(ctx, header);
  if (count > 0U) {
    session_send_system_line(ctx, buffer);
  }
}

static bool session_parse_birthday(const char *input, char *normalized, size_t length) {
  if (input == NULL || normalized == NULL || length < 11U) {
    return false;
  }

  char working[32];
  snprintf(working, sizeof(working), "%s", input);
  trim_whitespace_inplace(working);

  if (strlen(working) != 10U || working[4] != '-' || working[7] != '-') {
    return false;
  }

  for (size_t idx = 0U; idx < 10U; ++idx) {
    if (idx == 4U || idx == 7U) {
      continue;
    }
    if (!isdigit((unsigned char)working[idx])) {
      return false;
    }
  }

  int year = atoi(working);
  int month = atoi(working + 5);
  int day = atoi(working + 8);

  if (year < 1900 || year > 9999 || month < 1 || month > 12 || day < 1) {
    return false;
  }

  static const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int max_day = days_in_month[month - 1];
  bool leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
  if (month == 2 && leap) {
    max_day = 29;
  }
  if (day > max_day) {
    return false;
  }

  char formatted[16];
  int written = snprintf(formatted, sizeof(formatted), "%04d-%02d-%02d", year, month, day);
  if (written <= 0 || written >= (int)sizeof(formatted)) {
    return false;
  }
  if ((size_t)(written + 1) > length) {
    return false;
  }
  snprintf(normalized, length, "%s", formatted);
  return true;
}

static void session_handle_birthday(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /birthday YYYY-MM-DD");
    return;
  }

  char normalized[16];
  if (!session_parse_birthday(arguments, normalized, sizeof(normalized))) {
    session_send_system_line(ctx, "Invalid date. Use /birthday YYYY-MM-DD.");
    return;
  }

  ctx->has_birthday = true;
  snprintf(ctx->birthday, sizeof(ctx->birthday), "%s", normalized);
  host_store_birthday(ctx->owner, ctx, normalized);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Birthday recorded as %s.", normalized);
  session_send_system_line(ctx, message);
}

static void session_handle_soulmate(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->has_birthday) {
    session_send_system_line(ctx, "Set your birthday first with /birthday YYYY-MM-DD.");
    return;
  }

  char matches[SSH_CHATTER_MESSAGE_LIMIT];
  matches[0] = '\0';
  size_t count = 0U;

  pthread_mutex_lock(&ctx->owner->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    const user_preference_t *pref = &ctx->owner->preferences[idx];
    if (!pref->in_use || !pref->has_birthday) {
      continue;
    }
    if (strncmp(pref->birthday, ctx->birthday, sizeof(pref->birthday)) != 0) {
      continue;
    }
    if (strncmp(pref->username, ctx->user.name, SSH_CHATTER_USERNAME_LEN) == 0) {
      continue;
    }
    size_t current_len = strnlen(matches, sizeof(matches));
    size_t name_len = strnlen(pref->username, sizeof(pref->username));
    size_t prefix_len = count == 0U ? 0U : 2U;
    if (current_len + prefix_len + name_len >= sizeof(matches)) {
      continue;
    }
    if (count > 0U) {
      matches[current_len++] = ',';
      matches[current_len++] = ' ';
    }
    memcpy(matches + current_len, pref->username, name_len);
    matches[current_len + name_len] = '\0';
    ++count;
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  if (count == 0U) {
    session_send_system_line(ctx, "No birthday matches found right now.");
    return;
  }

  session_send_system_line(ctx, "Birthday soulmates:");
  session_send_system_line(ctx, matches);
}

static void session_handle_grant(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only LAN operators may grant operator privileges.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /grant <ip-address>");
    return;
  }

  char ip[SSH_CHATTER_IP_LEN];
  snprintf(ip, sizeof(ip), "%s", arguments);
  trim_whitespace_inplace(ip);
  if (ip[0] == '\0') {
    session_send_system_line(ctx, "Usage: /grant <ip-address>");
    return;
  }

  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET, ip, buf) != 1 && inet_pton(AF_INET6, ip, buf) != 1) {
    session_send_system_line(ctx, "Provide a valid IPv4 or IPv6 address.");
    return;
  }

  bool already_granted = false;
  bool added = false;
  pthread_mutex_lock(&ctx->owner->lock);
  already_granted = host_ip_has_grant_locked(ctx->owner, ip);
  if (!already_granted) {
    added = host_add_operator_grant_locked(ctx->owner, ip);
    if (added) {
      host_state_save_locked(ctx->owner);
    }
  } else {
    added = true;
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  if (!added) {
    session_send_system_line(ctx, "Cannot store more grants right now.");
    return;
  }

  if (already_granted) {
    session_send_system_line(ctx, "That IP already has operator privileges.");
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Operator privileges will be applied to %s.", ip);
    session_send_system_line(ctx, message);
  }
  host_apply_grant_to_ip(ctx->owner, ip);
}

static void session_handle_revoke(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only LAN administrators may revoke operator privileges.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /revoke <ip-address>");
    return;
  }

  char ip[SSH_CHATTER_IP_LEN];
  snprintf(ip, sizeof(ip), "%s", arguments);
  trim_whitespace_inplace(ip);
  if (ip[0] == '\0') {
    session_send_system_line(ctx, "Usage: /revoke <ip-address>");
    return;
  }

  unsigned char buf[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET, ip, buf) != 1 && inet_pton(AF_INET6, ip, buf) != 1) {
    session_send_system_line(ctx, "Provide a valid IPv4 or IPv6 address.");
    return;
  }

  bool removed = false;
  pthread_mutex_lock(&ctx->owner->lock);
  removed = host_remove_operator_grant_locked(ctx->owner, ip);
  if (removed) {
    host_state_save_locked(ctx->owner);
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  if (!removed) {
    session_send_system_line(ctx, "No stored grant exists for that IP address.");
    return;
  }

  host_revoke_grant_from_ip(ctx->owner, ip);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Operator privileges revoked for %s.", ip);
  session_send_system_line(ctx, message);
}

static void session_handle_delete_message(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may delete messages.");
    return;
  }

  static const char *kUsage = "Usage: /delete-msg <id|start-end>";
  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  uint64_t start_id = 0U;
  uint64_t end_id = 0U;
  char *dash = strchr(working, '-');
  if (dash != NULL) {
    *dash = '\0';
    char *end_token = dash + 1;
    trim_whitespace_inplace(working);
    trim_whitespace_inplace(end_token);
    if (working[0] == '\0' || end_token[0] == '\0') {
      session_send_system_line(ctx, kUsage);
      return;
    }

    char *endptr = NULL;
    errno = 0;
    unsigned long long start_value = strtoull(working, &endptr, 10);
    if (errno != 0 || endptr == NULL || *endptr != '\0' || start_value == 0ULL) {
      session_send_system_line(ctx, kUsage);
      return;
    }

    errno = 0;
    unsigned long long end_value = strtoull(end_token, &endptr, 10);
    if (errno != 0 || endptr == NULL || *endptr != '\0' || end_value == 0ULL) {
      session_send_system_line(ctx, kUsage);
      return;
    }

    start_id = (uint64_t)start_value;
    end_id = (uint64_t)end_value;
    if (start_id > end_id) {
      session_send_system_line(ctx, "Start identifier must be less than or equal to the end identifier.");
      return;
    }
  } else {
    char *endptr = NULL;
    errno = 0;
    unsigned long long value = strtoull(working, &endptr, 10);
    if (errno != 0 || endptr == NULL || *endptr != '\0' || value == 0ULL) {
      session_send_system_line(ctx, kUsage);
      return;
    }
    start_id = (uint64_t)value;
    end_id = start_id;
  }

  uint64_t first_removed = 0U;
  uint64_t last_removed = 0U;
  size_t replies_removed = 0U;
  size_t removed = host_history_delete_range(ctx->owner, start_id, end_id, &first_removed, &last_removed, &replies_removed);
  if (removed == 0U) {
    session_send_system_line(ctx, "No chat messages matched that identifier.");
    return;
  }

  char range_label[64];
  if (last_removed != 0U && last_removed != first_removed) {
    snprintf(range_label, sizeof(range_label), "#%" PRIu64 "-#%" PRIu64, first_removed, last_removed);
  } else {
    snprintf(range_label, sizeof(range_label), "#%" PRIu64, first_removed);
  }

  char reply_note[64];
  if (replies_removed > 0U) {
    snprintf(reply_note, sizeof(reply_note), " (%zu repl%s removed)", replies_removed, replies_removed == 1U ? "y" : "ies");
  } else {
    reply_note[0] = '\0';
  }

  char acknowledgement[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(acknowledgement, sizeof(acknowledgement), "Removed %zu message%s (%s)%s.", removed,
           removed == 1U ? "" : "s", range_label, reply_note);
  session_send_system_line(ctx, acknowledgement);

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [%s] removed %s %s%s.", ctx->user.name, removed == 1U ? "message" : "messages",
           range_label, reply_note);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
}

static void session_handle_poll(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage =
      "Usage: /poll <question>|<option1>|<option2>[|option3][|option4][|option5] or /poll to view current poll";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_poll_summary(ctx);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_poll_summary(ctx);
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may modify the main poll.");
    return;
  }

  char *tokens[1 + 5];
  size_t token_count = 0U;
  char *cursor = working;
  while (cursor != NULL && token_count < sizeof(tokens) / sizeof(tokens[0])) {
    char *next = strchr(cursor, '|');
    if (next != NULL) {
      *next = '\0';
    }
    trim_whitespace_inplace(cursor);
    tokens[token_count++] = cursor;
    cursor = next != NULL ? next + 1 : NULL;
  }

  if (token_count < 3U) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  size_t option_count = token_count - 1U;
  if (option_count > 5U) {
    option_count = 5U;
  }

  for (size_t idx = 1U; idx <= option_count; ++idx) {
    if (tokens[idx][0] == '\0') {
      session_send_system_line(ctx, "Poll options cannot be empty.");
      return;
    }
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  if (host->poll.id == UINT64_MAX) {
    host->poll.id = 0U;
  }
  host->poll.id += 1U;
  host->poll.active = true;
  host->poll.option_count = option_count;
  host->poll.allow_multiple = false;
  snprintf(host->poll.question, sizeof(host->poll.question), "%s", tokens[0]);
  for (size_t idx = 0U; idx < option_count; ++idx) {
    snprintf(host->poll.options[idx].text, sizeof(host->poll.options[idx].text), "%s", tokens[idx + 1U]);
    host->poll.options[idx].votes = 0U;
  }
  for (size_t idx = option_count; idx < sizeof(host->poll.options) / sizeof(host->poll.options[0]); ++idx) {
    host->poll.options[idx].text[0] = '\0';
    host->poll.options[idx].votes = 0U;
  }
  host_vote_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char announce[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(announce, sizeof(announce), "* [%s] started poll #%" PRIu64 ": %s", ctx->user.name, host->poll.id, tokens[0]);
  chat_room_broadcast(&host->room, announce, NULL);

  for (size_t idx = 0U; idx < option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(option_line, sizeof(option_line), "  /%zu - %s", idx + 1U, tokens[idx + 1U]);
    chat_room_broadcast(&host->room, option_line, NULL);
  }

  session_send_system_line(ctx, "Poll created successfully.");
  session_send_poll_summary(ctx);
}

static void session_handle_vote(session_ctx_t *ctx, size_t option_index) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  if (!host->poll.active || option_index >= host->poll.option_count) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "There is no active poll for that choice.");
    return;
  }

  user_preference_t *pref = host_ensure_preference_locked(host, ctx->user.name);
  if (pref == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Unable to record your vote right now.");
    return;
  }

  if (pref->last_poll_id == host->poll.id && pref->last_poll_choice == (int)option_index) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "You have already voted for that option.");
    return;
  }

  if (pref->last_poll_id == host->poll.id && pref->last_poll_choice >= 0 &&
      (size_t)pref->last_poll_choice < host->poll.option_count) {
    if (host->poll.options[pref->last_poll_choice].votes > 0U) {
      host->poll.options[pref->last_poll_choice].votes -= 1U;
    }
  }

  host->poll.options[option_index].votes += 1U;
  pref->last_poll_id = host->poll.id;
  pref->last_poll_choice = (int)option_index;
  host_vote_state_save_locked(host);
  host_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Vote recorded for option /%zu.", option_index + 1U);
  session_send_system_line(ctx, message);
  session_send_poll_summary(ctx);
}

// Record a vote in a named poll, ensuring a user can move their vote between options.
static void session_handle_named_vote(session_ctx_t *ctx, size_t option_index, const char *label) {
  if (ctx == NULL || ctx->owner == NULL || label == NULL || label[0] == '\0') {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  named_poll_state_t *poll = host_find_named_poll_locked(host, label);
  if (poll == NULL || !poll->poll.active || option_index >= poll->poll.option_count) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "There is no active poll with that label.");
    return;
  }

  const bool allow_multiple = poll->poll.allow_multiple;
  const uint32_t option_bit = (option_index < 32U) ? (1U << option_index) : 0U;

  size_t voter_slot = SIZE_MAX;
  for (size_t idx = 0U; idx < poll->voter_count; ++idx) {
    if (poll->voters[idx].username[0] == '\0') {
      continue;
    }
    if (strcasecmp(poll->voters[idx].username, ctx->user.name) == 0) {
      voter_slot = idx;
      break;
    }
  }

  if (voter_slot == SIZE_MAX) {
    if (poll->voter_count >= SSH_CHATTER_MAX_NAMED_VOTERS) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "Vote tracking is full for this poll right now.");
      return;
    }
    voter_slot = poll->voter_count++;
    snprintf(poll->voters[voter_slot].username, sizeof(poll->voters[voter_slot].username), "%s", ctx->user.name);
    poll->voters[voter_slot].choice = -1;
    poll->voters[voter_slot].choices_mask = 0U;
  }

  uint32_t *mask = &poll->voters[voter_slot].choices_mask;
  if (allow_multiple) {
    if (option_bit != 0U && (*mask & option_bit) != 0U) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "You have already voted for that option.");
      return;
    }
  } else {
    if (poll->voters[voter_slot].choice == (int)option_index) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "You have already voted for that option.");
      return;
    }
    if (poll->voters[voter_slot].choice >= 0) {
      int previous = poll->voters[voter_slot].choice;
      if (previous >= 0 && (size_t)previous < poll->poll.option_count && poll->poll.options[previous].votes > 0U) {
        poll->poll.options[previous].votes -= 1U;
      }
    }
  }

  poll->poll.options[option_index].votes += 1U;
  if (allow_multiple) {
    if (option_bit != 0U) {
      *mask |= option_bit;
    }
    poll->voters[voter_slot].choice = -1;
  } else {
    poll->voters[voter_slot].choice = (int)option_index;
    poll->voters[voter_slot].choices_mask = (option_bit != 0U) ? option_bit : 0U;
  }

  char resolved_label[SSH_CHATTER_POLL_LABEL_LEN];
  snprintf(resolved_label, sizeof(resolved_label), "%s", poll->label);
  host_vote_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Vote recorded for /%zu %s.", option_index + 1U, resolved_label);
  session_send_system_line(ctx, message);
  session_send_poll_summary_generic(ctx, &poll->poll, resolved_label);
}

// Allow voting in a named poll by specifying the label and desired choice directly.
static void session_handle_elect_command(session_ctx_t *ctx, const char *arguments) {
  const char *usage = "Usage: /elect <label> <choice>";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *label = working;
  char *choice = working;
  while (*choice != '\0' && !isspace((unsigned char)*choice)) {
    ++choice;
  }
  if (*choice != '\0') {
    *choice++ = '\0';
  }
  while (*choice == ' ' || *choice == '\t') {
    ++choice;
  }

  if (label[0] == '\0' || *choice == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  trim_whitespace_inplace(choice);

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  named_poll_state_t *poll = host_find_named_poll_locked(host, label);
  if (poll == NULL || !poll->poll.active) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "There is no active poll with that label.");
    return;
  }

  char canonical_label[SSH_CHATTER_POLL_LABEL_LEN];
  snprintf(canonical_label, sizeof(canonical_label), "%s", poll->label);

  size_t option_index = SIZE_MAX;
  const size_t option_count = poll->poll.option_count;

  const char *numeric_start = choice;
  if (*numeric_start == '/') {
    ++numeric_start;
  }
  if (*numeric_start != '\0') {
    char *endptr = NULL;
    unsigned long parsed = strtoul(numeric_start, &endptr, 10);
    if (endptr != NULL && endptr != numeric_start && *endptr == '\0' && parsed >= 1UL && parsed <= option_count) {
      option_index = (size_t)(parsed - 1UL);
    }
  }

  if (option_index == SIZE_MAX) {
    for (size_t idx = 0U; idx < option_count; ++idx) {
      if (poll->poll.options[idx].text[0] == '\0') {
        continue;
      }
      if (strcasecmp(poll->poll.options[idx].text, choice) == 0) {
        option_index = idx;
        break;
      }
    }
  }

  pthread_mutex_unlock(&host->lock);

  if (option_index == SIZE_MAX) {
    session_send_system_line(ctx, "That choice is not available in this poll.");
    return;
  }

  session_handle_named_vote(ctx, option_index, canonical_label);
}

// Parse the /vote command to manage named polls, including listing, creation, and closure.
static void session_handle_vote_command(session_ctx_t *ctx, const char *arguments, bool allow_multiple) {
  const char *usage = allow_multiple
                          ? "Usage: /vote <label> <question>|<option1>|<option2>[|option3][|option4][|option5]"
                          : "Usage: /vote-single <label> <question>|<option1>|<option2>[|option3][|option4][|option5]";
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_list_named_polls(ctx);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_list_named_polls(ctx);
    return;
  }

  if (strncmp(working, "@close", 6) == 0 && (working[6] == '\0' || isspace((unsigned char)working[6]))) {
    const char *label_start = working + 6;
    while (*label_start != '\0' && isspace((unsigned char)*label_start)) {
      ++label_start;
    }
    if (*label_start == '\0') {
      session_send_system_line(ctx, "Usage: /vote @close <label>");
      return;
    }

    char label[SSH_CHATTER_POLL_LABEL_LEN];
    size_t close_len = 0U;
    while (label_start[close_len] != '\0' && !isspace((unsigned char)label_start[close_len])) {
      if (close_len + 1U >= sizeof(label)) {
        session_send_system_line(ctx, "Poll label is too long.");
        return;
      }
      label[close_len] = label_start[close_len];
      ++close_len;
    }
    label[close_len] = '\0';
    if (!poll_label_is_valid(label)) {
      session_send_system_line(ctx, "Poll labels may contain only letters, numbers, hyphens, or underscores.");
      return;
    }

    host_t *host = ctx->owner;
    pthread_mutex_lock(&host->lock);
    named_poll_state_t *poll = host_find_named_poll_locked(host, label);
    if (poll == NULL || !poll->poll.active) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "That poll is not currently active.");
      return;
    }

    bool has_privilege = ctx->user.is_operator || ctx->user.is_lan_operator ||
                         (poll->owner[0] != '\0' && strcasecmp(poll->owner, ctx->user.name) == 0);
    if (!has_privilege) {
      pthread_mutex_unlock(&host->lock);
      session_send_system_line(ctx, "Only the poll owner or an operator may close this poll.");
      return;
    }

    poll_state_reset(&poll->poll);
    poll->voter_count = 0U;
    host_recount_named_polls_locked(host);
    host_vote_state_save_locked(host);
    pthread_mutex_unlock(&host->lock);

    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "* [%s] closed poll [%s].", ctx->user.name, label);
    chat_room_broadcast(&host->room, message, NULL);
    session_send_system_line(ctx, "Poll closed.");
    return;
  }

  char label[SSH_CHATTER_POLL_LABEL_LEN];
  size_t label_len = 0U;
  const char *cursor = working;
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    if (label_len + 1U >= sizeof(label)) {
      session_send_system_line(ctx, "Poll label is too long.");
      return;
    }
    label[label_len++] = *cursor++;
  }
  label[label_len] = '\0';
  if (!poll_label_is_valid(label)) {
    session_send_system_line(ctx, "Poll labels may contain only letters, numbers, hyphens, or underscores.");
    return;
  }

  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    host_t *host = ctx->owner;
    pthread_mutex_lock(&host->lock);
    named_poll_state_t *poll = host_find_named_poll_locked(host, label);
    named_poll_state_t snapshot = {0};
    if (poll != NULL) {
      snapshot = *poll;
    }
    pthread_mutex_unlock(&host->lock);

    if (poll == NULL) {
      session_send_system_line(ctx, "No poll exists with that label.");
      return;
    }

    session_send_poll_summary_generic(ctx, &snapshot.poll, snapshot.label);
    return;
  }

  char definition[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(definition, sizeof(definition), "%s", cursor);
  trim_whitespace_inplace(definition);
  if (definition[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *tokens[1 + 5];
  size_t token_count = 0U;
  char *token_cursor = definition;
  while (token_cursor != NULL && token_count < sizeof(tokens) / sizeof(tokens[0])) {
    char *next = strchr(token_cursor, '|');
    if (next != NULL) {
      *next = '\0';
    }
    trim_whitespace_inplace(token_cursor);
    tokens[token_count++] = token_cursor;
    token_cursor = next != NULL ? next + 1 : NULL;
  }

  if (token_count < 3U) {
    session_send_system_line(ctx, "Provide at least a question and two options.");
    return;
  }

  size_t option_count = token_count - 1U;
  if (option_count > 5U) {
    option_count = 5U;
  }

  for (size_t idx = 1U; idx <= option_count; ++idx) {
    if (tokens[idx][0] == '\0') {
      session_send_system_line(ctx, "Poll options cannot be empty.");
      return;
    }
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  named_poll_state_t *poll = host_ensure_named_poll_locked(host, label);
  if (poll == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Too many named polls are already registered.");
    return;
  }

  if (poll->poll.active && poll->owner[0] != '\0' && strcasecmp(poll->owner, ctx->user.name) != 0 &&
      !ctx->user.is_operator && !ctx->user.is_lan_operator) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Only the poll owner or an operator may restart this poll.");
    return;
  }

  if (poll->poll.id == UINT64_MAX) {
    poll->poll.id = 0U;
  }
  poll->poll.id += 1U;
  poll->poll.active = true;
  poll->poll.option_count = option_count;
  poll->poll.allow_multiple = allow_multiple;
  snprintf(poll->poll.question, sizeof(poll->poll.question), "%s", tokens[0]);
  for (size_t idx = 0U; idx < option_count; ++idx) {
    snprintf(poll->poll.options[idx].text, sizeof(poll->poll.options[idx].text), "%s", tokens[idx + 1U]);
    poll->poll.options[idx].votes = 0U;
  }
  for (size_t idx = option_count; idx < sizeof(poll->poll.options) / sizeof(poll->poll.options[0]); ++idx) {
    poll->poll.options[idx].text[0] = '\0';
    poll->poll.options[idx].votes = 0U;
  }
  snprintf(poll->owner, sizeof(poll->owner), "%s", ctx->user.name);
  poll->voter_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_VOTERS; ++idx) {
    poll->voters[idx].username[0] = '\0';
    poll->voters[idx].choice = -1;
    poll->voters[idx].choices_mask = 0U;
  }
  host_recount_named_polls_locked(host);
  named_poll_state_t snapshot = *poll;
  host_vote_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  char announce[SSH_CHATTER_MESSAGE_LIMIT];
  int question_preview = (int)strnlen(snapshot.poll.question, sizeof(snapshot.poll.question));
  if (question_preview > 120) {
    question_preview = 120;
  }
  snprintf(announce, sizeof(announce), "* [%s] started poll [%s] #%" PRIu64 ": %.*s", ctx->user.name, label, snapshot.poll.id,
           question_preview, snapshot.poll.question);
  chat_room_broadcast(&host->room, announce, NULL);

  for (size_t idx = 0U; idx < snapshot.poll.option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(option_line, sizeof(option_line), "  /%zu %s - %s", idx + 1U, label, snapshot.poll.options[idx].text);
    chat_room_broadcast(&host->room, option_line, NULL);
  }

  session_send_system_line(ctx, "Named poll created successfully.");
  session_send_poll_summary_generic(ctx, &snapshot.poll, snapshot.label);
}

// Format a timestamp for BBS displays in a compact form.
static void bbs_format_time(time_t value, char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return;
  }
  struct tm tm_value;
  if (localtime_r(&value, &tm_value) == NULL) {
    snprintf(buffer, length, "-");
    return;
  }
  strftime(buffer, length, "%Y-%m-%d %H:%M", &tm_value);
}

// Return a post by identifier while the host lock is held.
static bbs_post_t *host_find_bbs_post_locked(host_t *host, uint64_t id) {
  if (host == NULL || id == 0U) {
    return NULL;
  }
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (!host->bbs_posts[idx].in_use) {
      continue;
    }
    if (host->bbs_posts[idx].id == id) {
      return &host->bbs_posts[idx];
    }
  }
  return NULL;
}

// Allocate a new post slot, returning NULL if capacity has been reached.
static bbs_post_t *host_allocate_bbs_post_locked(host_t *host) {
  if (host == NULL) {
    return NULL;
  }
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (host->bbs_posts[idx].in_use) {
      continue;
    }
    bbs_post_t *post = &host->bbs_posts[idx];
    post->in_use = true;
    post->id = host->next_bbs_id++;
    post->tag_count = 0U;
    post->comment_count = 0U;
    post->created_at = time(NULL);
    post->bumped_at = post->created_at;
    post->title[0] = '\0';
    post->body[0] = '\0';
    post->author[0] = '\0';
    for (size_t tag = 0U; tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
      post->tags[tag][0] = '\0';
    }
    for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
      post->comments[comment].author[0] = '\0';
      post->comments[comment].text[0] = '\0';
      post->comments[comment].created_at = 0;
    }
    if (host->bbs_post_count < SSH_CHATTER_BBS_MAX_POSTS) {
      host->bbs_post_count += 1U;
    }
    return post;
  }
  return NULL;
}

static void host_reset_bbs_post(bbs_post_t *post) {
  if (post == NULL) {
    return;
  }

  post->in_use = false;
  post->id = 0U;
  post->author[0] = '\0';
  post->title[0] = '\0';
  post->body[0] = '\0';
  post->tag_count = 0U;
  post->created_at = 0;
  post->bumped_at = 0;
  post->comment_count = 0U;
  for (size_t tag = 0U; tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
    post->tags[tag][0] = '\0';
  }
  for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
    post->comments[comment].author[0] = '\0';
    post->comments[comment].text[0] = '\0';
    post->comments[comment].created_at = 0;
  }
}

static void host_clear_bbs_post_locked(host_t *host, bbs_post_t *post) {
  if (host == NULL || post == NULL) {
    return;
  }

  host_reset_bbs_post(post);

  size_t write_index = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (!host->bbs_posts[idx].in_use) {
      continue;
    }

    if (write_index != idx) {
      host->bbs_posts[write_index] = host->bbs_posts[idx];
    }

    ++write_index;
  }

  for (size_t idx = write_index; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    host_reset_bbs_post(&host->bbs_posts[idx]);
  }

  host->bbs_post_count = write_index;
}

static void session_bbs_queue_translation(session_ctx_t *ctx, const bbs_post_t *post) {
  if (ctx == NULL || post == NULL || !post->in_use) {
    return;
  }

  if (!ctx->translation_enabled || !ctx->output_translation_enabled ||
      ctx->output_translation_language[0] == '\0') {
    return;
  }

  char payload[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  size_t offset = 0U;

  offset = session_append_fragment(payload, sizeof(payload), offset, "Title: ");
  offset = session_append_fragment(payload, sizeof(payload), offset, post->title);
  offset = session_append_fragment(payload, sizeof(payload), offset, "\nAuthor: ");
  offset = session_append_fragment(payload, sizeof(payload), offset, post->author);

  char created_buffer[32];
  char bumped_buffer[32];
  bbs_format_time(post->created_at, created_buffer, sizeof(created_buffer));
  bbs_format_time(post->bumped_at, bumped_buffer, sizeof(bumped_buffer));
  offset = session_append_fragment(payload, sizeof(payload), offset, "\nCreated: ");
  offset = session_append_fragment(payload, sizeof(payload), offset, created_buffer);
  offset = session_append_fragment(payload, sizeof(payload), offset, " (bumped ");
  offset = session_append_fragment(payload, sizeof(payload), offset, bumped_buffer);
  offset = session_append_fragment(payload, sizeof(payload), offset, ")\n");

  if (post->tag_count > 0U) {
    offset = session_append_fragment(payload, sizeof(payload), offset, "Tags: ");
    for (size_t idx = 0U; idx < post->tag_count; ++idx) {
      if (idx > 0U) {
        offset = session_append_fragment(payload, sizeof(payload), offset, ",");
      }
      offset = session_append_fragment(payload, sizeof(payload), offset, post->tags[idx]);
    }
  } else {
    offset = session_append_fragment(payload, sizeof(payload), offset, "Tags: (none)");
  }

  offset = session_append_fragment(payload, sizeof(payload), offset, "\nBody:\n");
  if (post->body[0] != '\0') {
    offset = session_append_fragment(payload, sizeof(payload), offset, post->body);
  } else {
    offset = session_append_fragment(payload, sizeof(payload), offset, "(empty)");
  }

  if (post->comment_count > 0U) {
    offset = session_append_fragment(payload, sizeof(payload), offset, "\nComments:\n");
    for (size_t idx = 0U; idx < post->comment_count; ++idx) {
      const bbs_comment_t *comment = &post->comments[idx];
      offset = session_append_fragment(payload, sizeof(payload), offset, comment->author);
      offset = session_append_fragment(payload, sizeof(payload), offset, ": ");
      offset = session_append_fragment(payload, sizeof(payload), offset, comment->text);
      offset = session_append_fragment(payload, sizeof(payload), offset, "\n");
    }
  } else {
    offset = session_append_fragment(payload, sizeof(payload), offset, "\nComments: none");
  }

  payload[offset < sizeof(payload) ? offset : sizeof(payload) - 1U] = '\0';

  if (payload[0] == '\0') {
    return;
  }

  if (session_translation_queue_caption(ctx, payload, 0U)) {
    session_translation_flush_ready(ctx);
  }
}

// Render an ASCII framed view of a post, including metadata and comments.
static void session_bbs_emit_line_if_visible(session_ctx_t *ctx, const char *line, bool column_reset,
                                             size_t offset, size_t window, bool emit, size_t *line_index) {
  if (line_index == NULL) {
    return;
  }

  const char *text = (line != NULL) ? line : "";
  (void)column_reset;

  if (!emit) {
    ++(*line_index);
    return;
  }

  size_t start = offset;
  size_t end = (window == 0U || offset > SIZE_MAX - window) ? SIZE_MAX : offset + window;
  if (*line_index >= start && *line_index < end) {
    if (host_contains_column_reset(text)) {
      char sanitized[SSH_CHATTER_MESSAGE_LIMIT];
      sanitized[0] = '\0';
      snprintf(sanitized, sizeof(sanitized), "%s", text);
      host_strip_column_reset(sanitized);
      session_send_system_line(ctx, sanitized);
    } else {
      session_send_system_line(ctx, text);
    }
  }

  ++(*line_index);
}

static size_t session_bbs_render_post_iterate(session_ctx_t *ctx, const bbs_post_t *post, const char *notice,
                                              size_t offset, size_t window, bool emit) {
  size_t line_index = 0U;

  char header_label[64];
  snprintf(header_label, sizeof(header_label), "BBS Post #%" PRIu64, post->id);
  char separator_line[SSH_CHATTER_MESSAGE_LIMIT];
  session_format_separator_line(ctx, header_label, separator_line, sizeof(separator_line));
  session_bbs_emit_line_if_visible(ctx, separator_line, false, offset, window, emit, &line_index);

  if (notice != NULL && notice[0] != '\0') {
    session_bbs_emit_line_if_visible(ctx, notice, false, offset, window, emit, &line_index);
    session_bbs_emit_line_if_visible(ctx, "", false, offset, window, emit, &line_index);
  }

  char created_buffer[32];
  char bumped_buffer[32];
  bbs_format_time(post->created_at, created_buffer, sizeof(created_buffer));
  bbs_format_time(post->bumped_at, bumped_buffer, sizeof(bumped_buffer));

  char metadata[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(metadata, sizeof(metadata), "Title : %s", post->title);
  session_bbs_emit_line_if_visible(ctx, metadata, false, offset, window, emit, &line_index);
  snprintf(metadata, sizeof(metadata), "Author: %s", post->author);
  session_bbs_emit_line_if_visible(ctx, metadata, false, offset, window, emit, &line_index);
  snprintf(metadata, sizeof(metadata), "Created: %s (bumped %s)", created_buffer, bumped_buffer);
  session_bbs_emit_line_if_visible(ctx, metadata, false, offset, window, emit, &line_index);

  if (post->tag_count > 0U) {
    char tag_line[SSH_CHATTER_MESSAGE_LIMIT];
    int header_written = snprintf(tag_line, sizeof(tag_line), "Tags  : ");
    size_t tag_offset = header_written > 0 ? (size_t)header_written : 0U;
    if (tag_offset >= sizeof(tag_line)) {
      tag_offset = sizeof(tag_line) - 1U;
    }
    for (size_t idx = 0U; idx < post->tag_count; ++idx) {
      size_t tag_len = strlen(post->tags[idx]);
      if (tag_offset + tag_len + 2U >= sizeof(tag_line)) {
        break;
      }
      if (idx > 0U) {
        tag_line[tag_offset++] = ',';
      }
      memcpy(tag_line + tag_offset, post->tags[idx], tag_len);
      tag_offset += tag_len;
      tag_line[tag_offset] = '\0';
    }
    session_bbs_emit_line_if_visible(ctx, tag_line, false, offset, window, emit, &line_index);
  } else {
    session_bbs_emit_line_if_visible(ctx, "Tags  : (none)", false, offset, window, emit, &line_index);
  }

  if (ctx != NULL && ctx->owner != NULL) {
    user_data_record_t author_record;
    if (host_user_data_find_profile_picture(ctx->owner, post->author, &author_record)) {
      session_format_separator_line(ctx, "Profile Picture", separator_line, sizeof(separator_line));
      session_bbs_emit_line_if_visible(ctx, separator_line, false, offset, window, emit, &line_index);

      const char *picture_cursor = author_record.profile_picture;
      while (picture_cursor != NULL && *picture_cursor != '\0') {
        const char *newline = strchr(picture_cursor, '\n');
        if (newline == NULL) {
          session_bbs_emit_line_if_visible(ctx, picture_cursor, true, offset, window, emit, &line_index);
          break;
        }

        size_t len = (size_t)(newline - picture_cursor);
        if (len >= SSH_CHATTER_MESSAGE_LIMIT) {
          len = SSH_CHATTER_MESSAGE_LIMIT - 1U;
        }

        char line[SSH_CHATTER_MESSAGE_LIMIT];
        memcpy(line, picture_cursor, len);
        line[len] = '\0';
        session_bbs_emit_line_if_visible(ctx, line, true, offset, window, emit, &line_index);
        picture_cursor = newline + 1;
      }

      session_bbs_emit_line_if_visible(ctx, "", false, offset, window, emit, &line_index);
    }
  }

  session_format_separator_line(ctx, "Body", separator_line, sizeof(separator_line));
  session_bbs_emit_line_if_visible(ctx, separator_line, false, offset, window, emit, &line_index);

  if (post->body[0] != '\0') {
    const char *body_cursor = post->body;
    while (body_cursor != NULL && *body_cursor != '\0') {
      const char *newline = strchr(body_cursor, '\n');
      if (newline == NULL) {
        session_bbs_emit_line_if_visible(ctx, body_cursor, true, offset, window, emit, &line_index);
        break;
      }
      size_t len = (size_t)(newline - body_cursor);
      if (len >= SSH_CHATTER_MESSAGE_LIMIT) {
        len = SSH_CHATTER_MESSAGE_LIMIT - 1U;
      }
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      memcpy(line, body_cursor, len);
      line[len] = '\0';
      session_bbs_emit_line_if_visible(ctx, line, true, offset, window, emit, &line_index);
      body_cursor = newline + 1;
    }
  } else {
    session_bbs_emit_line_if_visible(ctx, "(empty)", false, offset, window, emit, &line_index);
  }

  session_format_separator_line(ctx, "Comments", separator_line, sizeof(separator_line));
  session_bbs_emit_line_if_visible(ctx, separator_line, false, offset, window, emit, &line_index);

  if (post->comment_count == 0U) {
    session_bbs_emit_line_if_visible(ctx, "No comments yet.", false, offset, window, emit, &line_index);
  } else {
    for (size_t idx = 0U; idx < post->comment_count; ++idx) {
      const bbs_comment_t *comment = &post->comments[idx];
      char comment_time[32];
      bbs_format_time(comment->created_at, comment_time, sizeof(comment_time));
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "[%zu] %s (%s)", idx + 1U, comment->author, comment_time);
      session_bbs_emit_line_if_visible(ctx, line, false, offset, window, emit, &line_index);
      session_bbs_emit_line_if_visible(ctx, comment->text, true, offset, window, emit, &line_index);
    }
  }

  const bool translation_active = ctx->translation_enabled && ctx->output_translation_enabled &&
                                  ctx->output_translation_language[0] != '\0';
  if (translation_active && post->comment_count > 0U) {
    session_bbs_emit_line_if_visible(ctx, "", false, offset, window, emit, &line_index);
  }

  session_bbs_emit_line_if_visible(ctx, "", false, offset, window, emit, &line_index);
  session_format_separator_line(ctx, "Write a comment", separator_line, sizeof(separator_line));
  session_bbs_emit_line_if_visible(ctx, separator_line, false, offset, window, emit, &line_index);

  char reply_instruction[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(reply_instruction, sizeof(reply_instruction),
           "Reply with /bbs comment %" PRIu64 "|<message> (or /bbs exit to leave this view).", post->id);
  session_bbs_emit_line_if_visible(ctx, reply_instruction, false, offset, window, emit, &line_index);
  session_bbs_emit_line_if_visible(ctx, "Need a new thread? Use /bbs post <title>[|tags...] instead.", false, offset,
                                   window, emit, &line_index);
  session_bbs_emit_line_if_visible(ctx, "Use Up/Down arrows or PgUp/PgDn to scroll this post.", false, offset, window,
                                   emit, &line_index);

  return line_index;
}

static void session_bbs_render_post(session_ctx_t *ctx, const bbs_post_t *post, const char *notice,
                                    bool reset_scroll, bool scroll_to_bottom) {
  if (ctx == NULL || post == NULL || !post->in_use) {
    return;
  }

  bool previous_override = session_translation_push_scope_override(ctx);

  bool same_post = ctx->bbs_view_active && ctx->bbs_view_post_id == post->id;
  if (!same_post || reset_scroll) {
    ctx->bbs_view_scroll_offset = 0U;
  }

  ctx->bbs_view_active = true;
  ctx->bbs_view_post_id = post->id;

  if (notice != NULL && notice[0] != '\0') {
    snprintf(ctx->bbs_view_notice, sizeof(ctx->bbs_view_notice), "%s", notice);
    ctx->bbs_view_notice_pending = true;
  }

  const char *active_notice = ctx->bbs_view_notice_pending ? ctx->bbs_view_notice : NULL;

  size_t window = SSH_CHATTER_BBS_VIEW_WINDOW;
  if (window == 0U) {
    window = 1U;
  }

  size_t total_lines = session_bbs_render_post_iterate(ctx, post, active_notice, 0U, window, false);
  if (total_lines == 0U) {
    total_lines = 1U;
  }
  ctx->bbs_view_total_lines = total_lines;

  size_t max_offset = (total_lines > window) ? (total_lines - window) : 0U;
  size_t desired_offset = ctx->bbs_view_scroll_offset;
  if (scroll_to_bottom) {
    desired_offset = max_offset;
  }
  if (desired_offset > max_offset) {
    desired_offset = max_offset;
  }
  ctx->bbs_view_scroll_offset = desired_offset;

  session_bbs_prepare_canvas(ctx);
  session_bbs_render_post_iterate(ctx, post, active_notice, desired_offset, window, true);
  ctx->bbs_view_notice_pending = false;

  session_bbs_queue_translation(ctx, post);
  session_translation_pop_scope_override(ctx, previous_override);
}

static bool session_bbs_refresh_view(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL || !ctx->bbs_view_active || ctx->bbs_view_post_id == 0U) {
    return false;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_find_bbs_post_locked(host, ctx->bbs_view_post_id);
  bbs_post_t snapshot = {0};
  if (post != NULL) {
    snapshot = *post;
  }
  pthread_mutex_unlock(&host->lock);

  if (post == NULL || !snapshot.in_use) {
    ctx->bbs_view_active = false;
    ctx->bbs_view_post_id = 0U;
    ctx->bbs_view_total_lines = 0U;
    ctx->bbs_view_scroll_offset = 0U;
    session_send_system_line(ctx, "That post is no longer available.");
    return false;
  }

  session_bbs_render_post(ctx, &snapshot, NULL, false, false);
  return true;
}

static bool session_bbs_scroll(session_ctx_t *ctx, int direction, size_t step) {
  if (ctx == NULL || ctx->owner == NULL || !ctx->bbs_view_active || direction == 0) {
    return false;
  }

  size_t window = SSH_CHATTER_BBS_VIEW_WINDOW;
  if (window == 0U) {
    window = 1U;
  }

  size_t total = ctx->bbs_view_total_lines;
  if (total <= window) {
    if (direction > 0) {
      session_send_system_line(ctx, "Already viewing the top of this post.");
    } else if (direction < 0) {
      session_send_system_line(ctx, "Already viewing the end of this post.");
    }
    return true;
  }

  size_t max_offset = total - window;
  size_t offset = ctx->bbs_view_scroll_offset;
  size_t effective_step = step;
  if (effective_step == 0U) {
    effective_step = window;
  }
  if (effective_step == 0U) {
    effective_step = 1U;
  }

  size_t new_offset = offset;
  if (direction > 0) {
    if (offset == 0U) {
      session_send_system_line(ctx, "Already viewing the top of this post.");
      return true;
    }
    if (effective_step > offset) {
      effective_step = offset;
    }
    if (effective_step == 0U) {
      effective_step = 1U;
    }
    new_offset = offset - effective_step;
  } else if (direction < 0) {
    if (offset >= max_offset) {
      session_send_system_line(ctx, "Already viewing the end of this post.");
      return true;
    }
    size_t advance = effective_step;
    if (advance > max_offset - offset) {
      advance = max_offset - offset;
    }
    if (advance == 0U) {
      advance = 1U;
    }
    new_offset = offset + advance;
  }

  if (new_offset == offset) {
    if (direction > 0) {
      session_send_system_line(ctx, "Already viewing the top of this post.");
    } else if (direction < 0) {
      session_send_system_line(ctx, "Already viewing the end of this post.");
    }
    return true;
  }

  ctx->bbs_view_scroll_offset = new_offset;
  return session_bbs_refresh_view(ctx);
}

// Show the BBS dashboard and mark the session as being in BBS mode.
static void session_bbs_show_dashboard(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  ctx->in_bbs_mode = true;
  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;
  session_bbs_prepare_canvas(ctx);
  session_render_separator(ctx, "BBS Dashboard");
  session_send_system_line(ctx,
                           "Commands: list, read <id>, post <title> [tags...], comment <id>|<text>, regen <id>, delete <id>, exit");
  session_bbs_list(ctx);
}

// List posts sorted by most recent activity.
static void session_bbs_list(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  bool previous_override = session_translation_push_scope_override(ctx);
  typedef struct bbs_listing {
    uint64_t id;
    char title[SSH_CHATTER_BBS_TITLE_LEN];
    char author[SSH_CHATTER_USERNAME_LEN];
    char tags[SSH_CHATTER_BBS_MAX_TAGS][SSH_CHATTER_BBS_TAG_LEN];
    size_t tag_count;
    time_t created_at;
    time_t bumped_at;
  } bbs_listing_t;

  bbs_listing_t listings[SSH_CHATTER_BBS_MAX_POSTS];
  size_t count = 0U;

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    const bbs_post_t *post = &host->bbs_posts[idx];
    if (!post->in_use) {
      continue;
    }
    listings[count].id = post->id;
    snprintf(listings[count].title, sizeof(listings[count].title), "%s", post->title);
    snprintf(listings[count].author, sizeof(listings[count].author), "%s", post->author);
    listings[count].tag_count = post->tag_count;
    for (size_t tag = 0U; tag < post->tag_count && tag < SSH_CHATTER_BBS_MAX_TAGS; ++tag) {
      snprintf(listings[count].tags[tag], sizeof(listings[count].tags[tag]), "%s", post->tags[tag]);
    }
    listings[count].created_at = post->created_at;
    listings[count].bumped_at = post->bumped_at;
    ++count;
    if (count >= SSH_CHATTER_BBS_MAX_POSTS) {
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (count == 0U) {
    session_send_system_line(ctx,
                             "The bulletin board is empty. Use /bbs post <title> [tags...] to write something. Finish drafts "
                             "with " SSH_CHATTER_BBS_TERMINATOR ".");
    session_translation_pop_scope_override(ctx, previous_override);
    return;
  }

  for (size_t outer = 1U; outer < count; ++outer) {
    bbs_listing_t key = listings[outer];
    size_t position = outer;
    while (position > 0U && listings[position - 1U].bumped_at < key.bumped_at) {
      listings[position] = listings[position - 1U];
      --position;
    }
    listings[position] = key;
  }

  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;

  typedef struct bbs_topic_group {
    char name[SSH_CHATTER_BBS_TAG_LEN];
    size_t indexes[SSH_CHATTER_BBS_MAX_POSTS];
    size_t count;
  } bbs_topic_group_t;

  bbs_topic_group_t topics[SSH_CHATTER_BBS_MAX_POSTS];
  size_t topic_count = 0U;
  memset(topics, 0, sizeof(topics));

  for (size_t idx = 0U; idx < count; ++idx) {
    const char *topic_name = (listings[idx].tag_count > 0U) ? listings[idx].tags[0] : SSH_CHATTER_BBS_DEFAULT_TAG;
    size_t match = topic_count;
    for (size_t topic_idx = 0U; topic_idx < topic_count; ++topic_idx) {
      if (strcasecmp(topics[topic_idx].name, topic_name) == 0) {
        match = topic_idx;
        break;
      }
    }
    if (match == topic_count) {
      if (topic_count >= SSH_CHATTER_BBS_MAX_POSTS) {
        continue;
      }
      snprintf(topics[match].name, sizeof(topics[match].name), "%s", topic_name);
      topics[match].count = 0U;
      ++topic_count;
    }
    if (topics[match].count < SSH_CHATTER_BBS_MAX_POSTS) {
      topics[match].indexes[topics[match].count++] = idx;
    }
  }

  for (size_t outer = 1U; outer < topic_count; ++outer) {
    bbs_topic_group_t key = topics[outer];
    size_t position = outer;
    while (position > 0U && strcasecmp(topics[position - 1U].name, key.name) > 0) {
      topics[position] = topics[position - 1U];
      --position;
    }
    topics[position] = key;
  }

  session_render_separator(ctx, "BBS Posts by Topic");
  for (size_t topic_idx = 0U; topic_idx < topic_count; ++topic_idx) {
    char section_label[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(section_label, sizeof(section_label), "Topic: %s", topics[topic_idx].name);
    session_render_separator(ctx, section_label);

    for (size_t entry_idx = 0U; entry_idx < topics[topic_idx].count; ++entry_idx) {
      size_t listing_index = topics[topic_idx].indexes[entry_idx];
      const bbs_listing_t *entry = &listings[listing_index];
      char created_buffer[32];
      bbs_format_time(entry->bumped_at, created_buffer, sizeof(created_buffer));
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      int title_preview = (int)strnlen(entry->title, sizeof(entry->title));
      if (title_preview > 80) {
        title_preview = 80;
      }
      if (entry->tag_count == 0U) {
        snprintf(line, sizeof(line), "#%" PRIu64 " [%s] %.*s|(no tags)", entry->id, created_buffer, title_preview,
                 entry->title);
      } else {
        char tag_buffer[SSH_CHATTER_MESSAGE_LIMIT];
        size_t buffer_offset = 0U;
        tag_buffer[0] = '\0';
        for (size_t tag = 0U; tag < entry->tag_count; ++tag) {
          size_t len = strlen(entry->tags[tag]);
          if (buffer_offset + len + 2U >= sizeof(tag_buffer)) {
            break;
          }
          if (tag > 0U) {
            tag_buffer[buffer_offset++] = ',';
          }
          memcpy(tag_buffer + buffer_offset, entry->tags[tag], len);
          buffer_offset += len;
          tag_buffer[buffer_offset] = '\0';
        }
        int tags_preview = (int)strnlen(tag_buffer, sizeof(tag_buffer));
        if (tags_preview > 80) {
          tags_preview = 80;
        }
        snprintf(line, sizeof(line), "#%" PRIu64 " [%s] %.*s|%.*s", entry->id, created_buffer, title_preview,
                 entry->title, tags_preview, tag_buffer);
      }
      session_send_system_line(ctx, line);
    }
  }

  session_render_separator(ctx, "End");
  session_translation_pop_scope_override(ctx, previous_override);
}

// Display a single post to the user.
static void session_bbs_read(session_ctx_t *ctx, uint64_t id) {
  if (ctx == NULL || ctx->owner == NULL || id == 0U) {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_find_bbs_post_locked(host, id);
  bbs_post_t snapshot = {0};
  if (post != NULL) {
    snapshot = *post;
  }
  pthread_mutex_unlock(&host->lock);

  if (post == NULL || !snapshot.in_use) {
    session_send_system_line(ctx, "No post exists with that identifier.");
    return;
  }

  session_bbs_render_post(ctx, &snapshot, NULL, true, false);
}

// Create a new post using the provided argument format.
static bool session_bbs_is_admin_only_tag(const char *tag) {
  if (tag == NULL || tag[0] == '\0') {
    return false;
  }

  if (strcasecmp(tag, "manual") == 0 || strcasecmp(tag, "notice") == 0) {
    return true;
  }

  if (strcmp(tag, "설명서") == 0 || strcmp(tag, "공지") == 0) {
    return true;
  }

  return false;
}

static void session_bbs_reset_pending_post(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->bbs_post_pending = false;
  ctx->pending_bbs_title[0] = '\0';
  ctx->pending_bbs_body[0] = '\0';
  ctx->pending_bbs_body_length = 0U;
  ctx->pending_bbs_tag_count = 0U;
  ctx->pending_bbs_line_count = 0U;
  ctx->pending_bbs_cursor_line = 0U;
  ctx->pending_bbs_editing_line = false;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_TAGS; ++idx) {
    ctx->pending_bbs_tags[idx][0] = '\0';
  }
  ctx->bbs_breaking_count = 0U;
  memset(ctx->bbs_breaking_messages, 0, sizeof(ctx->bbs_breaking_messages));
  ctx->bbs_rendering_editor = false;
}

static void session_bbs_commit_pending_post(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->bbs_post_pending) {
    return;
  }

  if (ctx->pending_bbs_body_length == 0U) {
    session_send_system_line(ctx, "Post body was empty. Draft discarded.");
    session_bbs_reset_pending_post(ctx);
    return;
  }

  if (!session_security_check_text(ctx, "BBS post", ctx->pending_bbs_body, ctx->pending_bbs_body_length)) {
    session_bbs_reset_pending_post(ctx);
    return;
  }

  host_t *host = ctx->owner;
  if (host == NULL) {
    session_bbs_reset_pending_post(ctx);
    return;
  }

  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_allocate_bbs_post_locked(host);
  if (post == NULL) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "The bulletin board is full right now.");
    return;
  }

  snprintf(post->author, sizeof(post->author), "%s", ctx->user.name);
  snprintf(post->title, sizeof(post->title), "%s", ctx->pending_bbs_title);
  memcpy(post->body, ctx->pending_bbs_body, ctx->pending_bbs_body_length);
  post->body[ctx->pending_bbs_body_length] = '\0';
  host_strip_column_reset(post->author);
  host_strip_column_reset(post->title);
  host_strip_column_reset(post->body);
  post->tag_count = ctx->pending_bbs_tag_count;
  for (size_t idx = 0U; idx < post->tag_count; ++idx) {
    snprintf(post->tags[idx], sizeof(post->tags[idx]), "%s", ctx->pending_bbs_tags[idx]);
    host_strip_column_reset(post->tags[idx]);
  }

  bbs_post_t snapshot = *post;
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_bbs_reset_pending_post(ctx);

  session_bbs_render_post(ctx, &snapshot, "Post created.", true, false);
}

static void session_bbs_begin_post(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->bbs_post_pending) {
    session_send_system_line(ctx, "You are already composing a post. Finish it with " SSH_CHATTER_BBS_TERMINATOR ".");
    return;
  }

  ctx->bbs_breaking_count = 0U;
  memset(ctx->bbs_breaking_messages, 0, sizeof(ctx->bbs_breaking_messages));
  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "The bulletin board is unavailable right now.");
    return;
  }

  session_bbs_reset_pending_post(ctx);

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /bbs post <title>[|tags...]");
    session_send_system_line(ctx, "Use | to separate tags when the title has spaces.");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /bbs post <title>[|tags...]");
    session_send_system_line(ctx, "Use | to separate tags when the title has spaces.");
    return;
  }

  char title[SSH_CHATTER_BBS_TITLE_LEN];
  title[0] = '\0';
  char *tag_cursor = NULL;
  char *separator = strchr(working, '|');
  if (separator != NULL) {
    *separator = '\0';
    char *title_part = working;
    char *tags_part = separator + 1;
    trim_whitespace_inplace(title_part);
    trim_whitespace_inplace(tags_part);
    size_t title_len = strnlen(title_part, sizeof(title));
    if (title_len > 1U && (title_part[0] == '\"' || title_part[0] == '\'') && title_part[title_len - 1U] == title_part[0]) {
      title_part[title_len - 1U] = '\0';
      ++title_part;
      trim_whitespace_inplace(title_part);
    }
    size_t copy_len = strnlen(title_part, sizeof(title) - 1U);
    memcpy(title, title_part, copy_len);
    title[copy_len] = '\0';
    tag_cursor = tags_part;
  } else {
    char *cursor = working;
    if (*cursor == '\"' || *cursor == '\'') {
      char quote = *cursor++;
      char *closing = strchr(cursor, quote);
      if (closing == NULL) {
        session_send_system_line(ctx, "Missing closing quote for the title.");
        return;
      }
      size_t copy_len = (size_t)(closing - cursor);
      if (copy_len >= sizeof(title)) {
        copy_len = sizeof(title) - 1U;
      }
      memcpy(title, cursor, copy_len);
      title[copy_len] = '\0';
      cursor = closing + 1;
    } else {
      char *space = cursor;
      while (*space != '\0' && !isspace((unsigned char)*space)) {
        ++space;
      }
      size_t copy_len = (size_t)(space - cursor);
      if (copy_len >= sizeof(title)) {
        copy_len = sizeof(title) - 1U;
      }
      memcpy(title, cursor, copy_len);
      title[copy_len] = '\0';
      cursor = space;
    }

    trim_whitespace_inplace(cursor);
    tag_cursor = cursor;
  }

  if (title[0] == '\0') {
    session_send_system_line(ctx, "A title is required to create a post.");
    return;
  }

  size_t tag_count = 0U;
  bool discarded_tags = false;
  bool default_tag_applied = false;
  while (tag_cursor != NULL && *tag_cursor != '\0') {
    while (isspace((unsigned char)*tag_cursor)) {
      ++tag_cursor;
    }
    if (*tag_cursor == '\0') {
      break;
    }
    char *end = tag_cursor;
    while (*end != '\0' && !isspace((unsigned char)*end)) {
      ++end;
    }
    size_t length = (size_t)(end - tag_cursor);
    if (length > 0U) {
      if (tag_count < SSH_CHATTER_BBS_MAX_TAGS) {
        if (length >= SSH_CHATTER_BBS_TAG_LEN) {
          length = SSH_CHATTER_BBS_TAG_LEN - 1U;
        }
        char tag_value[SSH_CHATTER_BBS_TAG_LEN];
        memcpy(tag_value, tag_cursor, length);
        tag_value[length] = '\0';
        if (!ctx->user.is_operator && session_bbs_is_admin_only_tag(tag_value)) {
          char warning[SSH_CHATTER_MESSAGE_LIMIT];
          snprintf(warning, sizeof(warning), "The '%s' tag is reserved for administrators.", tag_value);
          session_send_system_line(ctx, warning);
          return;
        }
        snprintf(ctx->pending_bbs_tags[tag_count], sizeof(ctx->pending_bbs_tags[tag_count]), "%s", tag_value);
        ++tag_count;
      } else {
        discarded_tags = true;
      }
    }
    tag_cursor = end;
  }

  if (tag_count == 0U) {
    snprintf(ctx->pending_bbs_tags[0], sizeof(ctx->pending_bbs_tags[0]), "%s", SSH_CHATTER_BBS_DEFAULT_TAG);
    tag_count = 1U;
    default_tag_applied = true;
  }

  snprintf(ctx->pending_bbs_title, sizeof(ctx->pending_bbs_title), "%s", title);
  ctx->pending_bbs_tag_count = tag_count;
  ctx->pending_bbs_body[0] = '\0';
  ctx->pending_bbs_body_length = 0U;
  ctx->bbs_post_pending = true;

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  notice[0] = '\0';
  if (default_tag_applied) {
    snprintf(notice, sizeof(notice), "No tags provided; default tag '%s' applied.", SSH_CHATTER_BBS_DEFAULT_TAG);
  }
  if (discarded_tags) {
    if (notice[0] != '\0') {
      strncat(notice, "\n", sizeof(notice) - strlen(notice) - 1U);
    }
    strncat(notice, "Only the first four tags were kept. Extra tags were ignored.",
            sizeof(notice) - strlen(notice) - 1U);
  }

  session_bbs_render_editor(ctx, notice[0] != '\0' ? notice : NULL);
}

static void session_bbs_capture_body_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || !ctx->bbs_post_pending || text == NULL) {
    return;
  }

  session_capture_multiline_text(ctx, text, session_bbs_capture_body_line, session_bbs_capture_continue);
}

static void session_bbs_capture_body_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || !ctx->bbs_post_pending) {
    return;
  }

  char trimmed[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(trimmed, sizeof(trimmed), "%s", line != NULL ? line : "");
  trim_whitespace_inplace(trimmed);
  if (strcmp(trimmed, SSH_CHATTER_BBS_TERMINATOR) == 0) {
    session_bbs_commit_pending_post(ctx);
    return;
  }

  if (line == NULL) {
    line = "";
  }

  char status[SSH_CHATTER_MESSAGE_LIMIT];
  status[0] = '\0';

  session_bbs_recalculate_line_count(ctx);
  bool editing_line = ctx->pending_bbs_editing_line && ctx->pending_bbs_cursor_line < ctx->pending_bbs_line_count;

  bool updated = false;
  if (editing_line) {
    updated = session_bbs_replace_line(ctx, ctx->pending_bbs_cursor_line, line, status, sizeof(status));
  } else {
    updated = session_bbs_append_line(ctx, line, status, sizeof(status));
  }

  if (!updated && status[0] == '\0') {
    snprintf(status, sizeof(status), "Unable to update the draft right now.");
  }

  session_bbs_render_editor(ctx, status[0] != '\0' ? status : NULL);
}

// Append a comment to a post.
static void session_bbs_add_comment(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL || arguments == NULL) {
    session_send_system_line(ctx, "Usage: /bbs comment <id>|<text>");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /bbs comment <id>|<text>");
    return;
  }

  char *separator = strchr(working, '|');
  if (separator == NULL) {
    session_send_system_line(ctx, "Usage: /bbs comment <id>|<text>");
    return;
  }
  *separator = '\0';
  char *id_text = working;
  char *comment_text = separator + 1;
  trim_whitespace_inplace(id_text);
  trim_whitespace_inplace(comment_text);

  if (id_text[0] == '\0' || comment_text[0] == '\0') {
    session_send_system_line(ctx, "Usage: /bbs comment <id>|<text>");
    return;
  }

  uint64_t id = (uint64_t)strtoull(id_text, NULL, 10);
  if (id == 0U) {
    session_send_system_line(ctx, "Invalid post identifier.");
    return;
  }

  size_t comment_scan_length = strnlen(comment_text, SSH_CHATTER_BBS_COMMENT_LEN);
  if (!session_security_check_text(ctx, "BBS comment", comment_text, comment_scan_length)) {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_find_bbs_post_locked(host, id);
  if (post == NULL || !post->in_use) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "No post exists with that identifier.");
    return;
  }
  if (post->comment_count >= SSH_CHATTER_BBS_MAX_COMMENTS) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "This post has reached the comment limit.");
    return;
  }

  bbs_comment_t *comment = &post->comments[post->comment_count++];
  snprintf(comment->author, sizeof(comment->author), "%s", ctx->user.name);
  size_t comment_len = strnlen(comment_text, SSH_CHATTER_BBS_COMMENT_LEN - 1U);
  memcpy(comment->text, comment_text, comment_len);
  comment->text[comment_len] = '\0';
  host_strip_column_reset(comment->author);
  host_strip_column_reset(comment->text);
  comment->created_at = time(NULL);
  post->bumped_at = comment->created_at;
  bbs_post_t snapshot = *post;
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_bbs_render_post(ctx, &snapshot, "Comment added.", false, true);
}

static void session_bbs_delete(session_ctx_t *ctx, uint64_t id) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (id == 0U) {
    session_send_system_line(ctx, "Invalid post identifier.");
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_find_bbs_post_locked(host, id);
  if (post == NULL || !post->in_use) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "No post exists with that identifier.");
    return;
  }

  bool can_delete = (strncmp(post->author, ctx->user.name, SSH_CHATTER_USERNAME_LEN) == 0) || ctx->user.is_operator ||
                    ctx->user.is_lan_operator;
  if (!can_delete) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "Only the author or an operator may delete this post.");
    return;
  }

  host_clear_bbs_post_locked(host, post);
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_send_system_line(ctx, "Post deleted.");
}

// Bump a post to the top of the list by refreshing its activity time.
static void session_bbs_regen_post(session_ctx_t *ctx, uint64_t id) {
  if (ctx == NULL || ctx->owner == NULL || id == 0U) {
    return;
  }

  host_t *host = ctx->owner;
  pthread_mutex_lock(&host->lock);
  bbs_post_t *post = host_find_bbs_post_locked(host, id);
  if (post == NULL || !post->in_use) {
    pthread_mutex_unlock(&host->lock);
    session_send_system_line(ctx, "No post exists with that identifier.");
    return;
  }

  post->bumped_at = time(NULL);
  bbs_post_t snapshot = *post;
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_bbs_render_post(ctx, &snapshot, "Post bumped to the top.", false, false);
}

static void session_rss_clear(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  memset(&ctx->rss_view, 0, sizeof(ctx->rss_view));
  ctx->in_rss_mode = false;
}

static void session_rss_exit(session_ctx_t *ctx, const char *reason) {
  if (ctx == NULL) {
    return;
  }

  const bool was_active = ctx->in_rss_mode;
  session_rss_clear(ctx);

  if (reason != NULL && reason[0] != '\0') {
    session_send_system_line(ctx, reason);
  } else if (was_active) {
    session_send_system_line(ctx, "RSS reader closed.");
  }

  if (was_active) {
    session_render_prompt(ctx, false);
  }
}

static void session_rss_show_current(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->rss_view.active || ctx->rss_view.item_count == 0U) {
    return;
  }

  if (ctx->rss_view.cursor >= ctx->rss_view.item_count) {
    ctx->rss_view.cursor = ctx->rss_view.item_count - 1U;
  }

  const rss_session_item_t *item = &ctx->rss_view.items[ctx->rss_view.cursor];

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Feed %s (%zu/%zu)", ctx->rss_view.tag, ctx->rss_view.cursor + 1U,
           ctx->rss_view.item_count);
  session_render_separator(ctx, header);

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  if (item->title[0] != '\0') {
    snprintf(line, sizeof(line), "Title : %s", item->title);
  } else {
    snprintf(line, sizeof(line), "Title : (untitled)");
  }
  session_send_system_line(ctx, line);

  if (item->link[0] != '\0') {
    snprintf(line, sizeof(line), "Link  : %s", item->link);
  } else {
    snprintf(line, sizeof(line), "Link  : (none)");
  }
  session_send_system_line(ctx, line);

  if (item->summary[0] != '\0') {
    session_send_system_line(ctx, "Summary:");
    char working[SSH_CHATTER_RSS_SUMMARY_LEN];
    snprintf(working, sizeof(working), "%s", item->summary);
    char *saveptr = NULL;
    char *fragment = strtok_r(working, "\r\n", &saveptr);
    while (fragment != NULL) {
      rss_trim_whitespace(fragment);
      if (fragment[0] != '\0') {
        snprintf(line, sizeof(line), "  %s", fragment);
        session_send_system_line(ctx, line);
      }
      fragment = strtok_r(NULL, "\r\n", &saveptr);
    }
  } else {
    session_send_system_line(ctx, "Summary: (none)");
  }
}

static void session_rss_begin(session_ctx_t *ctx, const char *tag, const rss_session_item_t *items, size_t count) {
  if (ctx == NULL || tag == NULL || tag[0] == '\0' || items == NULL || count == 0U) {
    return;
  }

  session_rss_clear(ctx);

  if (count > SSH_CHATTER_RSS_MAX_ITEMS) {
    count = SSH_CHATTER_RSS_MAX_ITEMS;
  }

  ctx->rss_view.active = true;
  ctx->rss_view.item_count = count;
  ctx->rss_view.cursor = 0U;
  snprintf(ctx->rss_view.tag, sizeof(ctx->rss_view.tag), "%s", tag);
  for (size_t idx = 0U; idx < count; ++idx) {
    ctx->rss_view.items[idx] = items[idx];
  }
  ctx->in_rss_mode = true;

  char intro[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(intro, sizeof(intro),
           "Browsing feed '%s'. Use Up/Down arrows to navigate. Type /exit or press Ctrl+Z to return.",
           ctx->rss_view.tag);
  session_render_separator(ctx, "RSS Reader");
  session_send_system_line(ctx, intro);
  session_rss_show_current(ctx);
}

static bool session_rss_move(session_ctx_t *ctx, int delta) {
  if (ctx == NULL || !ctx->rss_view.active || ctx->rss_view.item_count == 0U || delta == 0) {
    return false;
  }

  size_t current = ctx->rss_view.cursor;
  size_t next = current;

  if (delta > 0) {
    if (next + 1U < ctx->rss_view.item_count) {
      next += 1U;
    }
  } else {
    if (next > 0U) {
      next -= 1U;
    }
  }

  if (next == current) {
    return false;
  }

  ctx->rss_view.cursor = next;
  session_rss_show_current(ctx);
  return true;
}

static void session_rss_list(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  rss_feed_t snapshot[SSH_CHATTER_RSS_MAX_FEEDS];
  size_t count = 0U;

  pthread_mutex_lock(&ctx->owner->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    if (!ctx->owner->rss_feeds[idx].in_use) {
      continue;
    }
    snapshot[count++] = ctx->owner->rss_feeds[idx];
    if (count >= SSH_CHATTER_RSS_MAX_FEEDS) {
      break;
    }
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  session_render_separator(ctx, "RSS Feeds");
  if (count == 0U) {
    session_send_system_line(ctx,
                             "No RSS feeds registered. Operators can add one with /rss add <url> <tag>.");
    return;
  }

  for (size_t idx = 0U; idx < count; ++idx) {
    const rss_feed_t *entry = &snapshot[idx];
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (entry->last_title[0] != '\0') {
      char preview[72];
      snprintf(preview, sizeof(preview), "%.64s", entry->last_title);
      snprintf(line, sizeof(line), "[%s] %s (last: %s)", entry->tag, entry->url, preview);
    } else {
      snprintf(line, sizeof(line), "[%s] %s", entry->tag, entry->url);
    }
    session_send_system_line(ctx, line);
  }
}

static void session_rss_read(session_ctx_t *ctx, const char *tag) {
  if (ctx == NULL || ctx->owner == NULL || tag == NULL || tag[0] == '\0') {
    session_send_system_line(ctx, "Usage: /rss read <tag>");
    return;
  }

  char working[SSH_CHATTER_RSS_TAG_LEN];
  snprintf(working, sizeof(working), "%s", tag);
  rss_trim_whitespace(working);
  if (!rss_tag_is_valid(working)) {
    session_send_system_line(ctx, "Tags may only contain letters, numbers, '-', '_' or '.'.");
    return;
  }

  rss_feed_t feed_snapshot = {0};
  pthread_mutex_lock(&ctx->owner->lock);
  rss_feed_t *entry = host_find_rss_feed_locked(ctx->owner, working);
  if (entry != NULL) {
    feed_snapshot = *entry;
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  if (feed_snapshot.tag[0] == '\0') {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No RSS feed found for tag '%s'.", working);
    session_send_system_line(ctx, message);
    return;
  }

  rss_session_item_t items[SSH_CHATTER_RSS_MAX_ITEMS];
  size_t item_count = 0U;
  if (!host_rss_fetch_items(&feed_snapshot, items, SSH_CHATTER_RSS_MAX_ITEMS, &item_count)) {
    session_send_system_line(ctx, "Failed to fetch RSS feed. Try again later.");
    return;
  }

  if (item_count == 0U) {
    session_send_system_line(ctx, "The feed does not contain any recent entries.");
    return;
  }

  time_t now = time(NULL);
  pthread_mutex_lock(&ctx->owner->lock);
  entry = host_find_rss_feed_locked(ctx->owner, working);
  if (entry != NULL) {
    entry->last_checked = now;
    snprintf(entry->last_title, sizeof(entry->last_title), "%s", items[0].title);
    snprintf(entry->last_link, sizeof(entry->last_link), "%s", items[0].link);
    host_rss_state_save_locked(ctx->owner);
  }
  pthread_mutex_unlock(&ctx->owner->lock);

  session_rss_begin(ctx, feed_snapshot.tag, items, item_count);
}

static void session_handle_rss(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /rss <add <url> <tag>|del <tag>|read <tag>|list>";

  char working[SSH_CHATTER_MAX_INPUT_LEN];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  rss_trim_whitespace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *saveptr = NULL;
  char *command = strtok_r(working, " \t", &saveptr);
  if (command == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (strcasecmp(command, "list") == 0) {
    session_rss_list(ctx);
    return;
  }

  if (strcasecmp(command, "add") == 0) {
    if (!ctx->user.is_operator) {
      session_send_system_line(ctx, "Only operators may add RSS feeds.");
      return;
    }

    char *url = strtok_r(NULL, " \t", &saveptr);
    char *tag = strtok_r(NULL, " \t", &saveptr);
    if (url == NULL || tag == NULL) {
      session_send_system_line(ctx, "Usage: /rss add <url> <tag>");
      return;
    }

    rss_trim_whitespace(url);
    rss_trim_whitespace(tag);
    if (url[0] == '\0' || tag[0] == '\0') {
      session_send_system_line(ctx, "Usage: /rss add <url> <tag>");
      return;
    }

    char error[128];
    if (host_rss_add_feed(ctx->owner, url, tag, error, sizeof(error))) {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "RSS feed '%s' registered as '%s'.", url, tag);
      session_send_system_line(ctx, message);
      host_rss_start_backend(ctx->owner);
    } else {
      if (error[0] == '\0') {
        snprintf(error, sizeof(error), "Failed to add RSS feed.");
      }
      session_send_system_line(ctx, error);
    }
    return;
  }

  if (strcasecmp(command, "del") == 0) {
    if (!ctx->user.is_operator) {
      session_send_system_line(ctx, "Only operators may delete RSS feeds.");
      return;
    }

    char *tag = strtok_r(NULL, " \t", &saveptr);
    if (tag == NULL) {
      session_send_system_line(ctx, "Usage: /rss del <tag>");
      return;
    }

    rss_trim_whitespace(tag);
    if (tag[0] == '\0') {
      session_send_system_line(ctx, "Usage: /rss del <tag>");
      return;
    }

    char error[128];
    if (host_rss_remove_feed(ctx->owner, tag, error, sizeof(error))) {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "RSS feed '%s' deleted.", tag);
      session_send_system_line(ctx, message);
    } else {
      if (error[0] == '\0') {
        snprintf(error, sizeof(error), "Failed to delete RSS feed.");
      }
      session_send_system_line(ctx, error);
    }
    return;
  }

  if (strcasecmp(command, "read") == 0) {
    char *tag = strtok_r(NULL, " \t", &saveptr);
    if (tag == NULL) {
      session_send_system_line(ctx, "Usage: /rss read <tag>");
      return;
    }
    session_rss_read(ctx, tag);
    return;
  }

  session_send_system_line(ctx, kUsage);
}

static bool host_asciiart_cooldown_active(host_t *host, const char *ip, const struct timespec *now,
                                          long *remaining_seconds) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    if (remaining_seconds != NULL) {
      *remaining_seconds = 0L;
    }
    return false;
  }

  struct timespec current = {0, 0};
  if (now != NULL) {
    current = *now;
  } else if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
    current.tv_sec = time(NULL);
    current.tv_nsec = 0L;
  }

  bool active = false;
  long remaining = 0L;

  pthread_mutex_lock(&host->lock);
  join_activity_entry_t *entry = host_find_join_activity_locked(host, ip);
  if (entry != NULL && entry->asciiart_has_cooldown) {
    struct timespec expiry = entry->last_asciiart_post;
    expiry.tv_sec += SSH_CHATTER_ASCIIART_COOLDOWN_SECONDS;
    if (timespec_compare(&current, &expiry) >= 0) {
      entry->asciiart_has_cooldown = false;
    } else {
      active = true;
      struct timespec diff = timespec_diff(&expiry, &current);
      remaining = diff.tv_sec;
      if (diff.tv_nsec > 0L) {
        ++remaining;
      }
      if (remaining < 0L) {
        remaining = 0L;
      }
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (remaining_seconds != NULL) {
    *remaining_seconds = active ? remaining : 0L;
  }

  return active;
}

static void host_asciiart_register_post(host_t *host, const char *ip, const struct timespec *when) {
  if (host == NULL || ip == NULL || ip[0] == '\0' || when == NULL) {
    return;
  }

  pthread_mutex_lock(&host->lock);
  join_activity_entry_t *entry = host_ensure_join_activity_locked(host, ip);
  if (entry != NULL) {
    entry->last_asciiart_post = *when;
    entry->asciiart_has_cooldown = true;
  }
  pthread_mutex_unlock(&host->lock);
}

static void session_asciiart_reset(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->asciiart_pending = false;
  ctx->asciiart_target = SESSION_ASCIIART_TARGET_NONE;
  ctx->asciiart_buffer[0] = '\0';
  ctx->asciiart_length = 0U;
  ctx->asciiart_line_count = 0U;
}

static bool session_asciiart_cooldown_active(session_ctx_t *ctx, struct timespec *now, long *remaining_seconds) {
  if (ctx == NULL) {
    return false;
  }

  struct timespec current;
  if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
    current.tv_sec = time(NULL);
    current.tv_nsec = 0L;
  }

  if (now != NULL) {
    *now = current;
  }

  long session_remaining = 0L;
  bool session_active = false;
  if (ctx->asciiart_has_cooldown) {
    struct timespec expiry = ctx->last_asciiart_post;
    expiry.tv_sec += SSH_CHATTER_ASCIIART_COOLDOWN_SECONDS;
    if (timespec_compare(&current, &expiry) >= 0) {
      ctx->asciiart_has_cooldown = false;
    } else {
      session_active = true;
      struct timespec diff = timespec_diff(&expiry, &current);
      session_remaining = diff.tv_sec;
      if (diff.tv_nsec > 0L) {
        ++session_remaining;
      }
      if (session_remaining < 0L) {
        session_remaining = 0L;
      }
    }
  }

  long ip_remaining = 0L;
  bool ip_active = host_asciiart_cooldown_active(ctx->owner, ctx->client_ip, &current, &ip_remaining);

  if (!session_active && !ip_active) {
    if (remaining_seconds != NULL) {
      *remaining_seconds = 0L;
    }
    return false;
  }

  long max_remaining = session_active ? session_remaining : 0L;
  if (ip_active && ip_remaining > max_remaining) {
    max_remaining = ip_remaining;
  }

  if (remaining_seconds != NULL) {
    *remaining_seconds = max_remaining;
  }

  return true;
}

static void session_asciiart_begin(session_ctx_t *ctx, session_asciiart_target_t target) {
  if (ctx == NULL || target == SESSION_ASCIIART_TARGET_NONE) {
    return;
  }

  if (ctx->asciiart_pending) {
    session_send_system_line(ctx, "You are already composing ASCII art. Finish it with " SSH_CHATTER_ASCIIART_TERMINATOR ".");
    return;
  }

  if (ctx->bbs_post_pending) {
    session_send_system_line(ctx, "Finish your BBS draft before starting ASCII art.");
    return;
  }

  if (target == SESSION_ASCIIART_TARGET_CHAT) {
    struct timespec now;
    long remaining = 0L;
    if (session_asciiart_cooldown_active(ctx, &now, &remaining)) {
      if (remaining < 1L) {
        remaining = 1L;
      }
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "You can share another ASCII art in %ld second%s.", remaining,
               remaining == 1L ? "" : "s");
      session_send_system_line(ctx, message);
      return;
    }
  } else if (target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE) {
    if (!session_user_data_available(ctx) || !session_user_data_load(ctx)) {
      session_send_system_line(ctx, "Profile storage is unavailable.");
      return;
    }
  }

  session_asciiart_reset(ctx);
  ctx->asciiart_pending = true;
  ctx->asciiart_target = target;

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  size_t ascii_bytes = (size_t)SSH_CHATTER_ASCIIART_BUFFER_LEN;
  if (target == SESSION_ASCIIART_TARGET_CHAT) {
    snprintf(header, sizeof(header),
             "ASCII art composer ready (max %u lines, up to %zu bytes, 10-minute cooldown per IP).",
             SSH_CHATTER_ASCIIART_MAX_LINES, ascii_bytes);
    session_send_system_line(ctx, header);
    session_send_system_line(ctx,
                             "Type " SSH_CHATTER_ASCIIART_TERMINATOR " on a line by itself or press Ctrl+S to finish.");
    session_send_system_line(ctx, "Press Ctrl+A to cancel the draft.");
  } else {
    snprintf(header, sizeof(header),
             "Profile picture composer ready (max %u lines, up to %zu bytes, stored privately).",
             SSH_CHATTER_ASCIIART_MAX_LINES, ascii_bytes);
    session_send_system_line(ctx, header);
    session_send_system_line(ctx,
                             "Type " SSH_CHATTER_ASCIIART_TERMINATOR " on a line by itself or press Ctrl+S to save.");
    session_send_system_line(ctx, "Press Ctrl+A to cancel the draft.");
  }
}

static void session_asciiart_commit(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->asciiart_pending) {
    return;
  }

  const session_asciiart_target_t target = ctx->asciiart_target;

  if (ctx->asciiart_length == 0U) {
    const char *discard_message =
        (target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE) ? "Profile picture draft discarded."
                                                            : "ASCII art draft discarded.";
    session_asciiart_cancel(ctx, discard_message);
    return;
  }

  if (ctx->owner == NULL) {
    session_asciiart_reset(ctx);
    return;
  }

  const char *security_label =
      target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE ? "Profile picture" : "ASCII art";
  if (!session_security_check_text(ctx, security_label, ctx->asciiart_buffer, ctx->asciiart_length)) {
    session_asciiart_reset(ctx);
    return;
  }

  if (target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE) {
    if (!session_user_data_available(ctx) || !session_user_data_load(ctx)) {
      session_send_system_line(ctx, "Profile storage is unavailable.");
      session_asciiart_reset(ctx);
      return;
    }

    if ((size_t)ctx->asciiart_length >= USER_DATA_PROFILE_PICTURE_LEN) {
      session_send_system_line(ctx, "Profile picture exceeds the storage limit.");
      session_asciiart_reset(ctx);
      return;
    }

    char normalized[USER_DATA_PROFILE_PICTURE_LEN];
    session_profile_picture_normalize(ctx->asciiart_buffer, normalized, sizeof(normalized));
    if (normalized[0] == '\0') {
      session_send_system_line(ctx, "Profile picture cannot be empty.");
      session_asciiart_reset(ctx);
      return;
    }

    snprintf(ctx->user_data.profile_picture, sizeof(ctx->user_data.profile_picture), "%s", normalized);
    if (session_user_data_commit(ctx)) {
      session_send_system_line(ctx, "Profile picture updated.");
    } else {
      session_send_system_line(ctx, "Failed to save profile picture.");
    }

    session_asciiart_reset(ctx);
    return;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  ctx->last_asciiart_post = now;
  ctx->asciiart_has_cooldown = true;
  host_asciiart_register_post(ctx->owner, ctx->client_ip, &now);

  chat_history_entry_t entry = {0};
  if (!host_history_record_user(ctx->owner, ctx, ctx->asciiart_buffer, &entry)) {
    session_asciiart_reset(ctx);
    return;
  }

  session_send_history_entry(ctx, &entry);
  chat_room_broadcast_entry(&ctx->owner->room, &entry, ctx);
  host_notify_external_clients(ctx->owner, &entry);

  ctx->last_message_time = now;
  ctx->has_last_message_time = true;

  session_asciiart_reset(ctx);
}

static void session_asciiart_cancel(session_ctx_t *ctx, const char *reason) {
  if (ctx == NULL || !ctx->asciiart_pending) {
    return;
  }

  session_asciiart_reset(ctx);
  if (reason != NULL && reason[0] != '\0') {
    session_send_system_line(ctx, reason);
  }
}

static bool session_asciiart_capture_continue(const session_ctx_t *ctx) {
  return ctx != NULL && ctx->asciiart_pending;
}

static bool session_bbs_capture_continue(const session_ctx_t *ctx) {
  return ctx != NULL && ctx->bbs_post_pending;
}

static void session_capture_multiline_text(session_ctx_t *ctx, const char *text, session_text_line_consumer_t consumer,
                                           session_text_continue_predicate_t should_continue) {
  if (ctx == NULL || text == NULL || consumer == NULL || should_continue == NULL) {
    return;
  }

  char line[SSH_CHATTER_MAX_INPUT_LEN];
  size_t line_length = 0U;
  bool emitted = false;

  const char *cursor = text;
  while (*cursor != '\0') {
    char ch = *cursor++;
    if (ch == '\\') {
      char next = *cursor;
      if (next == 'r') {
        ++cursor;
        if (*cursor == '\\' && cursor[1] == 'n') {
          cursor += 2;
        }
        line[line_length] = '\0';
        consumer(ctx, line);
        emitted = true;
        line_length = 0U;
        if (!should_continue(ctx)) {
          return;
        }
        continue;
      }
      if (next == 'n') {
        ++cursor;
        line[line_length] = '\0';
        consumer(ctx, line);
        emitted = true;
        line_length = 0U;
        if (!should_continue(ctx)) {
          return;
        }
        continue;
      }
      if (next == '\\') {
        ++cursor;
        ch = '\\';
      }
    }

    if (ch == '\r') {
      if (*cursor == '\n') {
        ++cursor;
      }
      line[line_length] = '\0';
      consumer(ctx, line);
      emitted = true;
      line_length = 0U;
      if (!should_continue(ctx)) {
        return;
      }
      continue;
    }

    if (ch == '\n') {
      line[line_length] = '\0';
      consumer(ctx, line);
      emitted = true;
      line_length = 0U;
      if (!should_continue(ctx)) {
        return;
      }
      continue;
    }

    if (line_length + 1U < sizeof(line)) {
      line[line_length++] = ch;
    }
  }

  if (line_length > 0U || !emitted) {
    line[line_length] = '\0';
    consumer(ctx, line);
  }
}

static void session_asciiart_capture_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || !ctx->asciiart_pending || text == NULL) {
    return;
  }

  session_capture_multiline_text(ctx, text, session_asciiart_capture_line, session_asciiart_capture_continue);
}

static void session_asciiart_capture_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || !ctx->asciiart_pending) {
    return;
  }

  char trimmed[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(trimmed, sizeof(trimmed), "%s", line != NULL ? line : "");
  trim_whitespace_inplace(trimmed);
  if (strcmp(trimmed, SSH_CHATTER_ASCIIART_TERMINATOR) == 0) {
    session_asciiart_commit(ctx);
    return;
  }

  if (ctx->asciiart_line_count >= SSH_CHATTER_ASCIIART_MAX_LINES) {
    session_send_system_line(ctx, "ASCII art line limit reached. Use the terminator to finish.");
    return;
  }

  if (line == NULL) {
    line = "";
  }

  const bool profile_target = ctx->asciiart_target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE;
  const char *full_message =
      profile_target ? "Profile picture buffer is full. Additional text ignored."
                      : "ASCII art buffer is full. Additional text ignored.";
  const char *truncate_message =
      profile_target ? "Line truncated to fit within the profile picture size limit."
                     : "Line truncated to fit within the ASCII art size limit.";

  size_t buffer_capacity = sizeof(ctx->asciiart_buffer);
  if (profile_target && buffer_capacity > USER_DATA_PROFILE_PICTURE_LEN) {
    buffer_capacity = USER_DATA_PROFILE_PICTURE_LEN;
  }

  if (ctx->asciiart_length >= buffer_capacity - 1U) {
    session_send_system_line(ctx, full_message);
    return;
  }

  size_t available = buffer_capacity - ctx->asciiart_length - 1U;
  const size_t newline_cost = ctx->asciiart_length > 0U ? 1U : 0U;
  if (available < newline_cost) {
    session_send_system_line(ctx, full_message);
    return;
  }

  size_t line_length = strlen(line);
  size_t max_line_length = (available > newline_cost) ? (available - newline_cost) : 0U;
  if (line_length > max_line_length) {
    line_length = max_line_length;
    session_send_system_line(ctx, truncate_message);
  }

  if (ctx->asciiart_length > 0U) {
    ctx->asciiart_buffer[ctx->asciiart_length++] = '\n';
  }

  if (line_length > 0U) {
    memcpy(ctx->asciiart_buffer + ctx->asciiart_length, line, line_length);
    ctx->asciiart_length += line_length;
  }

  ctx->asciiart_buffer[ctx->asciiart_length] = '\0';
  ctx->asciiart_line_count += 1U;
}

// Handle the /bbs command entry point.
static void session_handle_bbs(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_bbs_show_dashboard(ctx);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_bbs_show_dashboard(ctx);
    return;
  }

  char *command = working;
  char *rest = NULL;
  for (char *cursor = working; *cursor != '\0'; ++cursor) {
    if (isspace((unsigned char)*cursor)) {
      *cursor = '\0';
      rest = cursor + 1;
      break;
    }
  }
  if (rest != NULL) {
    trim_whitespace_inplace(rest);
  }

  if (strcmp(command, "exit") == 0) {
    ctx->in_bbs_mode = false;
    ctx->bbs_view_active = false;
    ctx->bbs_view_post_id = 0U;
    session_send_system_line(ctx, "Exited BBS mode.");
    return;
  }

  ctx->in_bbs_mode = true;

  if (strcmp(command, "list") == 0) {
    session_bbs_prepare_canvas(ctx);
    session_bbs_list(ctx);
  } else if (strcmp(command, "read") == 0) {
    if (rest == NULL || rest[0] == '\0') {
      session_send_system_line(ctx, "Usage: /bbs read <id>");
      return;
    }
    uint64_t id = (uint64_t)strtoull(rest, NULL, 10);
    session_bbs_read(ctx, id);
  } else if (strcmp(command, "post") == 0) {
    session_bbs_begin_post(ctx, rest);
  } else if (strcmp(command, "comment") == 0) {
    session_bbs_add_comment(ctx, rest);
  } else if (strcmp(command, "regen") == 0) {
    if (rest == NULL || rest[0] == '\0') {
      session_send_system_line(ctx, "Usage: /bbs regen <id>");
      return;
    }
    uint64_t id = (uint64_t)strtoull(rest, NULL, 10);
    session_bbs_regen_post(ctx, id);
  } else if (strcmp(command, "delete") == 0) {
    if (rest == NULL || rest[0] == '\0') {
      session_send_system_line(ctx, "Usage: /bbs delete <id>");
      return;
    }
    uint64_t id = (uint64_t)strtoull(rest, NULL, 10);
    session_bbs_delete(ctx, id);
  } else {
    session_send_system_line(ctx, "Unknown /bbs subcommand. Try /bbs for usage.");
  }
}

static void session_game_seed_rng(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->game.rng_seeded) {
    return;
  }

  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    ts.tv_sec = time(NULL);
    ts.tv_nsec = 0L;
  }

  uint64_t seed = ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec ^ (uintptr_t)ctx ^ (uintptr_t)ctx->owner;
  if (seed == 0U) {
    seed = UINT64_C(0x9E3779B97F4A7C15);
  }
  ctx->game.rng_state = seed;
  ctx->game.rng_seeded = true;
}

static uint32_t session_game_random(session_ctx_t *ctx) {
  session_game_seed_rng(ctx);
  uint64_t x = ctx->game.rng_state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  ctx->game.rng_state = x;
  uint64_t result = x * UINT64_C(2685821657736338717);
  return (uint32_t)(result >> 32);
}

static int session_game_random_range(session_ctx_t *ctx, int max) {
  if (max <= 0) {
    return 0;
  }
  return (int)(session_game_random(ctx) % (uint32_t)max);
}

static void session_game_tetris_reset(tetris_game_state_t *state) {
  if (state == NULL) {
    return;
  }

  memset(state->board, 0, sizeof(state->board));
  state->current_piece = -1;
  state->rotation = 0;
  state->row = 0;
  state->column = 0;
  state->next_piece = 0;
  state->score = 0U;
  state->lines_cleared = 0U;
  state->game_over = false;
  state->bag_index = 0U;
  for (size_t idx = 0U; idx < 7U; ++idx) {
    state->bag[idx] = (int)idx;
  }
  state->gravity_counter = 0U;
  state->gravity_rate = SSH_CHATTER_TETRIS_GRAVITY_RATE;
  state->gravity_timer_initialized = false;
  state->gravity_timer_last.tv_sec = 0;
  state->gravity_timer_last.tv_nsec = 0;
  state->gravity_timer_accumulator_ns = 0U;
  state->round = 1U;
  state->next_round_line_goal = SSH_CHATTER_TETRIS_LINES_PER_ROUND;
  session_game_tetris_apply_round_settings(state);
  state->input_escape_active = false;
  state->input_escape_length = 0U;
  memset(state->input_escape_buffer, 0, sizeof(state->input_escape_buffer));
}

static void session_game_tetris_apply_round_settings(tetris_game_state_t *state) {
  if (state == NULL) {
    return;
  }

  if (state->round == 0U) {
    state->round = 1U;
  }

  unsigned reduction = state->round > 0U ? state->round - 1U : 0U;
  unsigned base_threshold = SSH_CHATTER_TETRIS_GRAVITY_THRESHOLD;
  unsigned threshold = base_threshold;
  if (reduction >= base_threshold) {
    threshold = 1U;
  } else {
    threshold = base_threshold - reduction;
  }

  if (threshold == 0U) {
    threshold = 1U;
  }

  state->gravity_threshold = threshold;
  state->gravity_counter = 0U;
  state->gravity_timer_initialized = false;
  state->gravity_timer_last.tv_sec = 0;
  state->gravity_timer_last.tv_nsec = 0;
  state->gravity_timer_accumulator_ns = 0U;
}

static void session_game_tetris_fill_bag(session_ctx_t *ctx) {
  tetris_game_state_t *state = &ctx->game.tetris;
  for (size_t idx = 0U; idx < 7U; ++idx) {
    state->bag[idx] = (int)idx;
  }
  for (int idx = 6; idx > 0; --idx) {
    int swap_index = session_game_random_range(ctx, idx + 1);
    int temp = state->bag[idx];
    state->bag[idx] = state->bag[swap_index];
    state->bag[swap_index] = temp;
  }
  state->bag_index = 0U;
}

static int session_game_tetris_take_piece(session_ctx_t *ctx) {
  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->bag_index >= 7U) {
    session_game_tetris_fill_bag(ctx);
  }
  return state->bag[state->bag_index++];
}

static bool session_game_tetris_cell_occupied(int piece, int rotation, int row, int column) {
  if (piece < 0 || piece >= 7) {
    return false;
  }
  rotation = rotation & 3;
  if (row < 0 || row >= SSH_CHATTER_TETROMINO_SIZE || column < 0 || column >= SSH_CHATTER_TETROMINO_SIZE) {
    return false;
  }
  const char *shape = TETROMINO_SHAPES[piece][rotation];
  char value = shape[row * SSH_CHATTER_TETROMINO_SIZE + column];
  return value != '.' && value != '\0';
}

static bool session_game_tetris_position_valid(const tetris_game_state_t *state, int piece, int rotation, int row,
                                              int column) {
  if (state == NULL) {
    return false;
  }
  for (int r = 0; r < SSH_CHATTER_TETROMINO_SIZE; ++r) {
    for (int c = 0; c < SSH_CHATTER_TETROMINO_SIZE; ++c) {
      if (!session_game_tetris_cell_occupied(piece, rotation, r, c)) {
        continue;
      }
      int board_row = row + r;
      int board_col = column + c;
      if (board_col < 0 || board_col >= SSH_CHATTER_TETRIS_WIDTH) {
        return false;
      }
      if (board_row >= SSH_CHATTER_TETRIS_HEIGHT) {
        return false;
      }
      if (board_row < 0) {
        continue;
      }
      if (state->board[board_row][board_col] != 0) {
        return false;
      }
    }
  }
  return true;
}

static bool session_game_tetris_spawn_piece(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }
  tetris_game_state_t *state = &ctx->game.tetris;
  state->current_piece = state->next_piece;
  state->rotation = 0;
  state->row = 0;
  state->column = (SSH_CHATTER_TETRIS_WIDTH / 2) - 2;
  state->gravity_counter = 0U;
  state->gravity_timer_initialized = false;
  state->gravity_timer_accumulator_ns = 0U;
  state->input_escape_active = false;
  state->input_escape_length = 0U;
  state->next_piece = session_game_tetris_take_piece(ctx);
  if (!session_game_tetris_position_valid(state, state->current_piece, state->rotation, state->row, state->column)) {
    state->game_over = true;
    return false;
  }
  return true;
}

static bool session_game_tetris_move(session_ctx_t *ctx, int drow, int dcol) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS) {
    return false;
  }
  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->current_piece < 0) {
    return false;
  }
  int new_row = state->row + drow;
  int new_col = state->column + dcol;
  if (!session_game_tetris_position_valid(state, state->current_piece, state->rotation, new_row, new_col)) {
    return false;
  }
  state->row = new_row;
  state->column = new_col;
  return true;
}

static bool session_game_tetris_soft_drop(session_ctx_t *ctx) {
  if (session_game_tetris_move(ctx, 1, 0)) {
    return true;
  }
  session_game_tetris_lock_piece(ctx);
  return false;
}

static bool session_game_tetris_apply_gravity(session_ctx_t *ctx, unsigned ticks) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return false;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->game_over || ticks == 0U) {
    return false;
  }

  if (state->gravity_threshold == 0U) {
    state->gravity_threshold = SSH_CHATTER_TETRIS_GRAVITY_THRESHOLD;
  }

  bool moved = false;
  state->gravity_counter += ticks;
  while (state->gravity_counter >= state->gravity_threshold) {
    if (!session_game_tetris_soft_drop(ctx)) {
      state->gravity_counter = 0U;
      break;
    }
    moved = true;
    state->gravity_counter -= state->gravity_threshold;
    if (state->game_over) {
      break;
    }
  }
  return moved;
}

typedef enum {
  TETRIS_INPUT_NONE = 0,
  TETRIS_INPUT_MOVE_LEFT,
  TETRIS_INPUT_MOVE_RIGHT,
  TETRIS_INPUT_ROTATE,
  TETRIS_INPUT_SOFT_DROP,
  TETRIS_INPUT_HARD_DROP,
} tetris_input_action_t;

static bool session_game_tetris_update_timer(session_ctx_t *ctx, bool accelerate) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return false;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->game_over) {
    return false;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  if (!state->gravity_timer_initialized) {
    state->gravity_timer_last = now;
    state->gravity_timer_initialized = true;
  } else {
    struct timespec last = state->gravity_timer_last;
    state->gravity_timer_last = now;

    time_t sec_delta = now.tv_sec - last.tv_sec;
    long nsec_delta = now.tv_nsec - last.tv_nsec;
    if (nsec_delta < 0L) {
      --sec_delta;
      nsec_delta += 1000000000L;
    }

    if (sec_delta > 0 || nsec_delta > 0L) {
      uint64_t elapsed_ns = (uint64_t)sec_delta * 1000000000ULL + (uint64_t)nsec_delta;
      state->gravity_timer_accumulator_ns += elapsed_ns;
    }
  }

  unsigned ticks = 0U;
  while (state->gravity_timer_accumulator_ns >= SSH_CHATTER_TETRIS_GRAVITY_INTERVAL_NS) {
    state->gravity_timer_accumulator_ns -= SSH_CHATTER_TETRIS_GRAVITY_INTERVAL_NS;
    ticks += state->gravity_rate;
  }

  if (accelerate) {
    ticks += state->gravity_rate + state->gravity_threshold;
  }

  if (ticks == 0U) {
    return false;
  }

  return session_game_tetris_apply_gravity(ctx, ticks);
}

static bool session_game_tetris_process_timeout(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return false;
  }

  bool redraw = session_game_tetris_update_timer(ctx, false);
  if (ctx->game.tetris.game_over) {
    session_game_suspend(ctx, "Game over!");
    return true;
  }

  if (redraw) {
    session_game_tetris_render(ctx);
  }
  return redraw;
}

static bool session_game_tetris_process_action(session_ctx_t *ctx, int action_value) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return false;
  }

  tetris_input_action_t action = (tetris_input_action_t)action_value;
  if (action == TETRIS_INPUT_NONE) {
    return false;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->game_over) {
    session_game_suspend(ctx, "Game over!");
    return true;
  }

  bool redraw = session_game_tetris_update_timer(ctx, false);
  if (state->game_over) {
    session_game_suspend(ctx, "Game over!");
    return true;
  }

  bool accelerate = false;
  bool manual_drop = false;

  switch (action) {
    case TETRIS_INPUT_MOVE_LEFT:
      if (session_game_tetris_move(ctx, 0, -1)) {
        redraw = true;
      }
      break;
    case TETRIS_INPUT_MOVE_RIGHT:
      if (session_game_tetris_move(ctx, 0, 1)) {
        redraw = true;
      }
      break;
    case TETRIS_INPUT_ROTATE:
      if (session_game_tetris_rotate(ctx)) {
        redraw = true;
      }
      break;
    case TETRIS_INPUT_SOFT_DROP:
      accelerate = true;
      break;
    case TETRIS_INPUT_HARD_DROP:
      while (session_game_tetris_soft_drop(ctx)) {
        redraw = true;
      }
      manual_drop = true;
      break;
    case TETRIS_INPUT_NONE:
    default:
      break;
  }

  if (state->game_over) {
    session_game_suspend(ctx, "Game over!");
    return true;
  }

  if (accelerate) {
    if (session_game_tetris_update_timer(ctx, true)) {
      redraw = true;
    }
  } else if (!manual_drop) {
    if (session_game_tetris_update_timer(ctx, false)) {
      redraw = true;
    }
  }

  if (state->game_over) {
    session_game_suspend(ctx, "Game over!");
    return true;
  }

  if (redraw) {
    session_game_tetris_render(ctx);
  }

  return true;
}

static bool session_game_tetris_process_raw_input(session_ctx_t *ctx, char ch) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return false;
  }

  tetris_game_state_t *state = &ctx->game.tetris;

  if (ch == 0x01 || ch == 0x03 || ch == 0x1a || ch == 0x13) {
    return false;
  }

  if (state->input_escape_active) {
    if (state->input_escape_length < sizeof(state->input_escape_buffer)) {
      state->input_escape_buffer[state->input_escape_length++] = ch;
    }

    if (state->input_escape_length == 2U && state->input_escape_buffer[1] == '[') {
      return true;
    }

    if (state->input_escape_length >= 3U && state->input_escape_buffer[1] == '[') {
      char final = state->input_escape_buffer[state->input_escape_length - 1U];
      tetris_input_action_t action = TETRIS_INPUT_NONE;
      if (final == 'A') {
        action = TETRIS_INPUT_ROTATE;
      } else if (final == 'B') {
        action = TETRIS_INPUT_SOFT_DROP;
      } else if (final == 'C') {
        action = TETRIS_INPUT_MOVE_RIGHT;
      } else if (final == 'D') {
        action = TETRIS_INPUT_MOVE_LEFT;
      }
      state->input_escape_active = false;
      state->input_escape_length = 0U;
      if (action != TETRIS_INPUT_NONE) {
        session_game_tetris_process_action(ctx, action);
      }
      return true;
    }

    state->input_escape_active = false;
    state->input_escape_length = 0U;
    return true;
  }

  if (ch == 0x1b) {
    state->input_escape_active = true;
    state->input_escape_length = 0U;
    state->input_escape_buffer[state->input_escape_length++] = ch;
    return true;
  }

  if (ch == '\r' || ch == '\n') {
    return true;
  }

  if (ch == 0x12) {
    session_game_tetris_process_action(ctx, TETRIS_INPUT_ROTATE);
    return true;
  }

  unsigned char lowered = (unsigned char)ch;
  if (lowered >= 'A' && lowered <= 'Z') {
    lowered = (unsigned char)tolower(lowered);
  }

  switch (lowered) {
    case 'a':
      session_game_tetris_process_action(ctx, TETRIS_INPUT_MOVE_LEFT);
      return true;
    case 'd':
      session_game_tetris_process_action(ctx, TETRIS_INPUT_MOVE_RIGHT);
      return true;
    case 'w':
      session_game_tetris_process_action(ctx, TETRIS_INPUT_ROTATE);
      return true;
    case 's':
      session_game_tetris_process_action(ctx, TETRIS_INPUT_SOFT_DROP);
      return true;
    case ' ':
      session_game_tetris_process_action(ctx, TETRIS_INPUT_HARD_DROP);
      return true;
    default:
      break;
  }

  if ((unsigned char)ch < 0x20U) {
    return false;
  }

  return true;
}

static bool session_game_tetris_rotate(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS) {
    return false;
  }
  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->current_piece < 0) {
    return false;
  }
  int new_rotation = (state->rotation + 1) & 3;
  if (!session_game_tetris_position_valid(state, state->current_piece, new_rotation, state->row, state->column)) {
    return false;
  }
  state->rotation = new_rotation;
  return true;
}

static void session_game_tetris_clear_lines(session_ctx_t *ctx, unsigned *cleared) {
  if (ctx == NULL) {
    if (cleared != NULL) {
      *cleared = 0U;
    }
    return;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  unsigned removed = 0U;
  for (int row = 0; row < SSH_CHATTER_TETRIS_HEIGHT; ++row) {
    bool full = true;
    for (int col = 0; col < SSH_CHATTER_TETRIS_WIDTH; ++col) {
      if (state->board[row][col] == 0) {
        full = false;
        break;
      }
    }
    if (!full) {
      continue;
    }
    ++removed;
    for (int move_row = row; move_row > 0; --move_row) {
      for (int move_col = 0; move_col < SSH_CHATTER_TETRIS_WIDTH; ++move_col) {
        state->board[move_row][move_col] = state->board[move_row - 1][move_col];
      }
    }
    for (int move_col = 0; move_col < SSH_CHATTER_TETRIS_WIDTH; ++move_col) {
      state->board[0][move_col] = 0;
    }
  }
  if (cleared != NULL) {
    *cleared = removed;
  }
}

static void session_game_tetris_handle_round_progress(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS) {
    return;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  while (state->round < SSH_CHATTER_TETRIS_MAX_ROUNDS && state->lines_cleared >= state->next_round_line_goal) {
    state->round += 1U;
    state->next_round_line_goal += SSH_CHATTER_TETRIS_LINES_PER_ROUND;
    session_game_tetris_apply_round_settings(state);

    char announcement[SSH_CHATTER_MESSAGE_LIMIT];
    if (state->round >= SSH_CHATTER_TETRIS_MAX_ROUNDS) {
      snprintf(announcement, sizeof(announcement), "Round %u reached! Gravity is at maximum speed.", state->round);
    } else {
      snprintf(announcement, sizeof(announcement), "Round %u reached! Blocks will fall faster.", state->round);
    }
    bool previous_translation_suppress = ctx->translation_suppress_output;
    ctx->translation_suppress_output = true;
    session_send_system_line(ctx, announcement);
    ctx->translation_suppress_output = previous_translation_suppress;
  }
}

static void session_game_tetris_lock_piece(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS) {
    return;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->current_piece < 0) {
    return;
  }

  for (int r = 0; r < SSH_CHATTER_TETROMINO_SIZE; ++r) {
    for (int c = 0; c < SSH_CHATTER_TETROMINO_SIZE; ++c) {
      if (!session_game_tetris_cell_occupied(state->current_piece, state->rotation, r, c)) {
        continue;
      }
      int board_row = state->row + r;
      int board_col = state->column + c;
      if (board_row < 0 || board_row >= SSH_CHATTER_TETRIS_HEIGHT || board_col < 0 || board_col >= SSH_CHATTER_TETRIS_WIDTH) {
        continue;
      }
      state->board[board_row][board_col] = state->current_piece + 1;
    }
  }

  unsigned cleared = 0U;
  session_game_tetris_clear_lines(ctx, &cleared);
  if (cleared > 0U) {
    state->lines_cleared += cleared;
    state->score += cleared * 100U;
    session_game_tetris_handle_round_progress(ctx);
  }

  if (!session_game_tetris_spawn_piece(ctx)) {
    state->game_over = true;
  }
}

static void session_game_tetris_render(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS) {
    return;
  }

  bool previous_translation_suppress = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;

  tetris_game_state_t *state = &ctx->game.tetris;
  session_render_separator(ctx, "Tetris");

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  char next_char = TETROMINO_DISPLAY_CHARS[state->next_piece % 7];
  if (state->round < SSH_CHATTER_TETRIS_MAX_ROUNDS) {
    unsigned lines_remaining = 0U;
    if (state->next_round_line_goal > state->lines_cleared) {
      lines_remaining = state->next_round_line_goal - state->lines_cleared;
    }
    snprintf(header, sizeof(header), "Score: %u   Lines: %u   Round: %u/%u (next in %u)   Next: %c", state->score,
             state->lines_cleared, state->round, SSH_CHATTER_TETRIS_MAX_ROUNDS, lines_remaining, next_char);
  } else {
    snprintf(header, sizeof(header), "Score: %u   Lines: %u   Round: %u/%u (max speed)   Next: %c", state->score,
             state->lines_cleared, state->round, SSH_CHATTER_TETRIS_MAX_ROUNDS, next_char);
  }
  session_send_system_line(ctx, header);
  session_send_system_line(ctx, "Controls: left, right, down, Ctrl+R rotate, drop. Blank line = down.");

  char border[SSH_CHATTER_TETRIS_WIDTH + 3];
  border[0] = '+';
  for (int col = 0; col < SSH_CHATTER_TETRIS_WIDTH; ++col) {
    border[col + 1] = '-';
  }
  border[SSH_CHATTER_TETRIS_WIDTH + 1] = '+';
  border[SSH_CHATTER_TETRIS_WIDTH + 2] = '\0';
  session_send_system_line(ctx, border);

  for (int row = 0; row < SSH_CHATTER_TETRIS_HEIGHT; ++row) {
    char line_buffer[SSH_CHATTER_TETRIS_WIDTH + 3];
    line_buffer[0] = '|';
    for (int col = 0; col < SSH_CHATTER_TETRIS_WIDTH; ++col) {
      char cell = ' ';
      if (state->board[row][col] != 0) {
        int index = state->board[row][col] - 1;
        if (index < 0 || index >= 7) {
          index = 0;
        }
        cell = TETROMINO_DISPLAY_CHARS[index];
      } else if (!state->game_over && state->current_piece >= 0) {
        int local_row = row - state->row;
        int local_col = col - state->column;
        if (local_row >= 0 && local_row < SSH_CHATTER_TETROMINO_SIZE && local_col >= 0 &&
            local_col < SSH_CHATTER_TETROMINO_SIZE &&
            session_game_tetris_cell_occupied(state->current_piece, state->rotation, local_row, local_col)) {
          cell = TETROMINO_DISPLAY_CHARS[state->current_piece];
        }
      }
      line_buffer[col + 1] = cell;
    }
    line_buffer[SSH_CHATTER_TETRIS_WIDTH + 1] = '|';
    line_buffer[SSH_CHATTER_TETRIS_WIDTH + 2] = '\0';
    session_send_system_line(ctx, line_buffer);
  }

  session_send_system_line(ctx, border);

  ctx->translation_suppress_output = previous_translation_suppress;
}

static void session_game_tetris_handle_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_TETRIS || !ctx->game.active) {
    return;
  }

  tetris_game_state_t *state = &ctx->game.tetris;
  if (state->game_over) {
    session_game_suspend(ctx, "Game over!");
    return;
  }

  bool previous_translation_suppress = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;

  char command[32];
  if (line == NULL) {
    command[0] = '\0';
  } else {
    size_t copy_len = strnlen(line, sizeof(command) - 1U);
    memcpy(command, line, copy_len);
    command[copy_len] = '\0';
  }
  trim_whitespace_inplace(command);
  for (size_t idx = 0U; command[idx] != '\0'; ++idx) {
    command[idx] = (char)tolower((unsigned char)command[idx]);
  }

  if (command[0] == '\0') {
    session_game_tetris_process_timeout(ctx);
    goto cleanup;
  }

  if (strcmp(command, "help") == 0) {
    session_send_system_line(ctx,
                             "Tetris controls: WASD or arrow keys move (W/Up rotate, S/Down soft drop, A/Left, D/Right),"
                             " space for a hard drop, and Ctrl+R also rotates. Ctrl+Z or /suspend! exits.");
    goto cleanup;
  }

  if (strcmp(command, "drop") == 0) {
    session_game_tetris_process_action(ctx, TETRIS_INPUT_HARD_DROP);
    goto cleanup;
  }

  session_send_system_line(ctx, "Use WASD or the arrow keys for control. Type help for a summary.");

cleanup:
  ctx->translation_suppress_output = previous_translation_suppress;
}

static void session_game_start_tetris(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_game_tetris_reset(&ctx->game.tetris);
  session_game_seed_rng(ctx);
  session_game_tetris_fill_bag(ctx);
  ctx->game.tetris.next_piece = session_game_tetris_take_piece(ctx);
  ctx->game.type = SESSION_GAME_TETRIS;
  ctx->game.active = true;
  ctx->game.tetris.game_over = false;
  bool previous_translation_suppress = ctx->translation_suppress_output;
  if (!session_game_tetris_spawn_piece(ctx)) {
    ctx->translation_suppress_output = true;
    session_send_system_line(ctx, "Unable to start Tetris right now.");
    ctx->translation_suppress_output = previous_translation_suppress;
    ctx->game.active = false;
    ctx->game.type = SESSION_GAME_NONE;
    return;
  }

  ctx->translation_suppress_output = true;

  session_send_system_line(ctx,
                           "Tetris started. Pieces fall on their own — use WASD or the arrow keys (W/Up rotate, S/Down soft"
                           " drop, A/Left, D/Right), space for a hard drop, and Ctrl+R to rotate. Ctrl+Z or /suspend! exits.");
  char round_message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(round_message, sizeof(round_message), "Round 1/%u: Clear %u lines to reach the next round.",
           SSH_CHATTER_TETRIS_MAX_ROUNDS, SSH_CHATTER_TETRIS_LINES_PER_ROUND);
  session_send_system_line(ctx, round_message);
  session_game_tetris_render(ctx);

  ctx->translation_suppress_output = previous_translation_suppress;
}

static void session_game_start_liargame(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->game.type = SESSION_GAME_LIARGAME;
  ctx->game.active = true;
  ctx->game.liar.round_number = 0U;
  ctx->game.liar.score = 0U;
  ctx->game.liar.awaiting_guess = false;
  session_send_system_line(ctx, "Liar Game started. Guess which statement is the lie by typing 1, 2, or 3.");
  session_game_liar_present_round(ctx);
}

static void session_game_liar_present_round(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_LIARGAME || !ctx->game.active) {
    return;
  }

  size_t prompt_count = sizeof(LIAR_PROMPTS) / sizeof(LIAR_PROMPTS[0]);
  if (prompt_count == 0U) {
    session_game_suspend(ctx, "No prompts available for the liar game.");
    return;
  }

  unsigned index = (unsigned)session_game_random_range(ctx, (int)prompt_count);
  ctx->game.liar.current_prompt_index = index;
  ctx->game.liar.liar_index = LIAR_PROMPTS[index].liar_index % 3U;
  ctx->game.liar.round_number += 1U;
  ctx->game.liar.awaiting_guess = true;

  session_render_separator(ctx, "Liar Game");
  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Round %u — which statement is the lie?", ctx->game.liar.round_number);
  session_send_system_line(ctx, header);

  const liar_prompt_t *prompt = &LIAR_PROMPTS[index];
  for (int i = 0; i < 3; ++i) {
    char line_buffer[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line_buffer, sizeof(line_buffer), "%d. %s", i + 1, prompt->statements[i]);
    session_send_system_line(ctx, line_buffer);
  }
  session_send_system_line(ctx, "Enter 1, 2, or 3 to choose. Type 'help' for options.");
}

static void session_game_liar_handle_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_LIARGAME || !ctx->game.active) {
    return;
  }

  liar_game_state_t *state = &ctx->game.liar;
  char command[32];
  if (line == NULL) {
    command[0] = '\0';
  } else {
    size_t copy_len = strnlen(line, sizeof(command) - 1U);
    memcpy(command, line, copy_len);
    command[copy_len] = '\0';
  }
  trim_whitespace_inplace(command);
  for (size_t idx = 0U; command[idx] != '\0'; ++idx) {
    command[idx] = (char)tolower((unsigned char)command[idx]);
  }

  if (strcmp(command, "help") == 0) {
    session_send_system_line(ctx, "Type 1, 2, or 3 to guess the lie. /suspend! exits the game.");
    return;
  }

  if (command[0] == '\0') {
    session_send_system_line(ctx, "Pick a statement number between 1 and 3.");
    return;
  }

  if (!state->awaiting_guess) {
    session_game_liar_present_round(ctx);
    return;
  }

  char *endptr = NULL;
  long value = strtol(command, &endptr, 10);
  if (endptr == command || value < 1L || value > 3L) {
    session_send_system_line(ctx, "Please enter 1, 2, or 3 to choose the lie.");
    return;
  }

  unsigned guess = (unsigned)(value - 1L);
  const liar_prompt_t *prompt = &LIAR_PROMPTS[state->current_prompt_index];
  if (guess == state->liar_index) {
    ++state->score;
    session_send_system_line(ctx, "Correct! That statement was the lie.");
  } else {
    char reveal[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(reveal, sizeof(reveal), "Nope! The lie was #%u: %s", state->liar_index + 1U,
             prompt->statements[state->liar_index]);
    session_send_system_line(ctx, reveal);
  }

  state->awaiting_guess = false;
  session_game_liar_present_round(ctx);
}

static void session_game_alpha_add_gravity_source(alpha_centauri_game_state_t *state, int x, int y, double mu,
                                                  int influence_radius, char symbol, const char *name) {
  if (state == NULL || state->gravity_source_count >= ALPHA_MAX_GRAVITY_SOURCES) {
    return;
  }

  if (x < 0) {
    x = 0;
  } else if (x >= ALPHA_NAV_WIDTH) {
    x = ALPHA_NAV_WIDTH - 1;
  }

  if (y < 0) {
    y = 0;
  } else if (y >= ALPHA_NAV_HEIGHT) {
    y = ALPHA_NAV_HEIGHT - 1;
  }

  alpha_gravity_source_t *source = &state->gravity_sources[state->gravity_source_count++];
  source->x = x;
  source->y = y;
  source->mu = mu >= 0.0 ? mu : 0.0;
  source->influence_radius = influence_radius > 0 ? influence_radius : 0;
  source->symbol = symbol;
  if (name != NULL) {
    snprintf(source->name, sizeof(source->name), "%s", name);
  } else {
    source->name[0] = '\0';
  }
}

static void session_game_alpha_configure_gravity(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;

  for (unsigned idx = 0U; idx < ALPHA_MAX_GRAVITY_SOURCES; ++idx) {
    state->gravity_sources[idx] = (alpha_gravity_source_t){0};
  }
  state->gravity_source_count = 0U;

  double stage_multiplier = 1.0 + (double)state->stage * 0.25;
  const char *hole_name = state->stage >= 3 ? "Proxima Abyss" : "Core Singularity";
  unsigned special_sources = 0U;
  if (state->stage == 4U) {
    if (!state->eva_ready || state->final_waypoint.symbol == '\0') {
      session_game_alpha_plan_waypoints(ctx);
    }
    if (!state->eva_ready) {
      special_sources += state->waypoint_count;
    }
    if (state->final_waypoint.symbol != '\0') {
      ++special_sources;
    }
  }
  double hole_mu = ALPHA_BLACK_HOLE_MU * session_game_alpha_random_double(ctx, stage_multiplier,
                                                                          stage_multiplier + 0.75);
  session_game_alpha_place_random_source(ctx, state, ALPHA_NAV_MARGIN, hole_mu, ALPHA_NAV_MARGIN * 3, 'B', hole_name);

  int star_count = 2 + (int)state->stage;
  int planet_count = 2 + (int)(state->stage / 2);
  int debris_count = 1 + (int)state->stage;
  if (state->stage >= 4 && state->awaiting_flag) {
    planet_count += 1;
    debris_count += 2;
  }

  if (state->stage >= 4) {
    planet_count = 0;
  }

  int available_slots = (int)ALPHA_MAX_GRAVITY_SOURCES - 1 - (int)special_sources;
  if (available_slots < 0) {
    available_slots = 0;
  }
  if (star_count > available_slots) {
    star_count = available_slots;
  }
  available_slots -= star_count;
  if (available_slots < 0) {
    available_slots = 0;
  }
  if (planet_count > available_slots) {
    planet_count = available_slots;
  }
  available_slots -= planet_count;
  if (available_slots < 0) {
    available_slots = 0;
  }
  if (debris_count > available_slots) {
    debris_count = available_slots;
  }

  for (int idx = 0; idx < star_count; ++idx) {
    const char *name = kAlphaStarCatalog[session_game_random_range(ctx, (int)ALPHA_STAR_CATALOG_COUNT)];
    double mu = ALPHA_STAR_MU * session_game_alpha_random_double(ctx, stage_multiplier * 0.7, stage_multiplier * 1.3);
    session_game_alpha_place_random_source(ctx, state, ALPHA_NAV_MARGIN / 2, mu, ALPHA_NAV_MARGIN * 2, 'S', name);
  }

  for (int idx = 0; idx < planet_count; ++idx) {
    const char *name = kAlphaPlanetCatalog[session_game_random_range(ctx, (int)ALPHA_PLANET_CATALOG_COUNT)];
    double mu = ALPHA_PLANET_MU * session_game_alpha_random_double(ctx, stage_multiplier * 0.6, stage_multiplier * 1.4);
    session_game_alpha_place_random_source(ctx, state, ALPHA_NAV_MARGIN / 2, mu, ALPHA_NAV_MARGIN * 2, 'P', name);
  }

  for (int idx = 0; idx < debris_count; ++idx) {
    const char *name = kAlphaDebrisCatalog[session_game_random_range(ctx, (int)ALPHA_DEBRIS_CATALOG_COUNT)];
    double mu = ALPHA_DEBRIS_MU * session_game_alpha_random_double(ctx, 0.5, 1.8) * stage_multiplier;
    session_game_alpha_place_random_source(ctx, state, ALPHA_NAV_MARGIN / 3, mu, ALPHA_NAV_MARGIN, 'D', name);
  }

  if (state->stage == 4U) {
    if (!state->eva_ready) {
      for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
        const alpha_waypoint_t *waypoint = &state->waypoints[idx];
        session_game_alpha_add_gravity_source(state, waypoint->x, waypoint->y, ALPHA_PLANET_MU,
                                              ALPHA_NAV_MARGIN * 2, waypoint->symbol, waypoint->name);
      }
    }
    if (state->final_waypoint.symbol != '\0') {
      session_game_alpha_add_gravity_source(state, state->final_waypoint.x, state->final_waypoint.y, ALPHA_PLANET_MU,
                                            ALPHA_NAV_MARGIN * 2, state->final_waypoint.symbol, state->final_waypoint.name);
    }
  }
}

static void session_game_alpha_apply_gravity(alpha_centauri_game_state_t *state) {
  if (state == NULL || state->gravity_source_count == 0U) {
    return;
  }

  double fx = state->nav_fx;
  double fy = state->nav_fy;
  double ax = 0.0;
  double ay = 0.0;

  for (unsigned idx = 0U; idx < state->gravity_source_count; ++idx) {
    const alpha_gravity_source_t *source = &state->gravity_sources[idx];
    if (source->mu <= 0.0) {
      continue;
    }

    double dx = (double)source->x - fx;
    double dy = (double)source->y - fy;
    double distance_sq = (dx * dx) + (dy * dy);
    double distance = sqrt(distance_sq);
    if (distance < ALPHA_GRAVITY_MIN_DISTANCE) {
      distance = ALPHA_GRAVITY_MIN_DISTANCE;
    }

    double radius = source->influence_radius > 0 ? (double)source->influence_radius : (double)ALPHA_NAV_MARGIN;
    double attenuation = 1.0;
    if (radius > 0.0) {
      double normalized = distance / radius;
      if (normalized > 1.0) {
        attenuation = 1.0 / (normalized * normalized);
      }
    }

    double force = (source->mu * attenuation) / (distance * distance);
    if (force <= 0.0) {
      continue;
    }

    ax += force * (dx / distance);
    ay += force * (dy / distance);
  }

  double accel_magnitude = hypot(ax, ay);
  if (accel_magnitude > ALPHA_GRAVITY_MAX_ACCEL && accel_magnitude > 0.0) {
    double accel_scale = ALPHA_GRAVITY_MAX_ACCEL / accel_magnitude;
    ax *= accel_scale;
    ay *= accel_scale;
  }

  state->nav_vx = (state->nav_vx + ax) * ALPHA_GRAVITY_DAMPING;
  state->nav_vy = (state->nav_vy + ay) * ALPHA_GRAVITY_DAMPING;

  double speed = hypot(state->nav_vx, state->nav_vy);
  if (speed > ALPHA_NAV_MAX_SPEED && speed > 0.0) {
    double speed_scale = ALPHA_NAV_MAX_SPEED / speed;
    state->nav_vx *= speed_scale;
    state->nav_vy *= speed_scale;
  }

  state->nav_fx += state->nav_vx;
  state->nav_fy += state->nav_vy;

  double max_x = (double)(ALPHA_NAV_WIDTH - 1);
  double max_y = (double)(ALPHA_NAV_HEIGHT - 1);

  if (state->nav_fx < 0.0) {
    state->nav_fx = 0.0;
    state->nav_vx = 0.0;
  } else if (state->nav_fx > max_x) {
    state->nav_fx = max_x;
    state->nav_vx = 0.0;
  }

  if (state->nav_fy < 0.0) {
    state->nav_fy = 0.0;
    state->nav_vy = 0.0;
  } else if (state->nav_fy > max_y) {
    state->nav_fy = max_y;
    state->nav_vy = 0.0;
  }

  long rounded_x = lround(state->nav_fx);
  long rounded_y = lround(state->nav_fy);
  if (rounded_x < 0) {
    rounded_x = 0;
  } else if (rounded_x > (long)(ALPHA_NAV_WIDTH - 1)) {
    rounded_x = (long)(ALPHA_NAV_WIDTH - 1);
  }
  if (rounded_y < 0) {
    rounded_y = 0;
  } else if (rounded_y > (long)(ALPHA_NAV_HEIGHT - 1)) {
    rounded_y = (long)(ALPHA_NAV_HEIGHT - 1);
  }

  state->nav_x = (int)rounded_x;
  state->nav_y = (int)rounded_y;
}

static void session_game_alpha_prepare_navigation(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  int safe_margin = ALPHA_NAV_MARGIN;

  state->nav_stable_ticks = 0U;
  state->nav_required_ticks = 3U;
  state->nav_vx = 0.0;
  state->nav_vy = 0.0;

  switch (state->stage) {
    case 0:
      state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_y = ALPHA_NAV_HEIGHT - 1 - session_game_random_range(ctx, safe_margin + 4);
      if (state->nav_y < safe_margin) {
        state->nav_y = safe_margin;
      }
      state->nav_target_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_target_y = session_game_random_range(ctx, safe_margin + 4);
      state->nav_required_ticks = 3U;
      break;
    case 1:
      state->nav_x = session_game_random_range(ctx, (ALPHA_NAV_WIDTH / 2)) + safe_margin;
      if (state->nav_x >= ALPHA_NAV_WIDTH) {
        state->nav_x = ALPHA_NAV_WIDTH - 1;
      }
      state->nav_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      state->nav_target_x = ALPHA_NAV_WIDTH - 1 - session_game_random_range(ctx, safe_margin + 5);
      state->nav_target_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      state->nav_required_ticks = 4U;
      break;
    case 2:
      state->nav_x = ALPHA_NAV_WIDTH - 1 - session_game_random_range(ctx, safe_margin + 5);
      state->nav_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      state->nav_target_x = session_game_random_range(ctx, safe_margin + 5);
      state->nav_target_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      state->nav_required_ticks = 4U;
      break;
    case 3:
      state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_y = session_game_random_range(ctx, safe_margin + 5);
      state->nav_target_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_target_y = ALPHA_NAV_HEIGHT - 1 - session_game_random_range(ctx, safe_margin + 5);
      state->nav_required_ticks = 5U;
      break;
    case 4:
      if (!state->eva_ready) {
        session_game_alpha_plan_waypoints(ctx);
        if (state->waypoint_count == 0U) {
          state->nav_target_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
          state->nav_target_y = session_game_random_range(ctx, safe_margin + 5);
        } else {
          if (state->waypoint_index >= state->waypoint_count) {
            state->waypoint_index = state->waypoint_count - 1U;
          }
          const alpha_waypoint_t *waypoint = &state->waypoints[state->waypoint_index];
          state->nav_target_x = waypoint->x;
          state->nav_target_y = waypoint->y;
        }
        state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
        state->nav_y = session_game_random_range(ctx, safe_margin + 5);
        state->nav_required_ticks = 4U;
      } else if (state->awaiting_flag) {
        if (state->final_waypoint.symbol == '\0') {
          session_game_alpha_plan_waypoints(ctx);
        }
        state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
        state->nav_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
        state->nav_target_x = state->final_waypoint.x;
        state->nav_target_y = state->final_waypoint.y;
        state->nav_required_ticks = 3U;
      } else {
        state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
        state->nav_y = ALPHA_NAV_HEIGHT - 1 - session_game_random_range(ctx, safe_margin + 3);
        state->nav_target_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
        state->nav_target_y = session_game_random_range(ctx, safe_margin + 3);
        state->nav_required_ticks = 3U;
      }
      break;
    default:
      state->nav_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      state->nav_target_x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, safe_margin);
      state->nav_target_y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, safe_margin);
      break;
  }

  if (state->nav_target_x < 0) {
    state->nav_target_x = 0;
  } else if (state->nav_target_x >= ALPHA_NAV_WIDTH) {
    state->nav_target_x = ALPHA_NAV_WIDTH - 1;
  }
  if (state->nav_target_y < 0) {
    state->nav_target_y = 0;
  } else if (state->nav_target_y >= ALPHA_NAV_HEIGHT) {
    state->nav_target_y = ALPHA_NAV_HEIGHT - 1;
  }

  if (state->nav_x < 0) {
    state->nav_x = 0;
  } else if (state->nav_x >= ALPHA_NAV_WIDTH) {
    state->nav_x = ALPHA_NAV_WIDTH - 1;
  }
  if (state->nav_y < 0) {
    state->nav_y = 0;
  } else if (state->nav_y >= ALPHA_NAV_HEIGHT) {
    state->nav_y = ALPHA_NAV_HEIGHT - 1;
  }

  if (state->nav_x == state->nav_target_x && state->nav_y == state->nav_target_y) {
    if (state->stage == 4U) {
      state->nav_x = (state->nav_target_x + ALPHA_NAV_MARGIN) % ALPHA_NAV_WIDTH;
      state->nav_y = (state->nav_target_y + ALPHA_NAV_MARGIN) % ALPHA_NAV_HEIGHT;
      state->nav_fx = (double)state->nav_x;
      state->nav_fy = (double)state->nav_y;
    } else {
      state->nav_target_x = (state->nav_target_x + (ALPHA_NAV_WIDTH / 2)) % ALPHA_NAV_WIDTH;
      state->nav_target_y = (state->nav_target_y + (ALPHA_NAV_HEIGHT / 2)) % ALPHA_NAV_HEIGHT;
    }
  }

  state->nav_fx = (double)state->nav_x;
  state->nav_fy = (double)state->nav_y;

  session_game_alpha_configure_gravity(ctx);
}

static void session_game_alpha_reroll_navigation(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  session_send_system_line(ctx, "Mission control: Recomputing the navigation solution...");
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_reset(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  *state = (alpha_centauri_game_state_t){0};
  state->stage = 0U;
  state->velocity_fraction_c = 0.0;
  state->distance_travelled_ly = 0.0;
  state->distance_remaining_ly = ALPHA_TOTAL_DISTANCE_LY;
  state->fuel_percent = 100.0;
  state->oxygen_days = 730.0;
  state->mission_time_years = 0.0;
  state->radiation_msv = 0.0;
  state->active = false;
  state->eva_ready = false;
  state->awaiting_flag = false;
  session_game_alpha_prepare_navigation(ctx);
}

static void session_game_alpha_sync_from_save(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  session_game_alpha_reset(ctx);

  if (!session_user_data_load(ctx)) {
    return;
  }

  const alpha_centauri_save_t *save = &ctx->user_data.alpha;
  if (!save->active) {
    return;
  }

  state->active = true;
  state->stage = save->stage <= 4U ? save->stage : 0U;
  state->eva_ready = save->eva_ready != 0U;
  state->awaiting_flag = save->awaiting_flag != 0U;
  state->velocity_fraction_c = save->velocity_fraction_c;
  state->distance_travelled_ly = save->distance_travelled_ly;
  state->distance_remaining_ly = save->distance_remaining_ly;
  if (state->distance_remaining_ly < 0.0) {
    state->distance_remaining_ly = 0.0;
  }
  state->fuel_percent = save->fuel_percent;
  state->oxygen_days = save->oxygen_days;
  state->mission_time_years = save->mission_time_years;
  state->radiation_msv = save->radiation_msv;
  session_game_alpha_prepare_navigation(ctx);
}

static void session_game_alpha_sync_to_save(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (!session_user_data_load(ctx)) {
    return;
  }

  alpha_centauri_save_t *save = &ctx->user_data.alpha;
  const alpha_centauri_game_state_t *state = &ctx->game.alpha;
  save->active = state->active ? 1U : 0U;
  save->stage = (uint8_t)(state->stage <= 4U ? state->stage : 0U);
  save->eva_ready = state->eva_ready ? 1U : 0U;
  save->awaiting_flag = state->awaiting_flag ? 1U : 0U;
  save->velocity_fraction_c = state->velocity_fraction_c;
  save->distance_travelled_ly = state->distance_travelled_ly;
  save->distance_remaining_ly = state->distance_remaining_ly;
  save->fuel_percent = state->fuel_percent;
  save->oxygen_days = state->oxygen_days;
  save->mission_time_years = state->mission_time_years;
  save->radiation_msv = state->radiation_msv;
  session_user_data_commit(ctx);
}

static void session_game_alpha_report_state(session_ctx_t *ctx, const char *label) {
  if (ctx == NULL) {
    return;
  }

  const alpha_centauri_game_state_t *state = &ctx->game.alpha;
  bool previous_translation = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;

  if (label != NULL && label[0] != '\0') {
    session_send_system_line(ctx, label);
  }

  double velocity_kms = state->velocity_fraction_c * ALPHA_SPEED_OF_LIGHT_MPS / 1000.0;
  double distance_au = state->distance_remaining_ly * ALPHA_LY_TO_AU;

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line),
           "Velocity: %.2f%% c (%.0f km/s) | Fuel %.1f%% | Radiation %.1f mSv",
           state->velocity_fraction_c * 100.0, velocity_kms, state->fuel_percent, state->radiation_msv);
  session_send_system_line(ctx, line);

  snprintf(line, sizeof(line),
           "Distance remaining: %.2f ly (%.0f AU) | Oxygen %.0f days | Mission clock %.2f years",
           state->distance_remaining_ly, distance_au, state->oxygen_days, state->mission_time_years);
  session_send_system_line(ctx, line);

  ctx->translation_suppress_output = previous_translation;
}

static const char *session_game_alpha_phase_label(const alpha_centauri_game_state_t *state) {
  if (state == NULL) {
    return "Guidance";
  }

  switch (state->stage) {
    case 0:
      return "Launch corridor beacon";
    case 1:
      return "Barycenter alignment";
    case 2:
      return "Turnover marker";
    case 3:
      return "Retro burn beacon";
    case 4:
      if (!state->eva_ready) {
        return "Deorbit corridor";
      }
      if (state->awaiting_flag) {
        return "Landing beacon";
      }
      return "Orbit standby";
    default:
      break;
  }
  return "Guidance";
}

static void session_game_alpha_render_navigation(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  const alpha_centauri_game_state_t *state = &ctx->game.alpha;
  const char *phase_label = session_game_alpha_phase_label(state);

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Guidance: %s (stability %u/%u — Alt+L to lock)", phase_label,
           state->nav_stable_ticks, state->nav_required_ticks);
  session_send_system_line(ctx, header);

  char border[ALPHA_NAV_WIDTH + 3];
  border[0] = '+';
  for (int idx = 0; idx < ALPHA_NAV_WIDTH; ++idx) {
    border[idx + 1] = '-';
  }
  border[ALPHA_NAV_WIDTH + 1] = '+';
  border[ALPHA_NAV_WIDTH + 2] = '\0';
  session_send_system_line(ctx, border);

  for (int y = 0; y < ALPHA_NAV_HEIGHT; ++y) {
    char row[ALPHA_NAV_WIDTH + 1];
    for (int x = 0; x < ALPHA_NAV_WIDTH; ++x) {
      row[x] = '.';
    }

    for (unsigned idx = 0U; idx < state->gravity_source_count; ++idx) {
      const alpha_gravity_source_t *source = &state->gravity_sources[idx];
      if (source->x >= 0 && source->x < ALPHA_NAV_WIDTH && source->y == y) {
        char symbol = source->symbol != '\0' ? source->symbol : 'G';
        row[source->x] = symbol;
      }
    }

    if (state->nav_target_x >= 0 && state->nav_target_x < ALPHA_NAV_WIDTH && state->nav_target_y >= 0 &&
        state->nav_target_y < ALPHA_NAV_HEIGHT && y == state->nav_target_y) {
      row[state->nav_target_x] = '+';
    }

    if (state->nav_x >= 0 && state->nav_x < ALPHA_NAV_WIDTH && state->nav_y >= 0 && state->nav_y < ALPHA_NAV_HEIGHT &&
        y == state->nav_y) {
      if (state->nav_target_x == state->nav_x && state->nav_target_y == state->nav_y) {
        row[state->nav_x] = '*';
      } else {
        row[state->nav_x] = '@';
      }
    }

    char line[ALPHA_NAV_WIDTH + 4];
    line[0] = '|';
    for (int x = 0; x < ALPHA_NAV_WIDTH; ++x) {
      line[x + 1] = row[x];
    }
    line[ALPHA_NAV_WIDTH + 1] = '|';
    line[ALPHA_NAV_WIDTH + 2] = '\0';
    session_send_system_line(ctx, line);
  }

  session_send_system_line(ctx, border);

  if (state->gravity_source_count > 0U) {
    char gravity_line[SSH_CHATTER_MESSAGE_LIMIT];
    int written = snprintf(gravity_line, sizeof(gravity_line), "Gravity wells: ");
    size_t offset = 0U;
    if (written >= 0) {
      offset = (size_t)written;
      if (offset >= sizeof(gravity_line)) {
        offset = sizeof(gravity_line) - 1U;
      }
    } else {
      gravity_line[0] = '\0';
    }

    for (unsigned idx = 0U; idx < state->gravity_source_count && offset < sizeof(gravity_line) - 1U; ++idx) {
      const alpha_gravity_source_t *source = &state->gravity_sources[idx];
      const char *name = source->name[0] != '\0' ? source->name : "Gravity Source";
      char symbol = source->symbol != '\0' ? source->symbol : 'G';
      written = snprintf(gravity_line + offset, sizeof(gravity_line) - offset, "%s%c=%s(μ=%.2e)",
                         idx == 0U ? "" : ", ", symbol, name, source->mu);
      if (written < 0) {
        break;
      }
      if ((size_t)written >= sizeof(gravity_line) - offset) {
        offset = sizeof(gravity_line) - 1U;
        break;
      }
      offset += (size_t)written;
    }

    gravity_line[sizeof(gravity_line) - 1U] = '\0';
    session_send_system_line(ctx, gravity_line);
  }
}

static void session_game_alpha_refresh_navigation(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  bool previous_translation = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;
  session_game_alpha_render_navigation(ctx);
  session_game_alpha_report_state(ctx, "Current status:");
  ctx->translation_suppress_output = previous_translation;
}

static void session_game_alpha_plan_waypoints(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  if (state->stage != 4U) {
    state->waypoint_count = 0U;
    state->waypoint_index = 0U;
    state->final_waypoint = (alpha_waypoint_t){0};
    return;
  }

  size_t name_count = sizeof(kAlphaWaystationNames) / sizeof(kAlphaWaystationNames[0]);

  if (!state->eva_ready && state->waypoint_count == 0U) {
    unsigned desired = ALPHA_MIN_WAYPOINTS;
    if (desired > ALPHA_MAX_WAYPOINTS) {
      desired = ALPHA_MAX_WAYPOINTS;
    }
    state->waypoint_count = desired;
    state->waypoint_index = 0U;

    for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
      int x = 0;
      int y = 0;
      bool placed = false;
      for (unsigned attempt = 0U; attempt < 96U && !placed; ++attempt) {
        x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, ALPHA_NAV_MARGIN);
        y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, ALPHA_NAV_MARGIN);
        bool conflict = false;
        for (unsigned prior = 0U; prior < idx; ++prior) {
          const alpha_waypoint_t *existing = &state->waypoints[prior];
          if (existing->x == x && existing->y == y) {
            conflict = true;
            break;
          }
        }
        if (!conflict) {
          placed = true;
        }
      }
      if (!placed) {
        x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, ALPHA_NAV_MARGIN);
        y = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_HEIGHT, ALPHA_NAV_MARGIN);
      }

      alpha_waypoint_t *waypoint = &state->waypoints[idx];
      waypoint->x = x;
      waypoint->y = y;
      waypoint->symbol = (char)('1' + (idx % 9));
      waypoint->visited = false;
      const char *name = name_count > 0 ? kAlphaWaystationNames[idx % name_count] : "Waystation";
      snprintf(waypoint->name, sizeof(waypoint->name), "%s", name);
    }
  } else if (!state->eva_ready) {
    for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
      alpha_waypoint_t *waypoint = &state->waypoints[idx];
      if (waypoint->symbol == '\0') {
        waypoint->symbol = (char)('1' + (idx % 9));
      }
    }
  }

  if (state->final_waypoint.symbol == '\0') {
    int x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, ALPHA_NAV_MARGIN);
    int y = ALPHA_NAV_HEIGHT - 1 - session_game_random_range(ctx, ALPHA_NAV_MARGIN + 4);
    for (unsigned attempt = 0U; attempt < 96U; ++attempt) {
      bool conflict = false;
      for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
        const alpha_waypoint_t *waypoint = &state->waypoints[idx];
        if (waypoint->x == x && waypoint->y == y) {
          conflict = true;
          break;
        }
      }
      if (!conflict) {
        break;
      }
      x = session_game_alpha_random_with_margin(ctx, ALPHA_NAV_WIDTH, ALPHA_NAV_MARGIN);
      y = ALPHA_NAV_HEIGHT - 1 - session_game_random_range(ctx, ALPHA_NAV_MARGIN + 4);
    }

    state->final_waypoint.x = x;
    state->final_waypoint.y = y;
    state->final_waypoint.symbol = 'P';
    state->final_waypoint.visited = false;
    snprintf(state->final_waypoint.name, sizeof(state->final_waypoint.name), "%s", "Proxima Landing");
  }
}

static void session_game_alpha_present_waypoints(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  if (state->stage != 4U) {
    return;
  }

  if (!state->eva_ready) {
    if (state->waypoint_count == 0U) {
      session_send_system_line(ctx, "Waystation manifest pending — reroll if the corridor looks blocked.");
      return;
    }

    session_send_system_line(ctx, "Waystation manifest:");
    for (unsigned idx = 0U; idx < state->waypoint_count; ++idx) {
      const alpha_waypoint_t *waypoint = &state->waypoints[idx];
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "  [%c] %c — %s%s", waypoint->visited ? 'x' : ' ', waypoint->symbol, waypoint->name,
               idx == state->waypoint_index ? " ← current objective" : "");
      session_send_system_line(ctx, line);
    }

    char landing[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(landing, sizeof(landing),
             "Final descent: P — %s unlocks after the last waystation. Hold the landing for 3 nav ticks, then press"
             " Alt+L to finish.",
             state->final_waypoint.name[0] != '\0' ? state->final_waypoint.name : "Proxima Landing");
    session_send_system_line(ctx, landing);
    return;
  }

  if (state->awaiting_flag) {
    char landing[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(landing, sizeof(landing), "Final target: P — %s. Hold for %u nav ticks, then press Alt+L or type 'plant"
                                        " flag' to finish.",
             state->final_waypoint.name[0] != '\0' ? state->final_waypoint.name : "Proxima Landing",
             state->nav_required_ticks);
    session_send_system_line(ctx, landing);
  }
}

static void session_game_alpha_complete_waypoint(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  if (state->stage != 4U || state->eva_ready) {
    return;
  }

  if (state->waypoint_index >= state->waypoint_count) {
    session_game_alpha_execute_eva(ctx);
    return;
  }

  alpha_waypoint_t *current = &state->waypoints[state->waypoint_index];
  current->visited = true;
  ++state->waypoint_index;
  state->nav_stable_ticks = 0U;

  if (state->waypoint_index >= state->waypoint_count) {
    session_send_system_line(ctx, "Waystations secured. Setting the descent beacon...");
    state->waypoint_index = state->waypoint_count;
    session_game_alpha_execute_eva(ctx);
    return;
  }

  const alpha_waypoint_t *next = &state->waypoints[state->waypoint_index];
  state->nav_target_x = next->x;
  state->nav_target_y = next->y;
  state->nav_required_ticks = 4U;
  state->nav_fx = (double)state->nav_x;
  state->nav_fy = (double)state->nav_y;
  state->nav_vx = 0.0;
  state->nav_vy = 0.0;

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Next stop %u/%u — marker %c (%s).", state->waypoint_index + 1U,
           state->waypoint_count, next->symbol, next->name);
  session_send_system_line(ctx, message);
  session_game_alpha_refresh_navigation(ctx);
}

static void session_game_alpha_present_stage(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  bool previous_translation = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;

  session_render_separator(ctx, "Alpha Centauri Expedition");

  char stage_line[SSH_CHATTER_MESSAGE_LIMIT];
  switch (state->stage) {
    case 0:
      snprintf(stage_line, sizeof(stage_line),
               "Stage 0 — Launch stack ready. Ride the ascent beacon, hold steady for %u nav ticks, then press Alt+L"
               " to ignite the antimatter booster.",
               state->nav_required_ticks);
      session_send_system_line(ctx, stage_line);
      break;
    case 1:
      snprintf(stage_line, sizeof(stage_line),
               "Stage 1 — Mid-course trim. Hold the barycenter beacon for %u nav ticks, then press Alt+L to bank the"
               " correction burn.",
               state->nav_required_ticks);
      session_send_system_line(ctx, stage_line);
      break;
    case 2:
      snprintf(stage_line, sizeof(stage_line),
               "Stage 2 — Turnover. Keep the retrograde marker centered for %u nav ticks, then press Alt+L to flip"
               " into braking attitude.",
               state->nav_required_ticks);
      session_send_system_line(ctx, stage_line);
      break;
    case 3:
      snprintf(stage_line, sizeof(stage_line),
               "Stage 3 — Braking burn. Bleed velocity by holding the braking beacon for %u nav ticks, then press"
               " Alt+L to lock the burn.",
               state->nav_required_ticks);
      session_send_system_line(ctx, stage_line);
      break;
    case 4:
      if (!state->eva_ready) {
        unsigned remaining = 0U;
        if (state->waypoint_count > state->waypoint_index) {
          remaining = state->waypoint_count - state->waypoint_index;
        }
        snprintf(stage_line, sizeof(stage_line),
                 "Stage 4 — High orbit over Proxima b. Visit the numbered waystations, hold each for %u nav ticks,"
                 " then press Alt+L. %u stop(s) remain before descent.",
                 state->nav_required_ticks, remaining);
        session_send_system_line(ctx, stage_line);
      } else if (state->awaiting_flag) {
        snprintf(stage_line, sizeof(stage_line),
                 "Stage 4 — Surface EVA. Settle on marker %c (%s) for %u nav ticks, then press Alt+L or type 'plant"
                 " flag' to plant \"Immigrants' Flag\".",
                 state->final_waypoint.symbol != '\0' ? state->final_waypoint.symbol : 'P',
                 state->final_waypoint.name[0] != '\0' ? state->final_waypoint.name : "Proxima Landing",
                 state->nav_required_ticks);
        session_send_system_line(ctx, stage_line);
      } else {
        session_send_system_line(ctx,
                                 "Stage 4 — Mission reset. Realign with the beacons for another run or exit with /suspend!.");
      }
      session_game_alpha_present_waypoints(ctx);
      break;
    default:
      session_send_system_line(ctx, "Awaiting next burn sequence.");
      break;
  }

  if (state->stage == 4U) {
    session_send_system_line(ctx,
                             "Route markers: 1–9 mark required waystations; P marks the Proxima landing zone.");
    session_send_system_line(ctx,
                             "Gravitational pulls: B=black hole, S=star, D=debris — each mass tugs with its own μ.");
  } else {
    session_send_system_line(ctx,
                             "Gravitational pulls: B=black hole, S=star, P=planet, D=debris — each mass tugs with its own μ.");
  }
  session_game_alpha_render_navigation(ctx);
  if (state->stage == 4U) {
    session_send_system_line(ctx,
                             "Legend: @ craft, + beacon, * locked alignment, digits=waystations, P final landing, B black"
                             " hole, S star, D debris.");
  } else {
    session_send_system_line(ctx,
                             "Legend: @ craft, + beacon, * locked alignment, B black hole, S star, P planet, D debris.");
  }
  session_send_system_line(ctx, "Navigation grid spans 60×60 sectors; each maneuver reshuffles the gravity field.");
  session_send_system_line(ctx, "Use arrow keys to nudge the craft and keep it steady over the beacon.");
  session_send_system_line(ctx,
                           "Press Alt+L once aligned to lock the maneuver; press Ctrl+S anytime to save the mission log.");
  session_send_system_line(ctx, "Stuck? Type 'reset' to reroll the field with a fresh gravimetric solution.");
  session_game_alpha_report_state(ctx, "Current status:");
  ctx->translation_suppress_output = previous_translation;
}

static void session_game_alpha_log_completion(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->velocity_fraction_c = 0.0;
  state->distance_travelled_ly = ALPHA_TOTAL_DISTANCE_LY;
  state->distance_remaining_ly = 0.0;
  if (state->fuel_percent > 5.0) {
    state->fuel_percent = 5.0;
  }
  if (state->oxygen_days > 20.0) {
    state->oxygen_days -= 20.0;
  } else {
    state->oxygen_days = 0.0;
  }
  state->mission_time_years += 0.05;
  state->radiation_msv += 5.0;
  state->eva_ready = true;
  state->awaiting_flag = false;

  double total_years = state->mission_time_years;
  double total_radiation = state->radiation_msv;

  if (session_user_data_load(ctx)) {
    ctx->user_data.flag_count += 1U;
    uint64_t timestamp = (uint64_t)time(NULL);
    if (ctx->user_data.flag_history_count < USER_DATA_FLAG_HISTORY_LIMIT) {
      ctx->user_data.flag_history[ctx->user_data.flag_history_count++] = timestamp;
    } else {
      for (size_t idx = 1U; idx < USER_DATA_FLAG_HISTORY_LIMIT; ++idx) {
        ctx->user_data.flag_history[idx - 1U] = ctx->user_data.flag_history[idx];
      }
      ctx->user_data.flag_history[USER_DATA_FLAG_HISTORY_LIMIT - 1U] = timestamp;
    }
  }

  bool previous_translation = ctx->translation_suppress_output;
  ctx->translation_suppress_output = true;

  char success[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(success, sizeof(success),
           "Mission complete! \"Immigrants' Flag\" is registered for %s. Flight time %.2f years, exposure %.1f mSv.",
           ctx->user.name, total_years, total_radiation);
  session_send_system_line(ctx, success);

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [alpha-centauri] Immigrants' Flag planted by %s.", ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);

  ctx->translation_suppress_output = previous_translation;

  session_game_alpha_reset(ctx);
  state->active = true;
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_execute_ignite(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || ctx->game.alpha.stage != 0U) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->stage = 1U;
  state->active = true;
  state->velocity_fraction_c = 0.04;
  state->distance_travelled_ly = 0.05;
  state->distance_remaining_ly = ALPHA_TOTAL_DISTANCE_LY - state->distance_travelled_ly;
  state->fuel_percent = 82.0;
  if (state->oxygen_days > 10.0) {
    state->oxygen_days -= 10.0;
  }
  state->mission_time_years += 0.02;
  state->radiation_msv += 12.0;
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_execute_trim(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || ctx->game.alpha.stage != 1U) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->stage = 2U;
  state->velocity_fraction_c = 0.18;
  state->distance_travelled_ly = 1.90;
  state->distance_remaining_ly = ALPHA_TOTAL_DISTANCE_LY - state->distance_travelled_ly;
  state->fuel_percent = 58.0;
  if (state->oxygen_days > 110.0) {
    state->oxygen_days -= 110.0;
  } else {
    state->oxygen_days = 0.0;
  }
  state->mission_time_years += 0.55;
  state->radiation_msv += 28.0;
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_execute_flip(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || ctx->game.alpha.stage != 2U) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->stage = 3U;
  state->distance_travelled_ly = 3.60;
  state->distance_remaining_ly = ALPHA_TOTAL_DISTANCE_LY - state->distance_travelled_ly;
  state->fuel_percent = 45.0;
  if (state->oxygen_days > 220.0) {
    state->oxygen_days -= 220.0;
  } else {
    state->oxygen_days = 0.0;
  }
  state->mission_time_years += 1.80;
  state->radiation_msv += 18.0;
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_execute_retro(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || ctx->game.alpha.stage != 3U) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->stage = 4U;
  state->velocity_fraction_c = 0.01;
  state->distance_travelled_ly = 4.22;
  state->distance_remaining_ly = ALPHA_TOTAL_DISTANCE_LY - state->distance_travelled_ly;
  state->fuel_percent = 18.0;
  if (state->oxygen_days > 150.0) {
    state->oxygen_days -= 150.0;
  } else {
    state->oxygen_days = 0.0;
  }
  state->mission_time_years += 1.20;
  state->radiation_msv += 12.0;
  state->eva_ready = false;
  state->awaiting_flag = false;
  state->waypoint_index = 0U;
  state->waypoint_count = 0U;
  state->final_waypoint = (alpha_waypoint_t){0};
  session_game_alpha_plan_waypoints(ctx);
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_game_alpha_execute_eva(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || ctx->game.alpha.stage != 4U ||
      ctx->game.alpha.eva_ready) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  state->eva_ready = true;
  state->awaiting_flag = true;
  state->waypoint_index = state->waypoint_count;
  if (state->oxygen_days > 30.0) {
    state->oxygen_days -= 30.0;
  } else {
    state->oxygen_days = 0.0;
  }
  state->mission_time_years += 0.05;
  state->radiation_msv += 6.0;
  session_game_alpha_prepare_navigation(ctx);
  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static bool session_game_alpha_attempt_completion(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return false;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  if (state->nav_required_ticks == 0U) {
    state->nav_required_ticks = 1U;
  }

  if (state->nav_stable_ticks < state->nav_required_ticks) {
    return false;
  }

  if (state->stage == 0U) {
    session_game_alpha_execute_ignite(ctx);
    return true;
  }
  if (state->stage == 1U) {
    session_game_alpha_execute_trim(ctx);
    return true;
  }
  if (state->stage == 2U) {
    session_game_alpha_execute_flip(ctx);
    return true;
  }
  if (state->stage == 3U) {
    session_game_alpha_execute_retro(ctx);
    return true;
  }
  if (state->stage == 4U) {
    if (!state->eva_ready) {
      session_game_alpha_complete_waypoint(ctx);
      return true;
    }
    if (state->awaiting_flag) {
      state->final_waypoint.visited = true;
      session_game_alpha_log_completion(ctx);
      return true;
    }
  }

  return false;
}

static void session_game_alpha_manual_lock(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  if (state->nav_x != state->nav_target_x || state->nav_y != state->nav_target_y) {
    session_send_system_line(ctx, "Lock failed: align with the beacon before pressing Alt+L.");
    session_game_alpha_refresh_navigation(ctx);
    return;
  }

  if (state->nav_required_ticks == 0U) {
    state->nav_required_ticks = 1U;
  }

  if (state->nav_stable_ticks < state->nav_required_ticks) {
    unsigned remaining = state->nav_required_ticks - state->nav_stable_ticks;
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Hold steady for %u more nav tick%s before locking.", remaining,
             (remaining == 1U) ? "" : "s");
    session_send_system_line(ctx, message);
    session_game_alpha_refresh_navigation(ctx);
    return;
  }

  if (!session_game_alpha_attempt_completion(ctx)) {
    session_send_system_line(ctx, "Alignment steady; mission control awaiting confirmation.");
    session_game_alpha_refresh_navigation(ctx);
  }
}

static void session_game_alpha_manual_save(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA) {
    return;
  }

  session_game_alpha_sync_to_save(ctx);
  session_send_system_line(ctx, "Mission log saved. Press Alt+L once stable to lock the maneuver.");
}

static bool session_game_alpha_handle_arrow(session_ctx_t *ctx, int dx, int dy) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return false;
  }

  if (dx == 0 && dy == 0) {
    return false;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;

  state->nav_vx += (double)dx * ALPHA_THRUST_DELTA;
  state->nav_vy += (double)dy * ALPHA_THRUST_DELTA;
  state->nav_fx += (double)dx * ALPHA_THRUST_POSITION_STEP;
  state->nav_fy += (double)dy * ALPHA_THRUST_POSITION_STEP;

  double max_x = (double)(ALPHA_NAV_WIDTH - 1);
  double max_y = (double)(ALPHA_NAV_HEIGHT - 1);
  if (state->nav_fx < 0.0) {
    state->nav_fx = 0.0;
    state->nav_vx = 0.0;
  } else if (state->nav_fx > max_x) {
    state->nav_fx = max_x;
    state->nav_vx = 0.0;
  }
  if (state->nav_fy < 0.0) {
    state->nav_fy = 0.0;
    state->nav_vy = 0.0;
  } else if (state->nav_fy > max_y) {
    state->nav_fy = max_y;
    state->nav_vy = 0.0;
  }

  state->nav_x = (int)lround(state->nav_fx);
  state->nav_y = (int)lround(state->nav_fy);
  if (state->nav_x < 0) {
    state->nav_x = 0;
  } else if (state->nav_x >= ALPHA_NAV_WIDTH) {
    state->nav_x = ALPHA_NAV_WIDTH - 1;
  }
  if (state->nav_y < 0) {
    state->nav_y = 0;
  } else if (state->nav_y >= ALPHA_NAV_HEIGHT) {
    state->nav_y = ALPHA_NAV_HEIGHT - 1;
  }

  session_game_alpha_apply_gravity(state);

  if (state->nav_x == state->nav_target_x && state->nav_y == state->nav_target_y) {
    if (state->nav_stable_ticks < state->nav_required_ticks) {
      ++state->nav_stable_ticks;
    }
  } else {
    state->nav_stable_ticks = 0U;
  }

  bool completed = session_game_alpha_attempt_completion(ctx);
  if (!completed) {
    session_game_alpha_refresh_navigation(ctx);
  }

  return true;
}

static void session_game_alpha_handle_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || ctx->game.type != SESSION_GAME_ALPHA || !ctx->game.active) {
    return;
  }

  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  char command[SSH_CHATTER_MAX_INPUT_LEN];
  if (line == NULL) {
    command[0] = '\0';
  } else {
    snprintf(command, sizeof(command), "%s", line);
  }
  trim_whitespace_inplace(command);

  if (command[0] == '\0') {
    session_game_alpha_refresh_navigation(ctx);
    return;
  }

  if (strcasecmp(command, "lock") == 0 || strcasecmp(command, "align lock") == 0) {
    session_game_alpha_manual_lock(ctx);
    return;
  }

  if (strcasecmp(command, "save") == 0 || strcasecmp(command, "log") == 0) {
    session_game_alpha_manual_save(ctx);
    return;
  }

  if (strcasecmp(command, "reset") == 0 || strcasecmp(command, "reroll") == 0 ||
      strcasecmp(command, "rescan") == 0) {
    session_game_alpha_reroll_navigation(ctx);
    return;
  }

  if (state->stage == 0U) {
    if (strcasecmp(command, "ignite") == 0 || strcasecmp(command, "launch") == 0) {
      session_game_alpha_execute_ignite(ctx);
    } else {
      session_send_system_line(ctx, "Line up with the ascent beacon using arrow keys or type 'ignite'.");
      session_game_alpha_refresh_navigation(ctx);
    }
    return;
  }

  if (state->stage == 1U) {
    if (strcasecmp(command, "trim") == 0 || strcasecmp(command, "align") == 0) {
      session_game_alpha_execute_trim(ctx);
    } else {
      session_send_system_line(ctx, "Hold the barycenter beacon with arrow keys or type 'trim'.");
      session_game_alpha_refresh_navigation(ctx);
    }
    return;
  }

  if (state->stage == 2U) {
    if (strcasecmp(command, "flip") == 0 || strcasecmp(command, "turnover") == 0) {
      session_game_alpha_execute_flip(ctx);
    } else {
      session_send_system_line(ctx, "Rotate into retrograde by holding the marker with arrow keys or type 'flip'.");
      session_game_alpha_refresh_navigation(ctx);
    }
    return;
  }

  if (state->stage == 3U) {
    if (strcasecmp(command, "retro") == 0 || strcasecmp(command, "brake") == 0) {
      session_game_alpha_execute_retro(ctx);
    } else {
      session_send_system_line(ctx, "Drop onto the braking beacon with arrow keys or type 'retro'.");
      session_game_alpha_refresh_navigation(ctx);
    }
    return;
  }

  if (state->stage == 4U) {
    if (!state->eva_ready) {
      if (state->waypoint_index < state->waypoint_count) {
        const alpha_waypoint_t *target = &state->waypoints[state->waypoint_index];
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(message, sizeof(message),
                 "Route checkpoint %u/%u — hold marker %c (%s) for %u nav ticks, then press Alt+L to proceed.",
                 state->waypoint_index + 1U, state->waypoint_count, target->symbol, target->name,
                 state->nav_required_ticks);
        session_send_system_line(ctx, message);
        session_game_alpha_refresh_navigation(ctx);
      } else {
        session_send_system_line(ctx,
                                 "Waystations cleared. Hold position on the descent beacon and press Alt+L to trigger EVA.");
        session_game_alpha_refresh_navigation(ctx);
      }
    } else if (state->awaiting_flag) {
      if (strcasecmp(command, "plant") == 0 || strcasecmp(command, "plant flag") == 0 ||
          strcasecmp(command, "flag") == 0) {
        session_game_alpha_log_completion(ctx);
      } else {
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(message, sizeof(message),
                 "Hold marker %c (%s) for %u nav ticks, then press Alt+L or type 'plant flag' to finish.",
                 state->final_waypoint.symbol != '\0' ? state->final_waypoint.symbol : 'P',
                 state->final_waypoint.name[0] != '\0' ? state->final_waypoint.name : "Proxima Landing",
                 state->nav_required_ticks);
        session_send_system_line(ctx, message);
        session_game_alpha_refresh_navigation(ctx);
      }
    } else {
      session_send_system_line(ctx, "Launch again with 'ignite' or exit with /suspend!.");
      session_game_alpha_refresh_navigation(ctx);
    }
    return;
  }

  session_send_system_line(ctx, "Hold position for the next maneuver.");
  session_game_alpha_refresh_navigation(ctx);
}

static void session_game_start_alpha(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (!session_user_data_load(ctx)) {
    session_send_system_line(ctx, "Profile storage unavailable; cannot start the mission.");
    return;
  }

  session_game_alpha_sync_from_save(ctx);
  alpha_centauri_game_state_t *state = &ctx->game.alpha;
  ctx->game.type = SESSION_GAME_ALPHA;
  ctx->game.active = true;
  state->active = true;

  if (state->stage == 0U) {
    session_send_system_line(ctx,
                             "Mission control: Alpha Centauri expedition primed. Complete each maneuver to reach Proxima b.");
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Mission control: Resuming expedition at stage %u.", state->stage);
    session_send_system_line(ctx, message);
  }

  session_game_alpha_sync_to_save(ctx);
  session_game_alpha_present_stage(ctx);
}

static void session_handle_game(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->game.active) {
    session_send_system_line(ctx, "Finish the current game with /suspend! first.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /game <tetris|liargame|alpha>");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);
  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /game <tetris|liargame|alpha>");
    return;
  }

  for (size_t idx = 0U; working[idx] != '\0'; ++idx) {
    working[idx] = (char)tolower((unsigned char)working[idx]);
  }

  if (strcmp(working, "tetris") == 0) {
    session_game_start_tetris(ctx);
  } else if (strcmp(working, "liargame") == 0) {
    session_game_start_liargame(ctx);
  } else if (strcmp(working, "alpha") == 0 || strcmp(working, "alphacentauri") == 0) {
    session_game_start_alpha(ctx);
  } else {
    session_send_system_line(ctx, "Unknown game. Available options: tetris, liargame, alpha.");
  }
}

static void session_game_suspend(session_ctx_t *ctx, const char *reason) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->game.active) {
    if (reason != NULL && reason[0] != '\0') {
      session_send_system_line(ctx, reason);
    } else {
      session_send_system_line(ctx, "There is no active game to suspend.");
    }
    return;
  }

  if (reason != NULL && reason[0] != '\0') {
    session_send_system_line(ctx, reason);
  }

  if (ctx->game.type == SESSION_GAME_TETRIS) {
    char summary[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(summary, sizeof(summary), "Tetris final score: %u (lines cleared: %u).", ctx->game.tetris.score,
             ctx->game.tetris.lines_cleared);
    session_send_system_line(ctx, summary);
    session_game_tetris_reset(&ctx->game.tetris);
  } else if (ctx->game.type == SESSION_GAME_LIARGAME) {
    char summary[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(summary, sizeof(summary), "Liar Game rounds played: %u, score: %u.", ctx->game.liar.round_number,
             ctx->game.liar.score);
    session_send_system_line(ctx, summary);
    ctx->game.liar.awaiting_guess = false;
    ctx->game.liar.round_number = 0U;
    ctx->game.liar.score = 0U;
  } else if (ctx->game.type == SESSION_GAME_ALPHA) {
    char summary[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(summary, sizeof(summary), "Alpha Centauri mission paused at stage %u with %.2f ly remaining.",
             ctx->game.alpha.stage, ctx->game.alpha.distance_remaining_ly);
    session_send_system_line(ctx, summary);
    session_game_alpha_reset(ctx);
    session_game_alpha_sync_to_save(ctx);
  }

  ctx->game.active = false;
  ctx->game.type = SESSION_GAME_NONE;
}

static int session_channel_read_poll(session_ctx_t *ctx, char *buffer, size_t length, int timeout_ms) {
  if (ctx == NULL || buffer == NULL || length == 0U || !session_transport_active(ctx)) {
    return SSH_ERROR;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    int result = session_transport_read(ctx, buffer, length, timeout_ms);
    if (result == SSH_AGAIN) {
      return SESSION_CHANNEL_TIMEOUT;
    }
    return result;
  }

  int fd = ssh_get_fd(ctx->session);
  if (fd < 0) {
    return session_transport_read(ctx, buffer, length, -1);
  }

  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  for (;;) {
    int poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result < 0) {
      if (errno == EINTR) {
        continue;
      }
      return SSH_ERROR;
    }
    if (poll_result == 0) {
      return SESSION_CHANNEL_TIMEOUT;
    }
    break;
  }

  if ((pfd.revents & POLLIN) == 0) {
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      return 0;
    }
    return SESSION_CHANNEL_TIMEOUT;
  }

  return session_transport_read(ctx, buffer, length, -1);
}

static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count) {
  if (working == NULL || tokens == NULL || token_count == NULL) {
    return false;
  }

  *token_count = 0U;
  bool extra_tokens = false;
  char *cursor = working;
  while (cursor != NULL) {
    char *next = strchr(cursor, ';');
    if (next != NULL) {
      *next = '\0';
    }

    trim_whitespace_inplace(cursor);
    if (cursor[0] == '\0') {
      return false;
    }

    if (*token_count < max_tokens) {
      tokens[*token_count] = cursor;
      ++(*token_count);
    } else if (cursor[0] != '\0') {
      extra_tokens = true;
    }

    if (next == NULL) {
      break;
    }

    cursor = next + 1;
    if (cursor[0] == '\0') {
      extra_tokens = true;
      break;
    }
  }

  return !extra_tokens;
}

static void session_handle_color(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  bool had_parentheses = false;
  if (working[0] == '(') {
    had_parentheses = true;
    memmove(working, working + 1, strlen(working));
    trim_whitespace_inplace(working);
  }

  if (had_parentheses) {
    size_t len = strlen(working);
    if (len == 0U || working[len - 1U] != ')') {
      session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
      return;
    }
    working[len - 1U] = '\0';
    trim_whitespace_inplace(working);
  }

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  char *tokens[3] = {0};
  size_t token_count = 0U;
  if (!session_parse_color_arguments(working, tokens, 3U, &token_count) || token_count < 2U) {
    session_send_system_line(ctx, "Usage: /color (text;highlight[;bold])");
    return;
  }

  const char *text_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), tokens[0]);
  if (text_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown text color '%s'.", tokens[0]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                                sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]),
                                                tokens[1]);
  if (highlight_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown highlight color '%s'.", tokens[1]);
    session_send_system_line(ctx, message);
    return;
  }

  bool is_bold = false;
  if (token_count == 3U) {
    if (!parse_bool_token(tokens[2], &is_bold)) {
      session_send_system_line(ctx, "The third value must describe bold (ex: bold, true, normal).");
      return;
    }
  }

  ctx->user_color_code = text_code;
  ctx->user_highlight_code = highlight_code;
  ctx->user_is_bold = is_bold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", tokens[0]);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", tokens[1]);

  char info[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(info, sizeof(info), "Handle colors updated: text=%s highlight=%s bold=%s", tokens[0], tokens[1],
           is_bold ? "on" : "off");
  session_send_system_line(ctx, info);

  const char *bold_code = is_bold ? ANSI_BOLD : "";
  char preview[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(preview, sizeof(preview), "%s%s%s[%s] preview%s", highlight_code, bold_code, text_code, ctx->user.name,
           ANSI_RESET);
  session_send_line(ctx, preview);

  if (ctx->owner != NULL) {
    host_store_user_theme(ctx->owner, ctx);
  }
}

static bool session_try_reload_motd_from_candidate_path(host_t *host, const char *candidate,
                                                        char *resolved_path, size_t resolved_len,
                                                        bool *path_exists_out, int *error_out) {
  if (resolved_path != NULL && resolved_len > 0U) {
    resolved_path[0] = '\0';
  }
  if (path_exists_out != NULL) {
    *path_exists_out = false;
  }
  if (error_out != NULL) {
    *error_out = 0;
  }
  if (host == NULL || candidate == NULL) {
    return false;
  }

  if (candidate[0] == '\0') {
    return false;
  }

  char trimmed[PATH_MAX];
  int copied = snprintf(trimmed, sizeof(trimmed), "%s", candidate);
  if (copied <= 0 || (size_t)copied >= sizeof(trimmed)) {
    return false;
  }

  trim_whitespace_inplace(trimmed);

  if (trimmed[0] == '\0') {
    return false;
  }

  if (strchr(trimmed, '\n') != NULL || strchr(trimmed, '\r') != NULL) {
    return false;
  }

  const size_t kMaxPaths = 2U;
  const char *paths_to_try[2] = {NULL, NULL};
  size_t path_count = 0U;

  char expanded[PATH_MAX];
  expanded[0] = '\0';
  if (trimmed[0] == '~' && (trimmed[1] == '\0' || trimmed[1] == '/')) {
    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0') {
      int expanded_written = snprintf(expanded, sizeof(expanded), "%s%s", home, trimmed + 1);
      if (expanded_written > 0 && (size_t)expanded_written < sizeof(expanded)) {
        paths_to_try[path_count++] = expanded;
      }
    }
  }

  if (path_count < kMaxPaths) {
    paths_to_try[path_count++] = trimmed;
  }

  for (size_t idx = 0U; idx < path_count; ++idx) {
    const char *path = paths_to_try[idx];
    if (path == NULL || path[0] == '\0') {
      continue;
    }

    if (host_try_load_motd_from_path(host, path)) {
      if (path_exists_out != NULL) {
        *path_exists_out = true;
      }
      if (resolved_path != NULL && resolved_len > 0U) {
        snprintf(resolved_path, resolved_len, "%s", path);
      }
      return true;
    }

    if (error_out != NULL && *error_out == 0) {
      const int load_error = errno;
      if (load_error != 0) {
        *error_out = load_error;
      }
    }

    struct stat info;
    if (stat(path, &info) == 0 && S_ISREG(info.st_mode)) {
      if (path_exists_out != NULL) {
        *path_exists_out = true;
      }
      if (resolved_path != NULL && resolved_len > 0U) {
        snprintf(resolved_path, resolved_len, "%s", path);
      }
    }
  }

  return false;
}

static void session_handle_motd(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_refresh_motd(ctx->owner);

  char motd[sizeof(ctx->owner->motd)];
  motd[0] = '\0';
  bool has_file = false;
  char configured_path[PATH_MAX];
  configured_path[0] = '\0';

  pthread_mutex_lock(&ctx->owner->lock);
  snprintf(motd, sizeof(motd), "%s", ctx->owner->motd);
  has_file = ctx->owner->motd_has_file;
  snprintf(configured_path, sizeof(configured_path), "%s", ctx->owner->motd_path);
  pthread_mutex_unlock(&ctx->owner->lock);

  bool config_path_exists = false;
  int config_error = 0;
  char resolved_path[PATH_MAX];
  resolved_path[0] = '\0';

  bool fallback_path_exists = false;
  int fallback_error = 0;
  char fallback_path[PATH_MAX];
  fallback_path[0] = '\0';

  if (!has_file) {
    if (configured_path[0] != '\0' &&
        session_try_reload_motd_from_candidate_path(ctx->owner, configured_path, resolved_path,
                                                    sizeof(resolved_path), &config_path_exists, &config_error)) {
      pthread_mutex_lock(&ctx->owner->lock);
      snprintf(motd, sizeof(motd), "%s", ctx->owner->motd);
      has_file = ctx->owner->motd_has_file;
      pthread_mutex_unlock(&ctx->owner->lock);
    } else if (resolved_path[0] == '\0' && configured_path[0] != '\0') {
      snprintf(resolved_path, sizeof(resolved_path), "%s", configured_path);
    }

    if (!has_file && motd[0] != '\0') {
      if (session_try_reload_motd_from_candidate_path(ctx->owner, motd, fallback_path, sizeof(fallback_path),
                                                      &fallback_path_exists, &fallback_error)) {
        pthread_mutex_lock(&ctx->owner->lock);
        snprintf(motd, sizeof(motd), "%s", ctx->owner->motd);
        has_file = ctx->owner->motd_has_file;
        pthread_mutex_unlock(&ctx->owner->lock);
      } else if (fallback_path[0] == '\0') {
        snprintf(fallback_path, sizeof(fallback_path), "%s", motd);
      }
    }
  }

  if (!has_file && configured_path[0] != '\0') {
    const char *failing_path = resolved_path[0] != '\0' ? resolved_path : configured_path;
    const bool any_path_exists = config_path_exists || fallback_path_exists;
    const int failing_error = config_error != 0 ? config_error : fallback_error;
    char warning[SSH_CHATTER_MESSAGE_LIMIT];
    if (failing_error != 0) {
      snprintf(warning, sizeof(warning), "Failed to load message of the day from %s: %s.", failing_path,
               strerror(failing_error));
    } else if (any_path_exists) {
      snprintf(warning, sizeof(warning), "Failed to load message of the day from %s.", failing_path);
    } else {
      snprintf(warning, sizeof(warning), "Message of the day file %s was not found.", failing_path);
    }
    session_send_system_line(ctx, warning);
    return;
  }

  if (!has_file && configured_path[0] == '\0' && fallback_path_exists) {
    const char *failing_path = fallback_path[0] != '\0' ? fallback_path : motd;
    char warning[SSH_CHATTER_MESSAGE_LIMIT];
    if (fallback_error != 0) {
      snprintf(warning, sizeof(warning), "Failed to load message of the day from %s: %s.", failing_path,
               strerror(fallback_error));
    } else {
      snprintf(warning, sizeof(warning), "Failed to load message of the day from %s.", failing_path);
    }
    session_send_system_line(ctx, warning);
    return;
  }

  if (motd[0] == '\0') {
    session_send_system_line(ctx, "No message of the day is configured.");
    return;
  }

  session_send_raw_text_bulk(ctx, motd);
}

static void session_handle_system_color(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage =
      "Usage: /systemcolor (fg;background[;highlight][;bold]) or /systemcolor reset - third value may be highlight or "
      "bold.";

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  bool had_parentheses = false;
  if (working[0] == '(') {
    had_parentheses = true;
    memmove(working, working + 1, strlen(working));
    trim_whitespace_inplace(working);
  }

  if (had_parentheses) {
    size_t len = strlen(working);
    if (len == 0U || working[len - 1U] != ')') {
      session_send_system_line(ctx, kUsage);
      return;
    }
    working[len - 1U] = '\0';
    trim_whitespace_inplace(working);
  }

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (strcasecmp(working, "reset") == 0) {
    session_apply_system_theme_defaults(ctx);
    session_send_system_line(ctx, "System colors reset to defaults.");
    session_render_separator(ctx, "Chatroom");
    session_render_prompt(ctx, true);
    if (ctx->owner != NULL) {
      host_store_system_theme(ctx->owner, ctx);
    }
    return;
  }

  char *tokens[4] = {0};
  size_t token_count = 0U;
  if (!session_parse_color_arguments(working, tokens, 4U, &token_count) || token_count < 2U) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  const char *fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), tokens[0]);
  if (fg_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown foreground color '%s'.", tokens[0]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *bg_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                          sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), tokens[1]);
  if (bg_code == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Unknown background color '%s'.", tokens[1]);
    session_send_system_line(ctx, message);
    return;
  }

  const char *highlight_code = ctx->system_highlight_code;
  bool highlight_updated = false;
  bool is_bold = ctx->system_is_bold;
  if (token_count >= 3U) {
    bool bool_value = false;
    if (parse_bool_token(tokens[2], &bool_value)) {
      if (token_count > 3U) {
        session_send_system_line(ctx, kUsage);
        return;
      }
      is_bold = bool_value;
    } else {
      highlight_code = lookup_color_code(HIGHLIGHT_COLOR_MAP,
                                         sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), tokens[2]);
      if (highlight_code == NULL) {
        char message[SSH_CHATTER_MESSAGE_LIMIT];
        snprintf(message, sizeof(message), "Unknown highlight color '%s'.", tokens[2]);
        session_send_system_line(ctx, message);
        return;
      }
      highlight_updated = true;

      if (token_count == 4U) {
        if (!parse_bool_token(tokens[3], &bool_value)) {
          session_send_system_line(ctx, "The last value must describe bold (ex: bold, true, normal).");
          return;
        }
        is_bold = bool_value;
      }
    }
  }

  ctx->system_fg_code = fg_code;
  ctx->system_bg_code = bg_code;
  ctx->system_highlight_code = highlight_code;
  ctx->system_is_bold = is_bold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", tokens[0]);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", tokens[1]);
  if (highlight_updated) {
    snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", tokens[2]);
  }

  session_force_dark_mode_foreground(ctx);
  session_apply_background_fill(ctx);

  session_send_system_line(ctx, "System colors updated.");
  session_render_separator(ctx, "Chatroom");
  session_render_prompt(ctx, true);
  if (ctx->owner != NULL) {
    host_store_system_theme(ctx->owner, ctx);
  }
}

static void session_handle_set_trans_lang(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  char working[SSH_CHATTER_LANG_NAME_LEN];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /set-trans-lang <language|off>");
    return;
  }

  if (session_argument_is_disable(working)) {
    ctx->output_translation_enabled = false;
    ctx->output_translation_language[0] = '\0';
    session_translation_clear_queue(ctx);
    session_send_system_line(ctx, "Terminal translation disabled.");
    if (ctx->owner != NULL) {
      host_store_translation_preferences(ctx->owner, ctx);
    }
    return;
  }

  if (session_language_equals(ctx->output_translation_language, working)) {
    snprintf(ctx->output_translation_language, sizeof(ctx->output_translation_language), "%s", working);
    ctx->output_translation_enabled = true;
    session_translation_clear_queue(ctx);

    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Terminal output will continue to be translated to %s.",
             ctx->output_translation_language);
    session_send_system_line(ctx, message);
    if (!ctx->translation_enabled) {
      session_send_system_line(ctx, "Translation is currently disabled; enable it with /translate on.");
    }
    if (ctx->owner != NULL) {
      host_store_translation_preferences(ctx->owner, ctx);
    }
    return;
  }

  char preview[SSH_CHATTER_MESSAGE_LIMIT];
  char detected[SSH_CHATTER_LANG_NAME_LEN];
  if (!translator_translate("Terminal messages will be translated for you.", working, preview, sizeof(preview), detected,
                            sizeof(detected))) {
    const char *error = translator_last_error();
    if (error != NULL && *error != '\0') {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Translation service error: %s", error);
      session_send_system_line(ctx, message);
    } else {
      session_send_system_line(ctx, "Failed to reach the translation service. Please try again later.");
    }
    return;
  }

  snprintf(ctx->output_translation_language, sizeof(ctx->output_translation_language), "%s", working);
  ctx->output_translation_enabled = true;
  session_translation_clear_queue(ctx);

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  int preview_limit = (int)(sizeof(message) / 2);
  if (preview_limit <= 0) {
    preview_limit = (int)sizeof(message) - 1;
  }
  int detected_limit = (int)sizeof(detected) - 1;
  if (detected_limit <= 0) {
    detected_limit = (int)sizeof(detected);
  }
  if (detected[0] != '\0') {
    snprintf(message, sizeof(message), "Terminal output will be translated to %s. Sample: %.*s (detected: %.*s).",
             ctx->output_translation_language, preview_limit, preview, detected_limit, detected);
  } else {
    snprintf(message, sizeof(message), "Terminal output will be translated to %s. Sample: %.*s.",
             ctx->output_translation_language, preview_limit, preview);
  }
  session_send_system_line(ctx, message);
  if (!ctx->translation_enabled) {
    session_send_system_line(ctx, "Translation is currently disabled; enable it with /translate on.");
  }
  if (ctx->owner != NULL) {
    host_store_translation_preferences(ctx->owner, ctx);
  }
}

static void session_handle_set_target_lang(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  char working[SSH_CHATTER_LANG_NAME_LEN];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /set-target-lang <language|off>");
    return;
  }

  if (session_argument_is_disable(working)) {
    ctx->input_translation_enabled = false;
    ctx->input_translation_language[0] = '\0';
    ctx->last_detected_input_language[0] = '\0';
    session_send_system_line(ctx, "Outgoing message translation disabled.");
    if (ctx->owner != NULL) {
      host_store_translation_preferences(ctx->owner, ctx);
    }
    return;
  }

  if (session_language_equals(ctx->input_translation_language, working)) {
    snprintf(ctx->input_translation_language, sizeof(ctx->input_translation_language), "%s", working);
    ctx->input_translation_enabled = true;
    ctx->last_detected_input_language[0] = '\0';

    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Outgoing messages will continue to be translated to %s.",
             ctx->input_translation_language);
    session_send_system_line(ctx, message);
    if (!ctx->translation_enabled) {
      session_send_system_line(ctx, "Translation is currently disabled; enable it with /translate on.");
    }
    if (ctx->owner != NULL) {
      host_store_translation_preferences(ctx->owner, ctx);
    }
    return;
  }

  char preview[SSH_CHATTER_MESSAGE_LIMIT];
  char detected[SSH_CHATTER_LANG_NAME_LEN];
  if (!translator_translate("Your messages will be translated before broadcasting.", working, preview, sizeof(preview),
                            detected, sizeof(detected))) {
    const char *error = translator_last_error();
    if (error != NULL && *error != '\0') {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Translation service error: %s", error);
      session_send_system_line(ctx, message);
    } else {
      session_send_system_line(ctx, "Failed to reach the translation service. Please try again later.");
    }
    return;
  }

  snprintf(ctx->input_translation_language, sizeof(ctx->input_translation_language), "%s", working);
  ctx->input_translation_enabled = true;
  ctx->last_detected_input_language[0] = '\0';

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  int preview_limit = (int)(sizeof(message) / 2);
  if (preview_limit <= 0) {
    preview_limit = (int)sizeof(message) - 1;
  }
  int detected_limit = (int)sizeof(detected) - 1;
  if (detected_limit <= 0) {
    detected_limit = (int)sizeof(detected);
  }
  if (detected[0] != '\0') {
    snprintf(message, sizeof(message), "Outgoing messages will be translated to %s. Sample: %.*s (detected: %.*s).",
             ctx->input_translation_language, preview_limit, preview, detected_limit, detected);
  } else {
    snprintf(message, sizeof(message), "Outgoing messages will be translated to %s. Sample: %.*s.",
             ctx->input_translation_language, preview_limit, preview);
  }
  session_send_system_line(ctx, message);
  if (!ctx->translation_enabled) {
    session_send_system_line(ctx, "Translation is currently disabled; enable it with /translate on.");
  }
  if (ctx->owner != NULL) {
    host_store_translation_preferences(ctx->owner, ctx);
  }
}

static void session_handle_chat_spacing(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /chat-spacing <0-5>";
  char working[16];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char *endptr = NULL;
  long value = strtol(working, &endptr, 10);
  if (endptr == working || (endptr != NULL && *endptr != '\0') || value < 0L || value > 5L) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  ctx->translation_caption_spacing = (size_t)value;

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  if (value == 0L) {
    snprintf(message, sizeof(message),
             "Translation captions will appear immediately without reserving extra blank lines.");
  } else if (value == 1L) {
    snprintf(message, sizeof(message),
             "Translation captions will reserve 1 blank line before appearing in chat threads.");
  } else {
    snprintf(message, sizeof(message),
             "Translation captions will reserve %ld blank lines before appearing in chat threads.", value);
  }
  session_send_system_line(ctx, message);

  if (ctx->owner != NULL) {
    host_store_chat_spacing(ctx->owner, ctx);
  }
}

static void session_handle_mode(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  const char *current_label = ctx->input_mode == SESSION_INPUT_MODE_COMMAND ? "command" : "chat";

  char working[32];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    char status_line[128];
    snprintf(status_line, sizeof(status_line), "Current input mode: %s.", current_label);
    session_send_system_line(ctx, status_line);
    if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
      session_send_system_line(ctx,
                               "Command mode: type commands without '/', use UpArrow/DownArrow for history, Tab for completion.");
    } else {
      session_send_system_line(ctx,
                               "Chat mode: send messages normally. Prefix commands with '/'. Switch with /mode command.");
    }
    return;
  }

  if (strcasecmp(working, "chat") == 0) {
    if (ctx->input_mode == SESSION_INPUT_MODE_CHAT) {
      session_send_system_line(ctx, "Already in chat mode. Commands require the '/' prefix.");
      return;
    }
    ctx->input_mode = SESSION_INPUT_MODE_CHAT;
    session_refresh_input_line(ctx);
    session_send_system_line(ctx, "Chat mode enabled. Commands once again require the '/' prefix.");
    return;
  }

  if (strcasecmp(working, "command") == 0) {
    if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
      session_send_system_line(ctx,
                               "Command mode already active. Enter commands without '/', use /DownArrow for history, Tab to autocomplete.");
      return;
    }
    ctx->input_mode = SESSION_INPUT_MODE_COMMAND;
    session_refresh_input_line(ctx);
    session_send_system_line(ctx,
                             "Command mode enabled. Enter commands without '/', use UpArrow/DownArrow for history and Tab for completion.");
    return;
  }

  if (strcasecmp(working, "toggle") == 0) {
    ctx->input_mode =
        (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) ? SESSION_INPUT_MODE_CHAT : SESSION_INPUT_MODE_COMMAND;
    session_refresh_input_line(ctx);
    if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
      session_send_system_line(ctx,
                               "Command mode enabled. Enter commands without '/', use UpArrow/DownArrow for history and Tab for completion.");
    } else {
      session_send_system_line(ctx, "Chat mode enabled. Commands once again require the '/' prefix.");
    }
    return;
  }

  session_send_system_line(ctx, "Usage: /mode <chat|command|toggle>");
}

typedef struct session_weather_buffer {
  char *data;
  size_t length;
} session_weather_buffer_t;

static size_t session_weather_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
  session_weather_buffer_t *buffer = (session_weather_buffer_t *)userp;
  const size_t total = size * nmemb;
  if (buffer == NULL || total == 0U) {
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

static bool session_fetch_weather_summary(const char *region, const char *city, char *summary, size_t summary_len) {
  if (region == NULL || city == NULL || summary == NULL || summary_len == 0U) {
    return false;
  }

  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    return false;
  }

  bool success = false;
  session_weather_buffer_t buffer = {0};
  char query[128];
  snprintf(query, sizeof(query), "%s %s", region, city);

  char *escaped = curl_easy_escape(curl, query, 0);
  if (escaped == NULL) {
    goto cleanup;
  }

  char url[512];
  static const char *kFormat = "%25l:%20%25C,%20%25t";
  int written = snprintf(url, sizeof(url), "https://wttr.in/%s?format=%s", escaped, kFormat);
  curl_free(escaped);
  if (written < 0 || (size_t)written >= sizeof(url)) {
    goto cleanup;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, session_weather_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

  CURLcode result = curl_easy_perform(curl);
  if (result != CURLE_OK) {
    goto cleanup;
  }

  long status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  if (status < 200L || status >= 300L || buffer.data == NULL) {
    goto cleanup;
  }

  char *trimmed = buffer.data;
  while (*trimmed != '\0' && isspace((unsigned char)*trimmed)) {
    ++trimmed;
  }
  size_t end = strlen(trimmed);
  while (end > 0U && isspace((unsigned char)trimmed[end - 1U])) {
    trimmed[--end] = '\0';
  }

  if (trimmed[0] == '\0') {
    goto cleanup;
  }

  snprintf(summary, summary_len, "%s", trimmed);
  success = true;

cleanup:
  free(buffer.data);
  curl_easy_cleanup(curl);
  return success;
}

static void session_handle_status(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /status <message|clear>";
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char working[SSH_CHATTER_STATUS_LEN];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  if (session_argument_is_disable(working) || strcasecmp(working, "clear") == 0) {
    ctx->status_message[0] = '\0';
    session_send_system_line(ctx, "Status cleared.");
    return;
  }

  snprintf(ctx->status_message, sizeof(ctx->status_message), "%s", working);
  session_send_system_line(ctx, "Status updated.");
}

static void session_handle_showstatus(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /showstatus <username>";
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, message);
    return;
  }

  if (target->status_message[0] == '\0') {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "[%s] has not set a status.", target->user.name);
    session_send_system_line(ctx, message);
    return;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "[%s]'s status: %s", target->user.name, target->status_message);
  session_send_system_line(ctx, message);
}

static void session_handle_weather(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /weather <region> <city>";
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  const char *cursor = arguments;
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  size_t region_len = (size_t)(cursor - arguments);
  char region[64];
  if (region_len >= sizeof(region)) {
    session_send_system_line(ctx, "Region name is too long.");
    return;
  }
  memcpy(region, arguments, region_len);
  region[region_len] = '\0';
  trim_whitespace_inplace(region);

  while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char city[64];
  snprintf(city, sizeof(city), "%s", cursor);
  trim_whitespace_inplace(city);

  if (region[0] == '\0' || city[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char summary[256];
  if (!session_fetch_weather_summary(region, city, summary, sizeof(summary))) {
    session_send_system_line(ctx, "Failed to fetch weather information. Please try again later.");
    return;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%s", summary);
  session_send_system_line(ctx, message);
}

static void session_handle_translate(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  char working[16];
  if (arguments == NULL) {
    working[0] = '\0';
  } else {
    snprintf(working, sizeof(working), "%s", arguments);
  }
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, "Usage: /translate <on|off>");
    return;
  }

  if (session_argument_is_disable(working)) {
    ctx->translation_enabled = false;
    ctx->translation_quota_notified = false;
    session_translation_clear_queue(ctx);
    session_send_system_line(ctx, "Translation disabled. New messages will be delivered without translation.");
    if (ctx->owner != NULL) {
      host_store_translation_preferences(ctx->owner, ctx);
    }
    return;
  }

  bool enabled = false;
  if (!parse_bool_token(working, &enabled)) {
    if (strcasecmp(working, "enable") == 0 || strcasecmp(working, "enabled") == 0) {
      enabled = true;
    } else {
      session_send_system_line(ctx, "Usage: /translate <on|off>");
      return;
    }
  }

  ctx->translation_enabled = enabled;
  ctx->translation_quota_notified = false;
  if (enabled) {
    session_send_system_line(ctx, "Translation enabled. Configure directions with /set-trans-lang or /set-target-lang.");
  } else {
    session_translation_clear_queue(ctx);
    session_send_system_line(ctx, "Translation disabled. New messages will be delivered without translation.");
  }
  if (ctx->owner != NULL) {
    host_store_translation_preferences(ctx->owner, ctx);
  }
}

static void session_handle_translate_scope(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may manage translation scope.");
    return;
  }

  char token[16];
  token[0] = '\0';
  if (arguments != NULL) {
    const char *cursor = arguments;
    while (*cursor == ' ' || *cursor == '\t') {
      ++cursor;
    }

    size_t length = 0U;
    while (cursor[length] != '\0' && !isspace((unsigned char)cursor[length]) && length + 1U < sizeof(token)) {
      token[length] = cursor[length];
      ++length;
    }
    token[length] = '\0';
  }

  if (token[0] == '\0') {
    const bool limited = translator_should_limit_to_chat_bbs();
    const bool forced = translator_is_ollama_only();
    const bool manual = translator_is_manual_chat_bbs_only();
    const bool skip_scrollback = translator_is_manual_skip_scrollback();

    char status[SSH_CHATTER_MESSAGE_LIMIT];
    if (limited) {
      if (skip_scrollback) {
        snprintf(status, sizeof(status),
                 "Translation scope is currently limited to chat messages and BBS posts. Scrollback translation is disabled.");
      } else {
        snprintf(status, sizeof(status), "Translation scope is currently limited to chat messages and BBS posts.");
      }
    } else {
      snprintf(status, sizeof(status),
               "Translation scope currently includes system output and bulk messages.");
    }
    session_send_system_line(ctx, status);

    if (forced) {
      session_send_system_line(ctx,
                               "Gemini translation is unavailable; Ollama fallback enforces chat/BBS-only scope.");
    } else if (manual) {
      if (skip_scrollback) {
        session_send_system_line(ctx, "Chat/BBS-only scope is enabled manually. Scrollback translation is suppressed.");
      } else {
        session_send_system_line(ctx, "Chat/BBS-only scope is enabled manually.");
      }
    }

    session_send_system_line(ctx, "Usage: /translate-scope <chat|chat-nohistory|all>");
    return;
  }

  if (strcasecmp(token, "chat") == 0 || strcasecmp(token, "limit") == 0 || strcasecmp(token, "on") == 0) {
    if (translator_is_manual_chat_bbs_only() && !translator_is_manual_skip_scrollback()) {
      session_send_system_line(ctx,
                               "Translation scope is already limited to chat messages and BBS posts.");
      return;
    }

    translator_set_manual_chat_bbs_only(true);
    translator_set_manual_skip_scrollback(false);
    session_send_system_line(ctx, "Translation scope limited to chat messages and BBS posts.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice), "* [%s] limited translation scope to chat and BBS posts.", ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
    return;
  }

  if (strcasecmp(token, "chat-nohistory") == 0 || strcasecmp(token, "chat_nohistory") == 0 ||
      strcasecmp(token, "chat-nohist") == 0) {
    if (translator_is_manual_chat_bbs_only() && translator_is_manual_skip_scrollback()) {
      session_send_system_line(ctx,
                               "Translation scope is already limited to chat/BBS posts with scrollback translation disabled.");
      return;
    }

    translator_set_manual_chat_bbs_only(true);
    translator_set_manual_skip_scrollback(true);
    session_send_system_line(ctx,
                             "Translation scope limited to chat messages and BBS posts. Scrollback translation is disabled.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice),
             "* [%s] limited translation scope to chat/BBS posts and disabled scrollback translation.", ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
    return;
  }

  if (strcasecmp(token, "all") == 0 || strcasecmp(token, "full") == 0 || strcasecmp(token, "off") == 0) {
    if (translator_is_ollama_only()) {
      session_send_system_line(ctx,
                               "Full translation scope cannot be restored while Gemini is unavailable."
                               " Ollama-only mode restricts translation to chat and BBS posts.");
      return;
    }

    if (!translator_is_manual_chat_bbs_only()) {
      session_send_system_line(ctx,
                               "Translation scope already includes system output and bulk messages.");
      return;
    }

    translator_set_manual_chat_bbs_only(false);
    translator_set_manual_skip_scrollback(false);
    session_send_system_line(ctx,
                             "Full translation scope restored. System output and bulk messages are eligible for translation.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice), "* [%s] restored full translation scope for translations.", ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
    return;
  }

  session_send_system_line(ctx, "Usage: /translate-scope <chat-nohistory|chat|all>");
}

static void session_handle_gemini(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may manage Gemini translation.");
    return;
  }

  const char *cursor = arguments;
  while (cursor != NULL && (*cursor == ' ' || *cursor == '\t')) {
    ++cursor;
  }

  char token[16];
  token[0] = '\0';
  if (cursor != NULL && *cursor != '\0') {
    size_t length = 0U;
    while (cursor[length] != '\0' && !isspace((unsigned char)cursor[length]) && length + 1U < sizeof(token)) {
      token[length] = cursor[length];
      ++length;
    }
    token[length] = '\0';
  }

  if (token[0] == '\0') {
    bool enabled = translator_is_gemini_enabled();
    bool manual = translator_is_gemini_manually_disabled();
    struct timespec remaining = {0, 0};
    bool cooldown_active = translator_gemini_backoff_remaining(&remaining);

    char status_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(status_line, sizeof(status_line), "Gemini translation is currently %s.", enabled ? "enabled" : "disabled");
    session_send_system_line(ctx, status_line);

    if (manual) {
      session_send_system_line(ctx, "Gemini usage is manually disabled. Use /gemini on to re-enable it.");
    }

    if (cooldown_active) {
      long long seconds = remaining.tv_sec;
      if (remaining.tv_nsec > 0L) {
        ++seconds;
      }
      long long hours = seconds / 3600LL;
      long long minutes = (seconds % 3600LL) / 60LL;
      long long secs = seconds % 60LL;

      char cooldown_line[SSH_CHATTER_MESSAGE_LIMIT];
      if (hours > 0) {
        snprintf(cooldown_line, sizeof(cooldown_line),
                 "Automatic Gemini cooldown ends in %lldh %lldm %llds.", hours, minutes, secs);
      } else if (minutes > 0) {
        snprintf(cooldown_line, sizeof(cooldown_line),
                 "Automatic Gemini cooldown ends in %lldm %llds.", minutes, secs);
      } else {
        snprintf(cooldown_line, sizeof(cooldown_line),
                 "Automatic Gemini cooldown ends in %lld seconds.", secs > 0 ? secs : 1LL);
      }
      session_send_system_line(ctx, cooldown_line);
    }

    session_send_system_line(ctx, "Usage: /gemini <on|off>");
    session_send_system_line(ctx, "Use /gemini-unfreeze to clear the automatic cooldown manually.");
    return;
  }

  if (strcasecmp(token, "on") == 0) {
    translator_set_gemini_enabled(true);
    session_send_system_line(ctx, "Gemini translation enabled. Ollama fallback remains available.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice), "* [%s] enabled Gemini translation; Ollama fallback remains available.",
             ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
    return;
  }

  if (strcasecmp(token, "off") == 0) {
    translator_set_gemini_enabled(false);
    session_send_system_line(ctx, "Gemini translation disabled. Using Ollama gemma2:2b only.");
    session_send_system_line(ctx, "While Gemini is off, only chat messages and BBS posts will be translated.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice),
             "* [%s] disabled Gemini translation; using Ollama fallback only (chat and BBS posts).", ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
    return;
  }

  session_send_system_line(ctx, "Usage: /gemini <on|off>");
}

static void session_handle_eliza(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may control eliza.");
    return;
  }

  char token[32];
  if (arguments != NULL) {
    snprintf(token, sizeof(token), "%s", arguments);
    trim_whitespace_inplace(token);
  } else {
    token[0] = '\0';
  }

  if (token[0] == '\0') {
    bool enabled = atomic_load(&ctx->owner->eliza_enabled);
    char status[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(status, sizeof(status), "eliza is currently %s.", enabled ? "enabled" : "disabled");
    session_send_system_line(ctx, status);
    session_send_system_line(ctx, "Usage: /eliza <on|off>");
    return;
  }

  if (strcasecmp(token, "on") == 0) {
    if (host_eliza_enable(ctx->owner)) {
      session_send_system_line(ctx, "eliza enabled. She will now mingle with the room and watch for severe issues.");
    } else {
      session_send_system_line(ctx, "eliza is already active.");
    }
    return;
  }

  if (strcasecmp(token, "off") == 0) {
    if (host_eliza_disable(ctx->owner)) {
      session_send_system_line(ctx, "eliza disabled. She will no longer intervene.");
    } else {
      session_send_system_line(ctx, "eliza is already inactive.");
    }
    return;
  }

  session_send_system_line(ctx, "Usage: /eliza <on|off>");
}

static void session_handle_eliza_chat(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /eliza-chat <message>";

  if (arguments == NULL) {
    session_send_system_line(ctx, kUsage);
    return;
  }

  char prompt[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(prompt, sizeof(prompt), "%s", arguments);
  trim_whitespace_inplace(prompt);

  if (prompt[0] == '\0') {
    session_send_system_line(ctx, kUsage);
    return;
  }

  host_t *host = ctx->owner;
  if (!atomic_load(&host->eliza_enabled)) {
    (void)host_eliza_enable(host);
  }

  char memory_context[SSH_CHATTER_ELIZA_CONTEXT_BUFFER];
  memory_context[0] = '\0';
  size_t memory_count = host_eliza_memory_collect_context(host, prompt, memory_context, sizeof(memory_context));

  char history_context[SSH_CHATTER_ELIZA_CONTEXT_BUFFER];
  history_context[0] = '\0';
  size_t history_count = host_eliza_history_collect_context(host, history_context, sizeof(history_context));

  char bbs_context[SSH_CHATTER_ELIZA_CONTEXT_BUFFER];
  bbs_context[0] = '\0';
  size_t bbs_count = host_eliza_bbs_collect_context(host, bbs_context, sizeof(bbs_context));

  const bool has_memory_context = memory_count > 0U && memory_context[0] != '\0';
  const bool has_history_context = history_count > 0U && history_context[0] != '\0';
  const bool has_bbs_context = bbs_count > 0U && bbs_context[0] != '\0';

  char formatted_prompt[SSH_CHATTER_ELIZA_PROMPT_BUFFER];
  size_t prompt_offset = 0U;
  int base_written = snprintf(formatted_prompt, sizeof(formatted_prompt),
                              "You are eliza, a calm and safety-focused chat companion in a shared room."
                              " You have operator-level visibility over the chat and shared bulletin board so you can"
                              " respond quickly to dangerous statements. When helpful, remind people of legal and safety"
                              " boundaries and encourage contacting local authorities for imminent danger.");
  if (base_written < 0) {
    formatted_prompt[0] = '\0';
    prompt_offset = 0U;
  } else {
    prompt_offset = (size_t)base_written;
    if (prompt_offset >= sizeof(formatted_prompt)) {
      prompt_offset = sizeof(formatted_prompt) - 1U;
      formatted_prompt[prompt_offset] = '\0';
    }
  }

  if (has_history_context && prompt_offset + 1U < sizeof(formatted_prompt)) {
    int written = snprintf(formatted_prompt + prompt_offset, sizeof(formatted_prompt) - prompt_offset,
                           "\n\nRecent chat history:\n%s", history_context);
    if (written > 0) {
      size_t used = (size_t)written;
      if (used >= sizeof(formatted_prompt) - prompt_offset) {
        prompt_offset = sizeof(formatted_prompt) - 1U;
        formatted_prompt[prompt_offset] = '\0';
      } else {
        prompt_offset += used;
      }
    }
  }

  if (has_bbs_context && prompt_offset + 1U < sizeof(formatted_prompt)) {
    int written = snprintf(formatted_prompt + prompt_offset, sizeof(formatted_prompt) - prompt_offset,
                           "\n\nRecent BBS activity:\n%s", bbs_context);
    if (written > 0) {
      size_t used = (size_t)written;
      if (used >= sizeof(formatted_prompt) - prompt_offset) {
        prompt_offset = sizeof(formatted_prompt) - 1U;
        formatted_prompt[prompt_offset] = '\0';
      } else {
        prompt_offset += used;
      }
    }
  }

  if (has_memory_context && prompt_offset + 1U < sizeof(formatted_prompt)) {
    int written = snprintf(formatted_prompt + prompt_offset, sizeof(formatted_prompt) - prompt_offset,
                           "\n\nMemories:\n%s", memory_context);
    if (written > 0) {
      size_t used = (size_t)written;
      if (used >= sizeof(formatted_prompt) - prompt_offset) {
        prompt_offset = sizeof(formatted_prompt) - 1U;
        formatted_prompt[prompt_offset] = '\0';
      } else {
        prompt_offset += used;
      }
    }
  }

  if (prompt_offset + 1U < sizeof(formatted_prompt)) {
    int written = snprintf(formatted_prompt + prompt_offset, sizeof(formatted_prompt) - prompt_offset,
                           "\n\nUser (%s) says:\n%s\n\nRespond as eliza with empathy and brevity.", ctx->user.name,
                           prompt);
    if (written > 0) {
      size_t used = (size_t)written;
      if (used >= sizeof(formatted_prompt) - prompt_offset) {
        prompt_offset = sizeof(formatted_prompt) - 1U;
        formatted_prompt[prompt_offset] = '\0';
      } else {
        prompt_offset += used;
      }
    }
  }

  session_send_private_message_line(ctx, ctx, "you -> eliza", prompt);

  char reply[SSH_CHATTER_MESSAGE_LIMIT];
  reply[0] = '\0';

  if (!translator_eliza_respond(formatted_prompt, reply, sizeof(reply))) {
    const char *error = translator_last_error();
    if (error != NULL && error[0] != '\0') {
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "eliza can't reply right now (%s).", error);
      session_send_system_line(ctx, line);
    } else {
      session_send_system_line(ctx, "eliza can't reply right now. Try again in a moment.");
    }
    return;
  }

  trim_whitespace_inplace(reply);
  if (reply[0] == '\0') {
    session_send_system_line(ctx, "eliza didn't have anything to add.");
    return;
  }

  host_eliza_memory_store(host, prompt, reply);

  session_ctx_t palette = {0};
  palette.user_color_code = host->user_theme.userColor;
  palette.user_highlight_code = host->user_theme.highlight;
  palette.user_is_bold = host->user_theme.isBold;

  session_send_private_message_line(ctx, &palette, "eliza -> you", reply);

  clock_gettime(CLOCK_MONOTONIC, &host->eliza_last_action);
  ctx->last_message_time = host->eliza_last_action;
  ctx->has_last_message_time = true;

  printf("[eliza-chat] %s -> eliza: %s\n", ctx->user.name, prompt);
  printf("[eliza-chat] eliza -> %s: %s\n", ctx->user.name, reply);
}

static void session_handle_gemini_unfreeze(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "Only operators may manage Gemini translation.");
    return;
  }

  struct timespec remaining = {0, 0};
  bool cooldown_active = translator_gemini_backoff_remaining(&remaining);
  translator_clear_gemini_backoff();

  if (cooldown_active) {
    session_send_system_line(ctx, "Automatic Gemini cooldown cleared. Translations may resume immediately.");

    char notice[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(notice, sizeof(notice), "* [%s] cleared the automatic Gemini cooldown.", ctx->user.name);
    host_history_record_system(ctx->owner, notice);
    chat_room_broadcast(&ctx->owner->room, notice, NULL);
  } else {
    session_send_system_line(ctx, "No automatic Gemini cooldown was active.");
  }
}

static void session_handle_palette(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /palette <name> (try /palette list)");
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0' || strcasecmp(working, "list") == 0) {
    session_send_system_line(ctx, "Available palettes:");
    for (size_t idx = 0U; idx < sizeof(PALETTE_DEFINITIONS) / sizeof(PALETTE_DEFINITIONS[0]); ++idx) {
      const palette_descriptor_t *descriptor = &PALETTE_DEFINITIONS[idx];
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "  %s - %s", descriptor->name, descriptor->description);
      session_send_system_line(ctx, line);
    }
    session_send_system_line(ctx, "Apply a palette with /palette <name>.");
    return;
  }

  const palette_descriptor_t *descriptor = palette_find_descriptor(working);
  if (descriptor == NULL) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "Unknown palette '%.32s'. Use /palette list to see options.", working);
    session_send_system_line(ctx, line);
    return;
  }

  if (!palette_apply_to_session(ctx, descriptor)) {
    session_send_system_line(ctx, "Unable to apply that palette right now.");
    return;
  }

  session_apply_background_fill(ctx);

  char info[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(info, sizeof(info), "Palette '%s' applied - %s", descriptor->name, descriptor->description);
  session_send_system_line(ctx, info);
  session_render_separator(ctx, "Chatroom");
  session_render_prompt(ctx, true);

  if (ctx->owner != NULL) {
    host_store_user_theme(ctx->owner, ctx);
    host_store_system_theme(ctx->owner, ctx);
  }
}

static void session_handle_nick(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /nick <name>");
    return;
  }

  char new_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(new_name, sizeof(new_name), "%s", arguments);
  trim_whitespace_inplace(new_name);

  if (new_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /nick <name>");
    return;
  }

  for (size_t idx = 0; new_name[idx] != '\0'; ++idx) {
    const unsigned char ch = (unsigned char)new_name[idx];
    if (ch <= 0x1FU || ch == 0x7FU || ch == ' ' || ch == '\t') {
      session_send_system_line(ctx, "Names may not include control characters or whitespace.");
      return;
    }
  }

  if (host_is_username_banned(ctx->owner, new_name)) {
    session_send_system_line(ctx, "That name is banned.");
    return;
  }

  if (host_username_reserved(ctx->owner, new_name)) {
    session_send_system_line(ctx, "That name is reserved for the chat bot.");
    return;
  }

  session_ctx_t *existing = chat_room_find_user(&ctx->owner->room, new_name);
  if (existing != NULL && existing != ctx) {
    session_send_system_line(ctx, "That name is already taken.");
    return;
  }

  char old_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(old_name, sizeof(old_name), "%s", ctx->user.name);
  snprintf(ctx->user.name, sizeof(ctx->user.name), "%s", new_name);

  char announcement[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(announcement, sizeof(announcement), "* [%s] is now known as [%s]", old_name, ctx->user.name);
  host_history_record_system(ctx->owner, announcement);
  chat_room_broadcast(&ctx->owner->room, announcement, NULL);
  session_apply_saved_preferences(ctx);
  session_send_system_line(ctx, "Display name updated.");
}

static void session_force_disconnect(session_ctx_t *ctx, const char *reason) {
  if (ctx == NULL) {
    return;
  }

  if (reason != NULL && reason[0] != '\0') {
    session_send_system_line(ctx, reason);
  }

  ctx->should_exit = true;
  ctx->exit_status = EXIT_FAILURE;

  if (ctx->translation_mutex_initialized) {
    pthread_mutex_lock(&ctx->translation_mutex);
    ctx->translation_thread_stop = true;
    pthread_cond_broadcast(&ctx->translation_cond);
    pthread_mutex_unlock(&ctx->translation_mutex);
  }
  session_translation_clear_queue(ctx);

  session_transport_request_close(ctx);
}

static void session_handle_exit(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_force_disconnect(ctx, "Disconnecting... bye!");
  ctx->exit_status = EXIT_SUCCESS;
}

static void session_handle_pardon(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to pardon users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /pardon <user|ip>");
    return;
  }

  char token[SSH_CHATTER_IP_LEN];
  snprintf(token, sizeof(token), "%s", arguments);
  trim_whitespace_inplace(token);

  if (token[0] == '\0') {
    session_send_system_line(ctx, "Usage: /pardon <user|ip>");
    return;
  }

  if (host_remove_ban_entry(ctx->owner, token)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Ban lifted for '%s'.", token);
    session_send_system_line(ctx, message);
  } else {
    session_send_system_line(ctx, "No matching ban found.");
  }
}

static session_ctx_t *chat_room_find_user(chat_room_t *room, const char *username) {
  if (room == NULL || username == NULL) {
    return NULL;
  }

  session_ctx_t *result = NULL;
  pthread_mutex_lock(&room->lock);
  for (size_t idx = 0; idx < room->member_count; ++idx) {
    session_ctx_t *member = room->members[idx];
    if (member == NULL) {
      continue;
    }

    if (strncmp(member->user.name, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      result = member;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);

  return result;
}

static bool host_username_reserved(host_t *host, const char *username) {
  (void)host;
  (void)username;
  return false;
}

static join_activity_entry_t *host_find_join_activity_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL) {
    return NULL;
  }

  for (size_t idx = 0; idx < host->join_activity_count; ++idx) {
    join_activity_entry_t *entry = &host->join_activity[idx];
    if (strncmp(entry->ip, ip, SSH_CHATTER_IP_LEN) == 0) {
      return entry;
    }
  }

  return NULL;
}

static join_activity_entry_t *host_ensure_join_activity_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return NULL;
  }

  join_activity_entry_t *entry = host_find_join_activity_locked(host, ip);
  if (entry != NULL) {
    return entry;
  }

  if (host->join_activity_count >= host->join_activity_capacity) {
    size_t new_capacity = host->join_activity_capacity > 0U ? host->join_activity_capacity * 2U : 8U;
    join_activity_entry_t *resized =
        realloc(host->join_activity, new_capacity * sizeof(join_activity_entry_t));
    if (resized == NULL) {
      return NULL;
    }
    host->join_activity = resized;
    host->join_activity_capacity = new_capacity;
  }

  entry = &host->join_activity[host->join_activity_count++];
  memset(entry, 0, sizeof(*entry));
  snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
  return entry;
}

static size_t host_prepare_join_delay(host_t *host, struct timespec *wait_duration) {
  struct timespec wait = {0, 0};
  if (host == NULL) {
    if (wait_duration != NULL) {
      *wait_duration = wait;
    }
    return 1U;
  }

  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);

  pthread_mutex_lock(&host->lock);
  if (!host->join_throttle_initialised) {
    host->next_join_ready_time = now;
    host->join_throttle_initialised = true;
    host->join_progress_length = 0U;
  }

  if (timespec_compare(&now, &host->next_join_ready_time) < 0) {
    wait = timespec_diff(&host->next_join_ready_time, &now);
  }

  struct timespec base = now;
  if (timespec_compare(&host->next_join_ready_time, &now) > 0) {
    base = host->next_join_ready_time;
  }
  host->next_join_ready_time = timespec_add_ms(&base, 100);
  host->join_progress_length = (host->join_progress_length % SSH_CHATTER_JOIN_BAR_MAX) + 1U;
  size_t progress = host->join_progress_length;
  pthread_mutex_unlock(&host->lock);

  if (wait_duration != NULL) {
    *wait_duration = wait;
  }
  return progress;
}

static bool host_register_join_attempt(host_t *host, const char *username, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);

  bool ban_ip = false;
  bool ban_same_name = false;
  bool exempt_ip = false;

  pthread_mutex_lock(&host->lock);
  join_activity_entry_t *entry = host_ensure_join_activity_locked(host, ip);
  if (entry == NULL) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }

  struct timespec diff = timespec_diff(&now, &entry->last_attempt);
  const long long diff_ns = (long long)diff.tv_sec * 1000000000LL + (long long)diff.tv_nsec;
  const bool has_prior_attempt = (entry->last_attempt.tv_sec != 0 || entry->last_attempt.tv_nsec != 0);
  const bool within_window = has_prior_attempt && diff_ns <= SSH_CHATTER_JOIN_RAPID_WINDOW_NS;

  if (within_window) {
    entry->rapid_attempts += 1U;
  } else {
    entry->rapid_attempts = 1U;
  }

  if (username != NULL && username[0] != '\0') {
    if (within_window && strncmp(entry->last_username, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      entry->same_name_attempts += 1U;
    } else {
      entry->same_name_attempts = 1U;
      snprintf(entry->last_username, sizeof(entry->last_username), "%s", username);
    }
  } else {
    entry->same_name_attempts = within_window ? entry->same_name_attempts + 1U : 1U;
  }

  entry->last_attempt = now;

  if (host_ip_has_grant_locked(host, ip)) {
    exempt_ip = true;
  }

  if (!exempt_ip && within_window && entry->rapid_attempts >= SSH_CHATTER_JOIN_IP_THRESHOLD) {
    ban_ip = true;
  }
  if (within_window && entry->same_name_attempts >= SSH_CHATTER_JOIN_NAME_THRESHOLD) {
    ban_same_name = true;
  }
  pthread_mutex_unlock(&host->lock);

  if ((ban_ip || ban_same_name) && !exempt_ip) {
    const char *ban_user = (username != NULL && username[0] != '\0') ? username : "";
    if (host_add_ban_entry(host, ban_user, ip)) {
      printf("[auto-ban] %s flagged for rapid reconnects\n", ip);
    }
    return true;
  }

  return false;
}

static bool host_register_suspicious_activity(host_t *host, const char *username, const char *ip,
                                             size_t *attempts_out) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    if (attempts_out != NULL) {
      *attempts_out = 0U;
    }
    return false;
  }

  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);

  size_t attempts = 0U;
  pthread_mutex_lock(&host->lock);
  join_activity_entry_t *entry = host_ensure_join_activity_locked(host, ip);
  if (entry != NULL) {
    if (entry->last_suspicious.tv_sec != 0 || entry->last_suspicious.tv_nsec != 0) {
      struct timespec diff = timespec_diff(&now, &entry->last_suspicious);
      long long diff_ns = (long long)diff.tv_sec * 1000000000LL + (long long)diff.tv_nsec;
      if (diff_ns > SSH_CHATTER_SUSPICIOUS_EVENT_WINDOW_NS) {
        entry->suspicious_events = 0U;
      }
    }

    if (entry->suspicious_events < SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD) {
      entry->suspicious_events += 1U;
    } else {
      entry->suspicious_events = SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD;
    }
    entry->last_suspicious = now;
    attempts = entry->suspicious_events;
  }
  pthread_mutex_unlock(&host->lock);

  if (attempts_out != NULL) {
    *attempts_out = attempts;
  }

  if (attempts >= SSH_CHATTER_SUSPICIOUS_EVENT_THRESHOLD) {
    const char *ban_user = (username != NULL && username[0] != '\0') ? username : "";
    (void)host_add_ban_entry(host, ban_user, ip);
    return true;
  }

  return false;
}

static bool host_is_ip_banned(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  bool banned = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].ip, ip, SSH_CHATTER_IP_LEN) == 0) {
      banned = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return banned;
}

static bool host_is_username_banned(host_t *host, const char *username) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return false;
  }

  bool banned = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].username, username, SSH_CHATTER_USERNAME_LEN) == 0) {
      banned = true;
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return banned;
}

static bool host_add_ban_entry(host_t *host, const char *username, const char *ip) {
  if (host == NULL) {
    return false;
  }

  bool added = false;
  pthread_mutex_lock(&host->lock);
  if (host->ban_count >= SSH_CHATTER_MAX_BANS) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }

  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    const bool username_match = (username != NULL && username[0] != '\0' &&
                                 strncmp(host->bans[idx].username, username, SSH_CHATTER_USERNAME_LEN) == 0);
    const bool ip_match = (ip != NULL && ip[0] != '\0' &&
                           strncmp(host->bans[idx].ip, ip, SSH_CHATTER_IP_LEN) == 0);
    if (username_match || ip_match) {
      pthread_mutex_unlock(&host->lock);
      return true;
    }
  }

  strncpy(host->bans[host->ban_count].username,
          username != NULL ? username : "", SSH_CHATTER_USERNAME_LEN - 1U);
  host->bans[host->ban_count].username[SSH_CHATTER_USERNAME_LEN - 1U] = '\0';
  strncpy(host->bans[host->ban_count].ip, ip != NULL ? ip : "", SSH_CHATTER_IP_LEN - 1U);
  host->bans[host->ban_count].ip[SSH_CHATTER_IP_LEN - 1U] = '\0';
  ++host->ban_count;
  added = true;

  host_ban_state_save_locked(host);

  pthread_mutex_unlock(&host->lock);
  return added;
}

static bool host_remove_ban_entry(host_t *host, const char *token) {
  if (host == NULL || token == NULL || token[0] == '\0') {
    return false;
  }

  bool removed = false;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < host->ban_count; ++idx) {
    if (strncmp(host->bans[idx].username, token, SSH_CHATTER_USERNAME_LEN) == 0 ||
        strncmp(host->bans[idx].ip, token, SSH_CHATTER_IP_LEN) == 0) {
      for (size_t shift = idx; shift + 1U < host->ban_count; ++shift) {
        host->bans[shift] = host->bans[shift + 1U];
      }
      memset(&host->bans[host->ban_count - 1U], 0, sizeof(host->bans[host->ban_count - 1U]));
      --host->ban_count;
      removed = true;
      host_ban_state_save_locked(host);
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return removed;
}

static bool session_parse_command(const char *line, const char *command, const char **arguments) {
  size_t command_len = strlen(command);

  if (strncmp(line, command, command_len) == 0) {
    const char boundary = line[command_len];
    if (boundary != '\0' && boundary != ' ' && boundary != '\t') {
      return false;
    }

    const char *args = line + command_len;

    while (*args == ' ' || *args == '\t') {
      ++args;
    }

    *arguments = args;
    return true;
  }
  return false;
}

static void session_dispatch_command(session_ctx_t *ctx, const char *line) {
  const char *args = NULL;

  if (strncmp(line, "/help", 5) == 0) {
    session_print_help(ctx);
    return;
  }

  else if (strncmp(line, "/exit", 5) == 0) {
    session_handle_exit(ctx);
    return;
  }

  else if (session_parse_command(line, "/nick", &args)) {
    session_handle_nick(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/pm", &args)) {
    session_handle_pm(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/asciiart", &args)) {
    if (*args != '\0') {
      session_send_system_line(ctx, "Usage: /asciiart");
    } else {
      session_asciiart_begin(ctx, SESSION_ASCIIART_TARGET_CHAT);
    }
    return;
  }

  else if (session_parse_command(line, "/motd", &args)) {
    if (*args != '\0') {
      session_send_system_line(ctx, "Usage: /motd");
    } else {
      session_handle_motd(ctx);
    }
    return;
  }

  else if (session_parse_command(line, "/status", &args)) {
    session_handle_status(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/showstatus", &args)) {
    session_handle_showstatus(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/users", &args)) {
    if (*args != '\0') {
      session_send_system_line(ctx, "Usage: /users");
    } else {
      session_handle_usercount(ctx);
    }
    return;
  }

  else if (session_parse_command(line, "/search", &args)) {
    session_handle_search(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/chat", &args)) {
    session_handle_chat_lookup(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/reply", &args)) {
    session_handle_reply(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/image", &args)) {
    session_handle_image(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/video", &args)) {
    session_handle_video(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/audio", &args)) {
    session_handle_audio(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/files", &args)) {
    session_handle_files(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/mail", &args)) {
    session_handle_mail(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/profilepic", &args)) {
    session_handle_profile_picture(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/game", &args)) {
    session_handle_game(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/banlist", &args)) {
    session_handle_ban_list(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/ban", &args)) {
    session_handle_ban(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/delete-msg", &args)) {
    session_handle_delete_message(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/block", &args)) {
    session_handle_block(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/unblock", &args)) {
    session_handle_unblock(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/pardon", &args)) {
    session_handle_pardon(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/poke", &args)) {
    session_handle_poke(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/color", &args)) {
    session_handle_color(ctx, args);
    return;
  }

  else if (session_parse_command(line, "/systemcolor", &args)) {
    session_handle_system_color(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/set-trans-lang", &args)) {
    session_handle_set_trans_lang(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/set-target-lang", &args)) {
    session_handle_set_target_lang(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/weather", &args)) {
    session_handle_weather(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/translate", &args)) {
    session_handle_translate(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/translate-scope", &args)) {
    session_handle_translate_scope(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/gemini-unfreeze", &args)) {
    session_handle_gemini_unfreeze(ctx);
    return;
  }
  else if (session_parse_command(line, "/gemini", &args)) {
    session_handle_gemini(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/eliza", &args)) {
    session_handle_eliza(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/eliza-chat", &args)) {
    session_handle_eliza_chat(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/chat-spacing", &args)) {
    session_handle_chat_spacing(ctx, args);
    return;
  }
  else if (session_parse_command(line, "/mode", &args)) {
    session_handle_mode(ctx, args);
    return;
  }
  else if (strncmp(line, "/palette", 8) == 0) {
    const char *arguments = line + 8;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_palette(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/suspend!", 9) == 0) {
    if (ctx->game.active) {
      session_game_suspend(ctx, "Game suspended.");
    } else {
      session_game_suspend(ctx, NULL);
    }
    return;
  }
  else if (strncmp(line, "/today", 6) == 0) {
    const char *arguments = line + 6;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /today");
    } else {
      session_handle_today(ctx);
    }
    return;
  }
  else if (strncmp(line, "/date", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_date(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/os", 3) == 0) {
    const char *arguments = line + 3;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_os(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/getos", 6) == 0) {
    const char *arguments = line + 6;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_getos(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/birthday", 9) == 0) {
    const char *arguments = line + 9;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_birthday(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/soulmate", 9) == 0) {
    const char *arguments = line + 9;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /soulmate");
    } else {
      session_handle_soulmate(ctx);
    }
    return;
  }
  else if (strncmp(line, "/grant", 6) == 0) {
    const char *arguments = line + 6;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_grant(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/revoke", 7) == 0) {
    const char *arguments = line + 7;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_revoke(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/pair", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /pair");
    } else {
      session_handle_pair(ctx);
    }
    return;
  }
  else if (strncmp(line, "/connected", 10) == 0) {
    const char *arguments = line + 10;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /connected");
    } else {
      session_handle_connected(ctx);
    }
    return;
  }
  else if (strncmp(line, "/poll", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_poll(ctx, arguments);
    return;
  }
  else if (strncmp(line, "/vote-single", 12) == 0) {
    const char *arguments = line + 12;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments == '\0') {
      session_handle_vote_command(ctx, NULL, false);
    } else {
      session_handle_vote_command(ctx, arguments, false);
    }
    return;
  }
  else if (strncmp(line, "/vote", 5) == 0) {
    const char *arguments = line + 5;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments == '\0') {
      session_handle_vote_command(ctx, NULL, true);
    } else {
      session_handle_vote_command(ctx, arguments, true);
    }
    return;
  }
  else if (strncmp(line, "/elect", 6) == 0) {
    const char *arguments = line + 6;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    if (*arguments == '\0') {
      session_handle_elect_command(ctx, NULL);
    } else {
      session_handle_elect_command(ctx, arguments);
    }
    return;
  }
  else if (session_parse_command(line, "/rss", &args)) {
    session_handle_rss(ctx, args);
    return;
  }
  else if (strncmp(line, "/bbs", 4) == 0) {
    const char *arguments = line + 4;
    while (*arguments == ' ' || *arguments == '\t') {
      ++arguments;
    }
    session_handle_bbs(ctx, *arguments == '\0' ? NULL : arguments);
    return;
  }

  else if (session_parse_command(line, "/kick", &args)) {
    session_handle_kick(ctx, args);
    return;
  }

  else if (line[0] == '/') {
    if (isdigit((unsigned char)line[1])) {
      char *endptr = NULL;
      unsigned long vote_index = strtoul(line + 1, &endptr, 10);
      const unsigned long max_vote = sizeof(ctx->owner->poll.options) / sizeof(ctx->owner->poll.options[0]);
      if (vote_index >= 1UL && vote_index <= max_vote) {
        while (endptr != NULL && (*endptr == ' ' || *endptr == '\t')) {
          ++endptr;
        }
        if (endptr == NULL || *endptr == '\0') {
          session_handle_vote(ctx, (size_t)(vote_index - 1UL));
          return;
        } else {
          while (*endptr == ' ' || *endptr == '\t') {
            ++endptr;
          }
          if (*endptr != '\0') {
            char label[SSH_CHATTER_POLL_LABEL_LEN];
            size_t label_len = 0U;
            while (*endptr != '\0' && !isspace((unsigned char)*endptr)) {
              if (label_len + 1U >= sizeof(label)) {
                label_len = 0U;
                break;
              }
              label[label_len++] = *endptr++;
            }
            label[label_len] = '\0';
            if (label_len > 0U) {
              session_handle_named_vote(ctx, (size_t)(vote_index - 1UL), label);
              return;
            }
          }
        }
      }
    }
    for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
      const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
      size_t command_len = strlen(descriptor->command);
      if (strncmp(line + 1, descriptor->command, command_len) != 0) {
        continue;
      }
      const char trailing = line[1 + command_len];
      if (!(trailing == '\0' || isspace((unsigned char)trailing))) {
        continue;
      }

      const char *arguments = line + 1 + command_len;
      while (*arguments == ' ' || *arguments == '\t') {
        ++arguments;
      }
      session_handle_reaction(ctx, idx, arguments);
      return;
    }
  }

  session_send_system_line(ctx, "Unknown command. Type /help for help.");
}

static void trim_whitespace_inplace(char *text) {
  if (text == NULL) {
    return;
  }

  char *start = text;
  while (*start != '\0' && isspace((unsigned char)*start)) {
    ++start;
  }

  char *end = text + strlen(text);
  while (end > start && isspace((unsigned char)*(end - 1))) {
    --end;
  }

  const size_t length = (size_t)(end - start);
  if (start != text && length > 0U) {
    memmove(text, start, length);
  }
  text[length] = '\0';
}

static const char *session_consume_token(const char *input, char *token, size_t length) {
  if (token == NULL || length == 0U) {
    return input;
  }

  token[0] = '\0';
  if (input == NULL) {
    return NULL;
  }

  while (*input == ' ' || *input == '\t') {
    ++input;
  }

  size_t out_idx = 0U;
  while (*input != '\0' && !isspace((unsigned char)*input)) {
    if (out_idx + 1U < length) {
      token[out_idx++] = *input;
    }
    ++input;
  }
  token[out_idx] = '\0';

  while (*input == ' ' || *input == '\t') {
    ++input;
  }

  return input;
}

static bool session_user_data_available(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return false;
  }

  if (!ctx->owner->user_data_ready) {
    return false;
  }

  if (ctx->user.name[0] == '\0') {
    return false;
  }

  return true;
}

static void session_user_data_touch(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->user_data_loaded) {
    return;
  }

  time_t now = time(NULL);
  if (now == (time_t)-1) {
    now = 0;
  }
  ctx->user_data.last_updated = (uint64_t)now;
}

static void host_user_data_build_match_key(const char *username, char *key, size_t length) {
  if (key == NULL || length == 0U) {
    return;
  }

  key[0] = '\0';
  if (username == NULL || username[0] == '\0') {
    return;
  }

  char sanitized[SSH_CHATTER_USERNAME_LEN * 2U];
  const bool sanitized_ok = user_data_sanitize_username(username, sanitized, sizeof(sanitized));
  const char *source = sanitized_ok ? sanitized : username;

  size_t out_idx = 0U;
  for (size_t idx = 0U; source[idx] != '\0'; ++idx) {
    unsigned char ch = (unsigned char)source[idx];
    if (isalnum(ch)) {
      if (out_idx + 1U < length) {
        key[out_idx++] = (char)tolower(ch);
      }
    }
  }

  key[out_idx] = '\0';
}

static bool host_user_data_find_profile_picture(host_t *host, const char *alias, user_data_record_t *record) {
  if (host == NULL || alias == NULL || alias[0] == '\0' || record == NULL) {
    return false;
  }

  user_data_record_t direct_record;
  const bool direct_loaded = host_user_data_load_existing(host, alias, &direct_record, false);
  if (direct_loaded && direct_record.profile_picture[0] != '\0') {
    *record = direct_record;
    return true;
  }

  char alias_key[SSH_CHATTER_USERNAME_LEN * 2U];
  host_user_data_build_match_key(alias, alias_key, sizeof(alias_key));
  if (alias_key[0] == '\0') {
    return false;
  }

  char alias_path_key[SSH_CHATTER_USERNAME_LEN * 2U];
  alias_path_key[0] = '\0';
  if (!user_data_sanitize_username(alias, alias_path_key, sizeof(alias_path_key))) {
    alias_path_key[0] = '\0';
  }

  if (host->user_data_root[0] == '\0') {
    return false;
  }

  DIR *dir = opendir(host->user_data_root);
  if (dir == NULL) {
    return false;
  }

  bool matched = false;
  struct dirent *entry = NULL;
  while (!matched && (entry = readdir(dir)) != NULL) {
    const char *name = entry->d_name;
    if (name == NULL || name[0] == '\0') {
      continue;
    }

    if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) {
      continue;
    }

    size_t name_len = strlen(name);
    if (name_len <= 4U || strcmp(name + name_len - 4U, ".dat") != 0) {
      continue;
    }

    size_t base_len = name_len - 4U;
    char candidate_name[SSH_CHATTER_USERNAME_LEN * 2U];
    if (base_len >= sizeof(candidate_name)) {
      continue;
    }
    memcpy(candidate_name, name, base_len);
    candidate_name[base_len] = '\0';

    if (alias_path_key[0] != '\0' && strcmp(candidate_name, alias_path_key) == 0) {
      continue;
    }

    user_data_record_t candidate_record;
    if (!host_user_data_load_existing(host, candidate_name, &candidate_record, false)) {
      continue;
    }

    if (candidate_record.profile_picture[0] == '\0') {
      continue;
    }

    char candidate_key[SSH_CHATTER_USERNAME_LEN * 2U];
    host_user_data_build_match_key(candidate_record.username, candidate_key, sizeof(candidate_key));
    if (candidate_key[0] == '\0') {
      continue;
    }

    if (strcmp(candidate_key, alias_key) == 0) {
      *record = candidate_record;
      matched = true;
    }
  }

  closedir(dir);
  return matched;
}

static bool host_user_data_load_existing(host_t *host, const char *username, user_data_record_t *record,
                                        bool create_if_missing) {
  if (host == NULL || username == NULL || username[0] == '\0') {
    return false;
  }

  if (!host->user_data_ready) {
    return false;
  }

  bool success = false;
  if (host->user_data_lock_initialized) {
    pthread_mutex_lock(&host->user_data_lock);
  }

  if (create_if_missing) {
    success = user_data_ensure_exists(host->user_data_root, username, record);
  } else {
    success = user_data_load(host->user_data_root, username, record);
  }

  if (host->user_data_lock_initialized) {
    pthread_mutex_unlock(&host->user_data_lock);
  }

  return success;
}

static bool session_user_data_load(session_ctx_t *ctx) {
  if (!session_user_data_available(ctx)) {
    return false;
  }

  if (ctx->user_data_loaded) {
    return true;
  }

  user_data_record_t record;
  if (!host_user_data_load_existing(ctx->owner, ctx->user.name, &record, true)) {
    return false;
  }

  ctx->user_data = record;
  ctx->user_data_loaded = true;
  return true;
}

static bool session_user_data_commit(session_ctx_t *ctx) {
  if (!session_user_data_available(ctx) || !ctx->user_data_loaded) {
    return false;
  }

  session_user_data_touch(ctx);

  host_t *host = ctx->owner;
  bool success = false;
  if (host->user_data_lock_initialized) {
    pthread_mutex_lock(&host->user_data_lock);
  }
  success = user_data_save(host->user_data_root, &ctx->user_data);
  if (host->user_data_lock_initialized) {
    pthread_mutex_unlock(&host->user_data_lock);
  }

  if (!success) {
    humanized_log_error("mailbox", "failed to persist user data", errno != 0 ? errno : EIO);
  }

  return success;
}

static bool host_user_data_send_mail(host_t *host, const char *recipient, const char *sender, const char *message,
                                    char *error, size_t error_length) {
  if (error != NULL && error_length > 0U) {
    error[0] = '\0';
  }

  if (host == NULL || recipient == NULL || recipient[0] == '\0' || message == NULL || message[0] == '\0') {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "%s", "Invalid mailbox parameters.");
    }
    return false;
  }

  if (!host->user_data_ready) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "%s", "Mailbox storage unavailable.");
    }
    return false;
  }

  user_data_record_t record;
  if (!host_user_data_load_existing(host, recipient, &record, true)) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "Unable to open mailbox for %s.", recipient);
    }
    return false;
  }

  if (record.mailbox_count >= USER_DATA_MAILBOX_LIMIT) {
    for (size_t idx = 1U; idx < USER_DATA_MAILBOX_LIMIT; ++idx) {
      record.mailbox[idx - 1U] = record.mailbox[idx];
    }
    record.mailbox_count = USER_DATA_MAILBOX_LIMIT - 1U;
  }

  user_data_mail_entry_t *entry = &record.mailbox[record.mailbox_count++];
  time_t now = time(NULL);
  if (now == (time_t)-1) {
    now = 0;
  }
  entry->timestamp = (uint64_t)now;
  if (sender != NULL && sender[0] != '\0') {
    snprintf(entry->sender, sizeof(entry->sender), "%s", sender);
  } else {
    snprintf(entry->sender, sizeof(entry->sender), "%s", "system");
  }
  snprintf(entry->message, sizeof(entry->message), "%s", message);
  record.last_updated = (uint64_t)now;

  bool success;
  if (host->user_data_lock_initialized) {
    pthread_mutex_lock(&host->user_data_lock);
  }
  success = user_data_save(host->user_data_root, &record);
  if (host->user_data_lock_initialized) {
    pthread_mutex_unlock(&host->user_data_lock);
  }

  if (!success) {
    if (error != NULL && error_length > 0U) {
      snprintf(error, error_length, "%s", "Failed to write mailbox file.");
    }
    humanized_log_error("mailbox", "failed to persist mailbox entry", errno != 0 ? errno : EIO);
    return false;
  }

  return true;
}

static void rss_trim_whitespace(char *text) {
  trim_whitespace_inplace(text);
}

static void rss_strip_html(char *text) {
  if (text == NULL) {
    return;
  }

  size_t read = 0U;
  size_t write = 0U;
  bool in_tag = false;
  while (text[read] != '\0') {
    char ch = text[read++];
    if (ch == '<') {
      in_tag = true;
      continue;
    }
    if (in_tag) {
      if (ch == '>') {
        in_tag = false;
      }
      continue;
    }
    text[write++] = ch;
  }
  text[write] = '\0';
}

static void rss_decode_entities(char *text) {
  if (text == NULL) {
    return;
  }

  char *src = text;
  char *dst = text;
  while (*src != '\0') {
    if (*src == '&') {
      if (strncmp(src, "&amp;", 5) == 0) {
        *dst++ = '&';
        src += 5;
        continue;
      }
      if (strncmp(src, "&lt;", 4) == 0) {
        *dst++ = '<';
        src += 4;
        continue;
      }
      if (strncmp(src, "&gt;", 4) == 0) {
        *dst++ = '>';
        src += 4;
        continue;
      }
      if (strncmp(src, "&quot;", 6) == 0) {
        *dst++ = '\"';
        src += 6;
        continue;
      }
      if (strncmp(src, "&#39;", 5) == 0) {
        *dst++ = '\'';
        src += 5;
        continue;
      }
    }
    *dst++ = *src++;
  }
  *dst = '\0';
}

static bool rss_tag_is_valid(const char *tag) {
  if (tag == NULL || tag[0] == '\0') {
    return false;
  }

  for (const char *cursor = tag; *cursor != '\0'; ++cursor) {
    const char ch = *cursor;
    if (!(isalnum((unsigned char)ch) || ch == '-' || ch == '_' || ch == '.')) {
      return false;
    }
  }
  return true;
}

// Reset a poll structure to a neutral inactive state.
static void poll_state_reset(poll_state_t *poll) {
  if (poll == NULL) {
    return;
  }

  poll->active = false;
  poll->option_count = 0U;
  poll->question[0] = '\0';
  poll->allow_multiple = false;
  for (size_t idx = 0U; idx < sizeof(poll->options) / sizeof(poll->options[0]); ++idx) {
    poll->options[idx].text[0] = '\0';
    poll->options[idx].votes = 0U;
  }
}

// Reset a named poll entry including its label and voter tracking list.
static void named_poll_reset(named_poll_state_t *poll) {
  if (poll == NULL) {
    return;
  }

  poll_state_reset(&poll->poll);
  poll->label[0] = '\0';
  poll->owner[0] = '\0';
  poll->voter_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_VOTERS; ++idx) {
    poll->voters[idx].username[0] = '\0';
    poll->voters[idx].choice = -1;
    poll->voters[idx].choices_mask = 0U;
  }
}

// Look up a named poll by its label while the host lock is already held.
static named_poll_state_t *host_find_named_poll_locked(host_t *host, const char *label) {
  if (host == NULL || label == NULL || label[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    named_poll_state_t *entry = &host->named_polls[idx];
    if (entry->label[0] == '\0') {
      continue;
    }
    if (strcasecmp(entry->label, label) == 0) {
      return entry;
    }
  }

  return NULL;
}

// Either fetch an existing named poll or initialise a new slot for the provided label.
static named_poll_state_t *host_ensure_named_poll_locked(host_t *host, const char *label) {
  if (host == NULL || label == NULL || label[0] == '\0') {
    return NULL;
  }

  named_poll_state_t *existing = host_find_named_poll_locked(host, label);
  if (existing != NULL) {
    return existing;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    named_poll_state_t *entry = &host->named_polls[idx];
    if (entry->label[0] != '\0') {
      continue;
    }
    named_poll_reset(entry);
    snprintf(entry->label, sizeof(entry->label), "%s", label);
    return entry;
  }

  return NULL;
}

// Recompute how many named polls are active so list summaries remain accurate.
static void host_recount_named_polls_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  size_t count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] != '\0' && host->named_polls[idx].poll.active) {
      ++count;
    }
  }
  host->named_poll_count = count;
}

// Ensure poll labels remain short and shell-friendly.
static bool poll_label_is_valid(const char *label) {
  if (label == NULL || label[0] == '\0') {
    return false;
  }

  for (size_t idx = 0U; label[idx] != '\0'; ++idx) {
    char ch = label[idx];
    if (!(isalnum((unsigned char)ch) || ch == '_' || ch == '-')) {
      return false;
    }
  }
  return true;
}

static void session_normalize_newlines(char *text) {
  if (text == NULL) {
    return;
  }

  size_t read_idx = 0U;
  size_t write_idx = 0U;
  while (text[read_idx] != '\0') {
    char ch = text[read_idx++];
    if (ch == '\r') {
      if (text[read_idx] == '\n') {
        ++read_idx;
      }
      text[write_idx++] = '\n';
    } else {
      text[write_idx++] = ch;
    }
  }

  text[write_idx] = '\0';
}

static bool timezone_sanitize_identifier(const char *input, char *output, size_t length) {
  if (input == NULL || output == NULL || length == 0U) {
    return false;
  }

  size_t out_idx = 0U;
  bool last_was_slash = true;

  for (size_t idx = 0U; input[idx] != '\0'; ++idx) {
    unsigned char ch = (unsigned char)input[idx];
    if (isspace(ch)) {
      return false;
    }

    if (ch == '/') {
      if (last_was_slash) {
        return false;
      }
      if (out_idx + 1U >= length) {
        return false;
      }
      output[out_idx++] = '/';
      last_was_slash = true;
      continue;
    }

    if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '+' || ch == '.')) {
      return false;
    }

    if (out_idx + 1U >= length) {
      return false;
    }
    output[out_idx++] = (char)ch;
    last_was_slash = false;
  }

  if (out_idx == 0U || last_was_slash) {
    return false;
  }

  output[out_idx] = '\0';

  if (output[0] == '/' || strstr(output, "..") != NULL) {
    return false;
  }

  return true;
}

static bool timezone_resolve_identifier(const char *input, char *resolved, size_t length) {
  if (input == NULL || input[0] == '\0' || resolved == NULL || length == 0U) {
    return false;
  }

  static const char kTimezoneDir[] = "/usr/share/zoneinfo";

  char full_path[PATH_MAX];
  int full_written = snprintf(full_path, sizeof(full_path), "%s/%s", kTimezoneDir, input);
  if (full_written >= 0 && (size_t)full_written < sizeof(full_path) && access(full_path, R_OK) == 0) {
    int copy_written = snprintf(resolved, length, "%s", input);
    return copy_written >= 0 && (size_t)copy_written < length;
  }

  char working[PATH_MAX];
  int working_written = snprintf(working, sizeof(working), "%s", input);
  if (working_written < 0 || (size_t)working_written >= sizeof(working)) {
    return false;
  }

  char accumulated[PATH_MAX];
  accumulated[0] = '\0';
  size_t accumulated_len = 0U;
  char current_dir[PATH_MAX];
  int dir_written = snprintf(current_dir, sizeof(current_dir), "%s", kTimezoneDir);
  if (dir_written < 0 || (size_t)dir_written >= sizeof(current_dir)) {
    return false;
  }

  char *saveptr = NULL;
  char *segment = strtok_r(working, "/", &saveptr);
  if (segment == NULL) {
    return false;
  }

  while (segment != NULL) {
    DIR *dir = opendir(current_dir);
    if (dir == NULL) {
      return false;
    }

    bool found = false;
    char matched[NAME_MAX + 1];
    matched[0] = '\0';
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_name[0] == '.') {
        if (entry->d_name[1] == '\0') {
          continue;
        }
        if (entry->d_name[1] == '.' && entry->d_name[2] == '\0') {
          continue;
        }
      }

      if (strcasecmp(entry->d_name, segment) == 0) {
        found = true;
        snprintf(matched, sizeof(matched), "%s", entry->d_name);
        break;
      }
    }
    closedir(dir);

    if (!found) {
      return false;
    }

    if (accumulated_len > 0U) {
      if (accumulated_len + 1U >= sizeof(accumulated)) {
        return false;
      }
      accumulated[accumulated_len++] = '/';
    }

    size_t match_len = strlen(matched);
    if (accumulated_len + match_len >= sizeof(accumulated)) {
      return false;
    }
    memcpy(accumulated + accumulated_len, matched, match_len);
    accumulated_len += match_len;
    accumulated[accumulated_len] = '\0';

    dir_written = snprintf(current_dir, sizeof(current_dir), "%s/%s", kTimezoneDir, accumulated);
    if (dir_written < 0 || (size_t)dir_written >= sizeof(current_dir)) {
      return false;
    }

    segment = strtok_r(NULL, "/", &saveptr);
  }

  if (accumulated_len == 0U) {
    return false;
  }

  full_written = snprintf(full_path, sizeof(full_path), "%s/%s", kTimezoneDir, accumulated);
  if (full_written < 0 || (size_t)full_written >= sizeof(full_path)) {
    return false;
  }

  if (access(full_path, R_OK) != 0) {
    return false;
  }

  int copy_written = snprintf(resolved, length, "%s", accumulated);
  return copy_written >= 0 && (size_t)copy_written < length;
}

static const os_descriptor_t *session_lookup_os_descriptor(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < sizeof(OS_CATALOG) / sizeof(OS_CATALOG[0]); ++idx) {
    if (strcasecmp(OS_CATALOG[idx].name, name) == 0) {
      return &OS_CATALOG[idx];
    }
  }

  return NULL;
}

static const char *lookup_color_code(const color_entry_t *entries, size_t entry_count, const char *name) {
  if (entries == NULL || name == NULL) {
    return NULL;
  }

  for (size_t idx = 0; idx < entry_count; ++idx) {
    if (strcasecmp(entries[idx].name, name) == 0) {
      return entries[idx].code;
    }
  }

  return NULL;
}

static const palette_descriptor_t *palette_find_descriptor(const char *name) {
  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  for (size_t idx = 0U; idx < sizeof(PALETTE_DEFINITIONS) / sizeof(PALETTE_DEFINITIONS[0]); ++idx) {
    if (strcasecmp(PALETTE_DEFINITIONS[idx].name, name) == 0) {
      return &PALETTE_DEFINITIONS[idx];
    }
  }

  return NULL;
}

static bool palette_apply_to_session(session_ctx_t *ctx, const palette_descriptor_t *descriptor) {
  if (ctx == NULL || descriptor == NULL) {
    return false;
  }

  const char *user_color_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->user_color_name);
  const char *user_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->user_highlight_name);
  const char *system_fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->system_fg_name);
  const char *system_bg_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_bg_name);
  const char *system_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_highlight_name);

  if (user_color_code == NULL || user_highlight_code == NULL || system_fg_code == NULL || system_bg_code == NULL ||
      system_highlight_code == NULL) {
    return false;
  }

  ctx->user_color_code = user_color_code;
  ctx->user_highlight_code = user_highlight_code;
  ctx->user_is_bold = descriptor->user_is_bold;
  snprintf(ctx->user_color_name, sizeof(ctx->user_color_name), "%s", descriptor->user_color_name);
  snprintf(ctx->user_highlight_name, sizeof(ctx->user_highlight_name), "%s", descriptor->user_highlight_name);

  ctx->system_fg_code = system_fg_code;
  ctx->system_bg_code = system_bg_code;
  ctx->system_highlight_code = system_highlight_code;
  ctx->system_is_bold = descriptor->system_is_bold;
  snprintf(ctx->system_fg_name, sizeof(ctx->system_fg_name), "%s", descriptor->system_fg_name);
  snprintf(ctx->system_bg_name, sizeof(ctx->system_bg_name), "%s", descriptor->system_bg_name);
  snprintf(ctx->system_highlight_name, sizeof(ctx->system_highlight_name), "%s", descriptor->system_highlight_name);

  session_force_dark_mode_foreground(ctx);

  return true;
}

static void host_apply_palette_descriptor(host_t *host, const palette_descriptor_t *descriptor) {
  if (host == NULL || descriptor == NULL) {
    return;
  }

  const char *user_color_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->user_color_name);
  const char *user_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->user_highlight_name);
  const char *system_fg_code =
      lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), descriptor->system_fg_name);
  const char *system_bg_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_bg_name);
  const char *system_highlight_code = lookup_color_code(
      HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), descriptor->system_highlight_name);

  if (user_color_code == NULL) {
    user_color_code = ANSI_GREEN;
  }
  if (user_highlight_code == NULL) {
    user_highlight_code = ANSI_BG_DEFAULT;
  }
  if (system_fg_code == NULL) {
    system_fg_code = ANSI_WHITE;
  }
  if (system_bg_code == NULL) {
    system_bg_code = ANSI_BG_BLUE;
  }
  if (system_highlight_code == NULL) {
    system_highlight_code = ANSI_BG_YELLOW;
  }

  host->user_theme.userColor = user_color_code;
  host->user_theme.highlight = user_highlight_code;
  host->user_theme.isBold = descriptor->user_is_bold;
  host->system_theme.foregroundColor = system_fg_code;
  host->system_theme.backgroundColor = system_bg_code;
  host->system_theme.highlightColor = system_highlight_code;
  host->system_theme.isBold = descriptor->system_is_bold;

  snprintf(host->default_user_color_name, sizeof(host->default_user_color_name), "%s", descriptor->user_color_name);
  snprintf(host->default_user_highlight_name, sizeof(host->default_user_highlight_name), "%s",
           descriptor->user_highlight_name);
  snprintf(host->default_system_fg_name, sizeof(host->default_system_fg_name), "%s", descriptor->system_fg_name);
  snprintf(host->default_system_bg_name, sizeof(host->default_system_bg_name), "%s", descriptor->system_bg_name);
  snprintf(host->default_system_highlight_name, sizeof(host->default_system_highlight_name), "%s",
           descriptor->system_highlight_name);
}

static bool parse_bool_token(const char *token, bool *value) {
  if (token == NULL || value == NULL) {
    return false;
  }

  if (strcasecmp(token, "true") == 0 || strcasecmp(token, "yes") == 0 || strcasecmp(token, "on") == 0 ||
      strcasecmp(token, "bold") == 0) {
    *value = true;
    return true;
  }

  if (strcasecmp(token, "false") == 0 || strcasecmp(token, "no") == 0 || strcasecmp(token, "off") == 0 ||
      strcasecmp(token, "normal") == 0) {
    *value = false;
    return true;
  }

  return false;
}

static bool session_transport_active(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    return ctx->telnet_fd >= 0 && !ctx->telnet_eof;
  }

  return ctx->channel != NULL;
}

static bool session_transport_is_open(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    return ctx->telnet_fd >= 0 && !ctx->telnet_eof;
  }

  return ctx->channel != NULL && ssh_channel_is_open(ctx->channel);
}

static bool session_transport_is_eof(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return true;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    return ctx->telnet_eof || ctx->telnet_fd < 0;
  }

  return ctx->channel == NULL || ssh_channel_is_eof(ctx->channel);
}

static void session_transport_request_close(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    if (ctx->telnet_fd >= 0) {
      shutdown(ctx->telnet_fd, SHUT_RDWR);
    }
    ctx->telnet_eof = true;
    return;
  }

  if (ctx->channel != NULL) {
    ssh_channel_send_eof(ctx->channel);
    ssh_channel_close(ctx->channel);
  }
}

static void session_close_channel(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    if (ctx->telnet_fd >= 0) {
      shutdown(ctx->telnet_fd, SHUT_RDWR);
      close(ctx->telnet_fd);
      ctx->telnet_fd = -1;
    }
    ctx->telnet_eof = true;
    return;
  }

  if (ctx->channel == NULL) {
    return;
  }

  ssh_channel_send_eof(ctx->channel);
  ssh_channel_close(ctx->channel);
  ssh_channel_free(ctx->channel);
  ctx->channel = NULL;
}

static void session_reset_for_retry(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_close_channel(ctx);
  ctx->should_exit = false;
  ctx->username_conflict = false;
  ctx->has_joined_room = false;
  ctx->input_length = 0U;
  ctx->input_buffer[0] = '\0';
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  ctx->input_escape_buffer[0] = '\0';
  ctx->bbs_post_pending = false;
  ctx->pending_bbs_title[0] = '\0';
  ctx->pending_bbs_body[0] = '\0';
  ctx->pending_bbs_body_length = 0U;
  ctx->pending_bbs_tag_count = 0U;
  memset(ctx->pending_bbs_tags, 0, sizeof(ctx->pending_bbs_tags));
  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;
  ctx->bbs_view_scroll_offset = 0U;
  ctx->bbs_view_total_lines = 0U;
  ctx->bbs_view_notice_pending = false;
  ctx->bbs_view_notice[0] = '\0';
  ctx->bbs_rendering_editor = false;
  ctx->bbs_breaking_count = 0U;
  memset(ctx->bbs_breaking_messages, 0, sizeof(ctx->bbs_breaking_messages));
  session_asciiart_reset(ctx);
  ctx->asciiart_has_cooldown = false;
  ctx->last_asciiart_post.tv_sec = 0;
  ctx->last_asciiart_post.tv_nsec = 0;
  session_game_tetris_reset(&ctx->game.tetris);
  ctx->game.liar.awaiting_guess = false;
  ctx->game.liar.round_number = 0U;
  ctx->game.liar.score = 0U;
  ctx->game.active = false;
  ctx->game.type = SESSION_GAME_NONE;
  ctx->game.rng_seeded = false;
  ctx->game.rng_state = 0U;
  ctx->game.alpha = (alpha_centauri_game_state_t){0};
  ctx->input_history_count = 0U;
  ctx->input_history_position = -1;
  ctx->history_scroll_position = 0U;
  ctx->has_last_message_time = false;
  ctx->last_message_time.tv_sec = 0;
  ctx->last_message_time.tv_nsec = 0;
  ctx->user_data_loaded = false;
  memset(&ctx->user_data, 0, sizeof(ctx->user_data));
}

static int host_telnet_open_socket(host_t *host) {
  if (host == NULL || host->telnet.port[0] == '\0') {
    return -1;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  const char *bind_addr = host->telnet.bind_address[0] != '\0' ? host->telnet.bind_address : NULL;
  struct addrinfo *result = NULL;
  int rc = getaddrinfo(bind_addr, host->telnet.port, &hints, &result);
  if (rc != 0) {
    printf("[telnet] failed to resolve %s:%s (%s)\n", bind_addr != NULL ? bind_addr : "*", host->telnet.port,
           gai_strerror(rc));
    return -1;
  }

  int fd = -1;
  for (struct addrinfo *ai = result; ai != NULL; ai = ai->ai_next) {
    int candidate = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (candidate < 0) {
      continue;
    }

    int enable = 1;
    setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    if (bind(candidate, ai->ai_addr, ai->ai_addrlen) != 0) {
      close(candidate);
      continue;
    }

    if (listen(candidate, 16) != 0) {
      close(candidate);
      continue;
    }

    fd = candidate;
    break;
  }

  freeaddrinfo(result);
  return fd;
}

static void *host_telnet_thread(void *arg) {
  host_t *host = (host_t *)arg;
  if (host == NULL) {
    return NULL;
  }

  atomic_store(&host->telnet.running, true);

  while (!atomic_load(&host->telnet.stop)) {
    if (host->telnet.fd < 0) {
      int fd = host_telnet_open_socket(host);
      if (fd < 0) {
        struct timespec backoff = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&backoff, NULL);
        continue;
      }

      host->telnet.fd = fd;
      const char *display_addr = host->telnet.bind_address[0] != '\0' ? host->telnet.bind_address : "*";
      printf("[telnet] listening on %s:%s\n", display_addr, host->telnet.port);
    }

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd = accept(host->telnet.fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (atomic_load(&host->telnet.stop)) {
        break;
      }
      humanized_log_error("telnet", "accept failed", errno);
      struct timespec backoff = {.tv_sec = 1, .tv_nsec = 0};
      nanosleep(&backoff, NULL);
      continue;
    }

    if (atomic_load(&host->telnet.stop)) {
      close(client_fd);
      break;
    }

    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    char peer_address[NI_MAXHOST];
    host_format_sockaddr((struct sockaddr *)&addr, addr_len, peer_address, sizeof(peer_address));
    if (peer_address[0] == '\0') {
      snprintf(peer_address, sizeof(peer_address), "%s", "unknown");
    }

    printf("[telnet] accepted client from %s\n", peer_address);

    session_ctx_t *ctx = calloc(1U, sizeof(session_ctx_t));
    if (ctx == NULL) {
      humanized_log_error("telnet", "failed to allocate session context", ENOMEM);
      close(client_fd);
      continue;
    }

    ctx->transport_kind = SESSION_TRANSPORT_TELNET;
    ctx->telnet_fd = client_fd;
    ctx->telnet_negotiated = false;
    ctx->telnet_eof = false;
    ctx->telnet_pending_valid = false;
    ctx->owner = host;
    ctx->auth = (auth_profile_t){0};
    snprintf(ctx->client_ip, sizeof(ctx->client_ip), "%.*s", (int)sizeof(ctx->client_ip) - 1, peer_address);
    ctx->input_mode = SESSION_INPUT_MODE_CHAT;

    pthread_mutex_lock(&host->lock);
    ++host->connection_count;
    snprintf(ctx->user.name, sizeof(ctx->user.name), "Guest%zu", host->connection_count);
    ctx->user.is_operator = false;
    ctx->user.is_lan_operator = false;
    pthread_mutex_unlock(&host->lock);

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, session_thread, ctx) != 0) {
      humanized_log_error("telnet", "failed to spawn session thread", errno);
      session_cleanup(ctx);
      continue;
    }

    pthread_detach(thread_id);
  }

  int listener_fd = host->telnet.fd;
  host->telnet.fd = -1;
  if (listener_fd >= 0) {
    close(listener_fd);
  }

  atomic_store(&host->telnet.running, false);
  return NULL;
}

static bool host_telnet_listener_start(host_t *host, const char *bind_addr, const char *port) {
  if (host == NULL || port == NULL || port[0] == '\0') {
    return false;
  }

  if (host->telnet.thread_initialized) {
    const bool same_port = strncmp(host->telnet.port, port, sizeof(host->telnet.port)) == 0;
    bool same_bind = false;
    if (bind_addr == NULL || bind_addr[0] == '\0') {
      same_bind = host->telnet.bind_address[0] == '\0';
    } else {
      same_bind = strncmp(host->telnet.bind_address, bind_addr, sizeof(host->telnet.bind_address)) == 0;
    }

    if (same_port && same_bind && atomic_load(&host->telnet.running)) {
      const char *display_addr = host->telnet.bind_address[0] != '\0' ? host->telnet.bind_address : "*";
      printf("[telnet] listener already active on %s:%s\n", display_addr, host->telnet.port);
      return true;
    }

    host_telnet_listener_stop(host);
  }

  if (bind_addr != NULL && bind_addr[0] != '\0') {
    snprintf(host->telnet.bind_address, sizeof(host->telnet.bind_address), "%s", bind_addr);
  } else {
    host->telnet.bind_address[0] = '\0';
  }
  snprintf(host->telnet.port, sizeof(host->telnet.port), "%s", port);
  host->telnet.enabled = true;
  host->telnet.fd = -1;
  host->telnet.restart_attempts = 0U;
  host->telnet.last_error_time.tv_sec = 0;
  host->telnet.last_error_time.tv_nsec = 0L;
  atomic_store(&host->telnet.stop, false);

  if (pthread_create(&host->telnet.thread, NULL, host_telnet_thread, host) != 0) {
    humanized_log_error("telnet", "failed to start telnet listener", errno);
    host->telnet.enabled = false;
    return false;
  }

  host->telnet.thread_initialized = true;
  return true;
}

static void host_telnet_listener_stop(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (!host->telnet.thread_initialized) {
    host->telnet.enabled = false;
    host->telnet.fd = -1;
    host->telnet.bind_address[0] = '\0';
    host->telnet.port[0] = '\0';
    atomic_store(&host->telnet.running, false);
    atomic_store(&host->telnet.stop, false);
    return;
  }

  const char *display_addr = host->telnet.bind_address[0] != '\0' ? host->telnet.bind_address : "*";
  printf("[telnet] stopping listener on %s:%s\n", display_addr, host->telnet.port);

  atomic_store(&host->telnet.stop, true);
  if (host->telnet.fd >= 0) {
    shutdown(host->telnet.fd, SHUT_RDWR);
  }

  int join_result = pthread_join(host->telnet.thread, NULL);
  if (join_result != 0) {
    humanized_log_error("telnet", "failed to join telnet listener", join_result);
  }

  host->telnet.thread_initialized = false;
  host->telnet.enabled = false;
  atomic_store(&host->telnet.running, false);
  atomic_store(&host->telnet.stop, false);

  if (host->telnet.fd >= 0) {
    close(host->telnet.fd);
    host->telnet.fd = -1;
  }

  host->telnet.bind_address[0] = '\0';
  host->telnet.port[0] = '\0';
}

static bool session_attempt_handshake_restart(session_ctx_t *ctx, unsigned int *attempts) {
  if (ctx == NULL || attempts == NULL) {
    return false;
  }

  if (!session_transport_active(ctx)) {
    return false;
  }

  if (*attempts >= SSH_CHATTER_HANDSHAKE_RETRY_LIMIT) {
    return false;
  }

  ++(*attempts);
  printf("[session] retrying handshake (attempt %u/%u)\n", *attempts, SSH_CHATTER_HANDSHAKE_RETRY_LIMIT);
  session_reset_for_retry(ctx);
  session_apply_theme_defaults(ctx);
  struct timespec backoff = {
      .tv_sec = 0,
      .tv_nsec = 200000000L,
  };
  nanosleep(&backoff, NULL);
  return true;
}

static void session_cleanup(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->user_data_loaded) {
    (void)session_user_data_commit(ctx);
  }

  session_translation_worker_shutdown(ctx);
  if (ctx->transport_kind == SESSION_TRANSPORT_SSH && ctx->channel != NULL) {
    ssh_channel_request_send_exit_status(ctx->channel, ctx->exit_status);
  }
  session_close_channel(ctx);

  if (ctx->session != NULL) {
    ssh_disconnect(ctx->session);
    ssh_free(ctx->session);
    ctx->session = NULL;
  }

  free(ctx);
}

static void *session_thread(void *arg) {
  session_ctx_t *ctx = (session_ctx_t *)arg;
  if (ctx == NULL) {
    return NULL;
  }

  ctx->exit_status = EXIT_FAILURE;
  session_apply_theme_defaults(ctx);

  bool authenticated = false;
  unsigned int handshake_retries = 0U;
  if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
    session_telnet_initialize(ctx);
    authenticated = true;
  }

  while (ctx->transport_kind == SESSION_TRANSPORT_SSH) {
    if (!authenticated) {
      if (session_authenticate(ctx) != 0) {
        humanized_log_error("session", "authentication failed", EACCES);
        session_cleanup(ctx);
        return NULL;
      }
      authenticated = true;
    }

    if (session_accept_channel(ctx) != 0) {
      humanized_log_error("session", "failed to open channel", EIO);
      if (session_attempt_handshake_restart(ctx, &handshake_retries)) {
        continue;
      }
      session_cleanup(ctx);
      return NULL;
    }

    if (session_prepare_shell(ctx) != 0) {
      humanized_log_error("session", "shell negotiation failed", EPROTO);
      if (session_attempt_handshake_restart(ctx, &handshake_retries)) {
        continue;
      }
      session_cleanup(ctx);
      return NULL;
    }

    break;
  }

  session_assign_lan_privileges(ctx);
  session_apply_granted_privileges(ctx);
  session_apply_saved_preferences(ctx);

  const bool captcha_exempt = session_is_captcha_exempt(ctx);
  if (!captcha_exempt && !session_run_captcha(ctx)) {
    session_cleanup(ctx);
    return NULL;
  }

  if (host_register_join_attempt(ctx->owner, ctx->user.name, ctx->client_ip)) {
    session_send_system_line(ctx, "Rapid reconnect detected. You have been banned.");
    session_cleanup(ctx);
    return NULL;
  }

  if (host_is_ip_banned(ctx->owner, ctx->client_ip) || host_is_username_banned(ctx->owner, ctx->user.name)) {
    session_send_system_line(ctx, "You are banned from this server.");
    session_cleanup(ctx);
    return NULL;
  }

  const bool reserved_username = host_username_reserved(ctx->owner, ctx->user.name);
  session_ctx_t *existing = chat_room_find_user(&ctx->owner->room, ctx->user.name);
  if (reserved_username || existing != NULL) {
    ctx->username_conflict = true;
    if (reserved_username) {
      printf("[reject] reserved username requested: %s\n", ctx->user.name);
    } else {
      printf("[reject] username in use: %s\n", ctx->user.name);
    }
    session_render_banner(ctx);
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    if (reserved_username) {
      snprintf(message, sizeof(message), "The username '%s' is reserved.", ctx->user.name);
    } else {
      snprintf(message, sizeof(message), "The username '%s' is already in use.", ctx->user.name);
    }
    session_send_system_line(ctx, message);
    session_send_system_line(ctx,
                             "Reconnect with a different username by running: ssh newname@<server> (or ssh -l newname <server>).");
    session_send_system_line(ctx, "Type /exit to quit.");
  } else {
    (void)host_try_load_motd_from_path(ctx->owner, "/etc/ssh-chatter/motd");
    session_send_system_line(ctx, "Wait for a moment...");
    struct timespec wait_time = {0, 0};
    size_t progress = host_prepare_join_delay(ctx->owner, &wait_time);
    if (progress == 0U) {
      progress = 1U;
    }
    if (progress > SSH_CHATTER_JOIN_BAR_MAX) {
      progress = SSH_CHATTER_JOIN_BAR_MAX;
    }
    char loading_line[SSH_CHATTER_MESSAGE_LIMIT];
    size_t written = 0U;
    for (size_t idx = 0; idx < progress && written + 1U < sizeof(loading_line); ++idx) {
      loading_line[written++] = '=';
    }
    if (written + 1U < sizeof(loading_line)) {
      loading_line[written++] = '>';
    }
    loading_line[written] = '\0';
    session_send_system_line(ctx, loading_line);
    if (wait_time.tv_sec != 0 || wait_time.tv_nsec != 0) {
      nanosleep(&wait_time, NULL);
    }
    chat_room_add(&ctx->owner->room, ctx);
    ctx->has_joined_room = true;
    printf("[join] %s\n", ctx->user.name);

    session_render_banner(ctx);
    session_send_history(ctx);
    host_refresh_motd(ctx->owner);
    if (ctx->owner->motd[0] != '\0') {
      session_send_system_line(ctx, ctx->owner->motd);
    }
    session_send_system_line(ctx, "Type /help to explore available commands.");
    session_send_system_line(ctx,
                             "Tip: /mode command lets you run commands without '/' and unlocks history (UpArrow/DownArrow) and Tab completion.");

    char join_message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(join_message, sizeof(join_message), "* [%s] has joined the chat", ctx->user.name);
    host_history_record_system(ctx->owner, join_message);
    chat_room_broadcast(&ctx->owner->room, join_message, NULL);
  }

  session_clear_input(ctx);
  session_render_prompt(ctx, true);

  char buffer[SSH_CHATTER_MAX_INPUT_LEN];
  const int poll_timeout_ms = 100;
  while (!ctx->should_exit) {
    session_translation_flush_ready(ctx);

    int read_result = session_transport_read(ctx, buffer, sizeof(buffer) - 1U, 200);
    if (read_result == SSH_AGAIN) {
      if (ctx->game.active && ctx->game.type == SESSION_GAME_TETRIS) {
        session_game_tetris_process_timeout(ctx);
      }
      continue;
    }
    if (read_result == SSH_ERROR) {
      if (ctx->transport_kind == SESSION_TRANSPORT_TELNET) {
        break;
      }
      read_result = session_channel_read_poll(ctx, buffer, sizeof(buffer) - 1U, poll_timeout_ms);
      if (read_result == SESSION_CHANNEL_TIMEOUT) {
        ctx->channel_error_retries = 0U;
        if (ctx->game.active && ctx->game.type == SESSION_GAME_TETRIS) {
          session_game_tetris_process_timeout(ctx);
        }
        continue;
      }

      if (read_result == SSH_ERROR) {
        const char *error_message = ssh_get_error(ctx->session);
        bool unexpected_bytes_error = false;
        if (error_message != NULL && error_message[0] != '\0') {
          unexpected_bytes_error = strstr(error_message, "unexpected bytes remain after decoding") != NULL;
        }

        if (unexpected_bytes_error) {
          const char *username = ctx->user.name[0] != '\0' ? ctx->user.name : "unknown";
          printf("[session] channel decode error for %s: %s\n", username, error_message);
          break;
        }

        if (ctx->has_joined_room && ctx->channel_error_retries < SSH_CHATTER_CHANNEL_RECOVERY_LIMIT) {
          ctx->channel_error_retries += 1U;
          if (error_message == NULL || error_message[0] == '\0') {
            error_message = "unknown channel error";
          }
          printf("[session] channel read error for %s (attempt %u/%u): %s\n", ctx->user.name,
                 ctx->channel_error_retries, SSH_CHATTER_CHANNEL_RECOVERY_LIMIT, error_message);
          struct timespec retry_delay = {
              .tv_sec = 0,
              .tv_nsec = SSH_CHATTER_CHANNEL_RECOVERY_DELAY_NS,
          };
          nanosleep(&retry_delay, NULL);
          continue;
        }

        if (ctx->has_joined_room) {
          if (error_message == NULL || error_message[0] == '\0') {
            error_message = "unknown channel error";
          }
          printf("[session] channel read failure for %s after %u retries: %s\n", ctx->user.name,
                 ctx->channel_error_retries, error_message);
        }
        break;
      }
      continue;
    }

    if (read_result == 0) {
      if (!session_transport_is_open(ctx) || session_transport_is_eof(ctx)) {
        break;
      }
      if (ctx->game.active && ctx->game.type == SESSION_GAME_TETRIS) {
        session_game_tetris_process_timeout(ctx);
      }
      continue;
    }

    ctx->channel_error_retries = 0U;

    if (read_result == 0) {
      break;
    }
    if (read_result < 0) {
      continue;
    }

    for (int idx = 0; idx < read_result; ++idx) {
      const char ch = buffer[idx];

      if (ctx->game.active && ctx->game.type == SESSION_GAME_TETRIS) {
        if (session_game_tetris_process_raw_input(ctx, ch)) {
          continue;
        }
      }

      if (session_consume_escape_sequence(ctx, ch)) {
        continue;
      }

      if (ch == 0x01) {
        if (ctx->bbs_post_pending || ctx->asciiart_pending) {
          ctx->input_buffer[ctx->input_length] = '\0';
          session_apply_background_fill(ctx);
          if (ctx->bbs_post_pending) {
            session_bbs_reset_pending_post(ctx);
            session_send_system_line(ctx, "BBS draft canceled.");
          } else {
            const char *cancel_message =
                (ctx->asciiart_target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE)
                    ? "Profile picture draft canceled."
                    : "ASCII art draft canceled.";
            session_asciiart_cancel(ctx, cancel_message);
          }
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        }
        continue;
      }

      if (ch == 0x03) {
        ctx->input_buffer[ctx->input_length] = '\0';
        session_apply_background_fill(ctx);
        session_handle_exit(ctx);
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
        continue;
      }

      if (ch == 0x1a) {
        ctx->input_buffer[ctx->input_length] = '\0';
        session_apply_background_fill(ctx);
        if (ctx->in_rss_mode) {
          session_rss_exit(ctx, NULL);
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        } else if (ctx->game.active) {
          session_game_suspend(ctx, "Game suspended.");
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        } else {
          session_handle_exit(ctx);
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        }
        continue;
      }

      if (ch == 0x13) {
        if (ctx->bbs_post_pending || ctx->asciiart_pending) {
          ctx->input_buffer[ctx->input_length] = '\0';
          bool had_body = ctx->input_length > 0U;
          if (had_body) {
            session_local_echo_char(ctx, '\n');
            session_history_record(ctx, ctx->input_buffer);
            if (ctx->bbs_post_pending) {
              session_bbs_capture_body_text(ctx, ctx->input_buffer);
            } else {
              session_asciiart_capture_text(ctx, ctx->input_buffer);
            }
          } else {
            session_local_echo_char(ctx, '\n');
          }

          const char *terminator = ctx->bbs_post_pending ? SSH_CHATTER_BBS_TERMINATOR : SSH_CHATTER_ASCIIART_TERMINATOR;
          for (const char *cursor = terminator; *cursor != '\0'; ++cursor) {
            session_local_echo_char(ctx, *cursor);
          }
          session_local_echo_char(ctx, '\n');
          session_history_record(ctx, terminator);
          if (ctx->bbs_post_pending) {
            session_bbs_capture_body_line(ctx, terminator);
          } else {
            session_asciiart_capture_line(ctx, terminator);
          }
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        } else if (ctx->game.active && ctx->game.type == SESSION_GAME_ALPHA) {
          session_game_alpha_manual_save(ctx);
        }
        continue;
      }

      if (ch == '\r' || ch == '\n') {
        session_apply_background_fill(ctx);
        const bool composing_draft = ctx->bbs_post_pending || ctx->asciiart_pending;
        if (ctx->input_length > 0U) {
          ctx->input_buffer[ctx->input_length] = '\0';
          session_history_record(ctx, ctx->input_buffer);
          session_process_line(ctx, ctx->input_buffer);
        } else if (composing_draft) {
          session_process_line(ctx, "");
        }
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        if (!ctx->bracket_paste_active) {
          session_render_prompt(ctx, false);
        }
        continue;
      }

      if (ch == '\b' || ch == 0x7f) {
        ctx->input_history_position = -1;
        ctx->history_scroll_position = 0U;
        session_local_backspace(ctx);
        continue;
      }

      if (ch == '\t') {
        if (session_try_command_completion(ctx)) {
          continue;
        }
        if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
          ctx->input_history_position = -1;
          ctx->history_scroll_position = 0U;
          ctx->input_buffer[ctx->input_length++] = ' ';
          session_local_echo_char(ctx, ' ');
        }
        continue;
      }

      if ((unsigned char)ch < 0x20U) {
        continue;
      }

      if (ctx->input_length + 1U >= sizeof(ctx->input_buffer)) {
        ctx->input_buffer[sizeof(ctx->input_buffer) - 1U] = '\0';
        session_history_record(ctx, ctx->input_buffer);
        session_process_line(ctx, ctx->input_buffer);
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
      }

      if (ctx->input_length + 1U < sizeof(ctx->input_buffer)) {
        ctx->input_history_position = -1;
        ctx->history_scroll_position = 0U;
        ctx->input_buffer[ctx->input_length++] = ch;
        session_local_echo_char(ctx, ch);
      }
    }

    if (ctx->should_exit) {
      break;
    }
  }

  session_translation_flush_ready(ctx);

  if (!ctx->should_exit && ctx->input_length > 0U) {
    ctx->input_buffer[ctx->input_length] = '\0';
    session_history_record(ctx, ctx->input_buffer);
    session_process_line(ctx, ctx->input_buffer);
    session_clear_input(ctx);
  }

  if (ctx->has_joined_room) {
    printf("[part] %s\n", ctx->user.name);
    char part_message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(part_message, sizeof(part_message), "* [%s] has left the chat", ctx->user.name);
    host_history_record_system(ctx->owner, part_message);
    chat_room_broadcast(&ctx->owner->room, part_message, NULL);
    chat_room_remove(&ctx->owner->room, ctx);
  }

  session_cleanup(ctx);

  return NULL;
}

void host_init(host_t *host, auth_profile_t *auth) {
  if (host == NULL) {
    return;
  }

  translator_global_init();

  chat_room_init(&host->room);
  host->listener.handle = NULL;
  host->listener.inplace_recoveries = 0U;
  host->listener.restart_attempts = 0U;
  host->listener.last_error_time.tv_sec = 0;
  host->listener.last_error_time.tv_nsec = 0L;
  host->telnet.enabled = false;
  host->telnet.fd = -1;
  host->telnet.thread_initialized = false;
  atomic_store(&host->telnet.running, false);
  atomic_store(&host->telnet.stop, false);
  host->telnet.restart_attempts = 0U;
  host->telnet.last_error_time.tv_sec = 0;
  host->telnet.last_error_time.tv_nsec = 0L;
  host->telnet.bind_address[0] = '\0';
  host->telnet.port[0] = '\0';
  host->auth = auth;
  host->clients = NULL;
  host->web_client = NULL;
  const palette_descriptor_t *default_palette = palette_find_descriptor("clean");
  if (default_palette != NULL) {
    host_apply_palette_descriptor(host, default_palette);
  } else {
    host->user_theme.userColor = ANSI_GREEN;
    host->user_theme.highlight = ANSI_BG_DEFAULT;
    host->user_theme.isBold = false;
    host->system_theme.backgroundColor = ANSI_BG_BLUE;
    host->system_theme.foregroundColor = ANSI_WHITE;
    host->system_theme.highlightColor = ANSI_BG_YELLOW;
    host->system_theme.isBold = true;
    snprintf(host->default_user_color_name, sizeof(host->default_user_color_name), "%s", "green");
    snprintf(host->default_user_highlight_name, sizeof(host->default_user_highlight_name), "%s", "default");
    snprintf(host->default_system_fg_name, sizeof(host->default_system_fg_name), "%s", "white");
    snprintf(host->default_system_bg_name, sizeof(host->default_system_bg_name), "%s", "blue");
    snprintf(host->default_system_highlight_name, sizeof(host->default_system_highlight_name), "%s", "yellow");
  }
  host->ban_count = 0U;
  memset(host->bans, 0, sizeof(host->bans));
  memset(host->replies, 0, sizeof(host->replies));
  host->reply_count = 0U;
  host->next_reply_id = 1U;
  memset(host->eliza_memory, 0, sizeof(host->eliza_memory));
  host->eliza_memory_count = 0U;
  host->eliza_memory_next_id = 1U;
  snprintf(host->version, sizeof(host->version), "ssh-chatter (C, rolling release)");
  snprintf(host->motd_base, sizeof(host->motd_base),
           "Welcome to ssh-chat!\n"
           "- Be polite to each other\n"
           "- fun fact: this server is written in pure c.\n"
           "============================================\n"
           " _      ____  ____  _____ ____  _        ____  _ \n"
           "/ \\__/|/  _ \\/  _ \\/  __//  __\\/ \\  /|  /   _\\/ \\\n"
           "| |\\/||| / \\|| | \\||  \\  |  \\/|| |\\ ||  |  /  | |\n"
           "| |  ||| \\_/|| |_/||  /_ |    /| | \\||  |  \\__\\_/\n"
           "\\_/  \\|\\____/\\____/\\____\\\\_/\\_\\\\_/  \\|  \\____/(_)\n"
           "                                                 \n"
           "============================================\n");
  snprintf(host->motd, sizeof(host->motd), "%s", host->motd_base);
  host->motd_path[0] = '\0';
  host->motd_has_file = false;
  host->motd_last_modified.tv_sec = 0;
  host->motd_last_modified.tv_nsec = 0L;


  host->translation_quota_exhausted = false;
  host->connection_count = 0U;
  host->history = NULL;
  host->history_count = 0U;
  host->history_capacity = 0U;
  host->next_message_id = 1U;
  memset(host->preferences, 0, sizeof(host->preferences));
  host->preference_count = 0U;
  host->state_file_path[0] = '\0';
  host_state_resolve_path(host);
  host->bbs_state_file_path[0] = '\0';
  host_bbs_resolve_path(host);
  host->vote_state_file_path[0] = '\0';
  host_vote_resolve_path(host);
  host->ban_state_file_path[0] = '\0';
  host_ban_resolve_path(host);
  host->reply_state_file_path[0] = '\0';
  host_reply_state_resolve_path(host);
  snprintf(host->user_data_root, sizeof(host->user_data_root), "%s", "/var/lib/mailbox");
  host->user_data_ready = user_data_ensure_root(host->user_data_root);
  if (pthread_mutex_init(&host->user_data_lock, NULL) == 0) {
    host->user_data_lock_initialized = true;
  } else {
    humanized_log_error("mailbox", "failed to initialise mailbox lock", errno != 0 ? errno : ENOMEM);
    host->user_data_lock_initialized = false;
    host->user_data_ready = false;
  }
  host->rss_state_file_path[0] = '\0';
  host_rss_resolve_path(host);
  host->eliza_memory_file_path[0] = '\0';
  host_eliza_memory_resolve_path(host);
  host->eliza_state_file_path[0] = '\0';
  host_eliza_state_resolve_path(host);
  host->security_clamav_thread_initialized = false;
  atomic_store(&host->security_clamav_thread_running, false);
  atomic_store(&host->security_clamav_thread_stop, false);
  host->security_clamav_last_run.tv_sec = 0;
  host->security_clamav_last_run.tv_nsec = 0;
  host->bbs_watchdog_thread_initialized = false;
  atomic_store(&host->bbs_watchdog_thread_running, false);
  atomic_store(&host->bbs_watchdog_thread_stop, false);
  host->bbs_watchdog_last_run.tv_sec = 0;
  host->bbs_watchdog_last_run.tv_nsec = 0;
  host->rss_thread_initialized = false;
  atomic_store(&host->rss_thread_running, false);
  atomic_store(&host->rss_thread_stop, false);
  host->rss_last_run.tv_sec = 0;
  host->rss_last_run.tv_nsec = 0L;
  host_security_configure(host);
  pthread_mutex_init(&host->lock, NULL);
  poll_state_reset(&host->poll);
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    named_poll_reset(&host->named_polls[idx]);
  }
  host->named_poll_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    host->bbs_posts[idx].in_use = false;
    host->bbs_posts[idx].id = 0U;
    host->bbs_posts[idx].author[0] = '\0';
    host->bbs_posts[idx].title[0] = '\0';
    host->bbs_posts[idx].body[0] = '\0';
    host->bbs_posts[idx].tag_count = 0U;
    host->bbs_posts[idx].created_at = 0;
    host->bbs_posts[idx].bumped_at = 0;
    host->bbs_posts[idx].comment_count = 0U;
    for (size_t comment = 0U; comment < SSH_CHATTER_BBS_MAX_COMMENTS; ++comment) {
      host->bbs_posts[idx].comments[comment].author[0] = '\0';
      host->bbs_posts[idx].comments[comment].text[0] = '\0';
      host->bbs_posts[idx].comments[comment].created_at = 0;
    }
  }
  host->bbs_post_count = 0U;
  host->next_bbs_id = 1U;
  for (size_t idx = 0U; idx < SSH_CHATTER_RSS_MAX_FEEDS; ++idx) {
    host_clear_rss_feed(&host->rss_feeds[idx]);
  }
  host->rss_feed_count = 0U;
  host->random_seeded = false;
  memset(host->operator_grants, 0, sizeof(host->operator_grants));
  host->operator_grant_count = 0U;
  host->next_join_ready_time = (struct timespec){0, 0};
  host->join_throttle_initialised = false;
  host->join_progress_length = 0U;
  host->join_activity = NULL;
  host->join_activity_count = 0U;
  host->join_activity_capacity = 0U;
  host->captcha_nonce = 0U;
  host->has_last_captcha = false;
  host->last_captcha_question[0] = '\0';
  host->last_captcha_answer[0] = '\0';
  host->last_captcha_generated.tv_sec = 0;
  host->last_captcha_generated.tv_nsec = 0L;
  atomic_store(&host->eliza_enabled, false);
  atomic_store(&host->eliza_announced, false);
  host->eliza_last_action.tv_sec = 0;
  host->eliza_last_action.tv_nsec = 0L;

  (void)host_try_load_motd_from_path(host, "/etc/ssh-chatter/motd");

  host_state_load(host);
  host_vote_state_load(host);
  host_bbs_state_load(host);
  host_ban_state_load(host);
  host_reply_state_load(host);
  host_rss_state_load(host);
  host_eliza_memory_load(host);
  host_eliza_state_load(host);

  host_user_data_bootstrap(host);

  host_refresh_motd(host);

  host->clients = client_manager_create(host);
  if (host->clients == NULL) {
    humanized_log_error("host", "failed to create client manager", ENOMEM);
  } else {
    host->web_client = webssh_client_create(host, host->clients);
    if (host->web_client == NULL) {
      humanized_log_error("host", "failed to initialise webssh client", ENOMEM);
    }

  }
  host_security_start_clamav_backend(host);
  host_bbs_start_watchdog(host);
  host_rss_start_backend(host);
}

static void host_build_birthday_notice_locked(host_t *host, char *line, size_t length) {
  if (line == NULL || length == 0U) {
    return;
  }

  line[0] = '\0';

  if (host == NULL) {
    return;
  }

  time_t now = time(NULL);
  if (now == (time_t)-1) {
    return;
  }

  struct tm local_now;
  if (localtime_r(&now, &local_now) == NULL) {
    return;
  }

  struct tm today_tm = local_now;
  today_tm.tm_hour = 0;
  today_tm.tm_min = 0;
  today_tm.tm_sec = 0;
  today_tm.tm_isdst = -1;
  time_t today = mktime(&today_tm);
  if (today == (time_t)-1) {
    today = now;
  }

  char names[SSH_CHATTER_MESSAGE_LIMIT];
  names[0] = '\0';
  size_t name_count = 0U;

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_PREFERENCES; ++idx) {
    const user_preference_t *pref = &host->preferences[idx];
    if (!pref->in_use || !pref->has_birthday) {
      continue;
    }
    if (pref->username[0] == '\0' || pref->birthday[0] == '\0') {
      continue;
    }

    int month = 0;
    int day = 0;
    if (sscanf(pref->birthday, "%*d-%d-%d", &month, &day) != 2) {
      continue;
    }
    if (month < 1 || month > 12 || day < 1 || day > 31) {
      continue;
    }

    int use_day = day;
    int use_month = month;
    const int current_year = local_now.tm_year + 1900;
    if (use_month == 2 && use_day == 29 && !host_is_leap_year(current_year)) {
      use_day = 28;
    }

    struct tm birthday_tm = today_tm;
    birthday_tm.tm_year = local_now.tm_year;
    birthday_tm.tm_mon = use_month - 1;
    birthday_tm.tm_mday = use_day;
    birthday_tm.tm_hour = 0;
    birthday_tm.tm_min = 0;
    birthday_tm.tm_sec = 0;
    birthday_tm.tm_isdst = -1;
    time_t birthday_time = mktime(&birthday_tm);
    if (birthday_time == (time_t)-1) {
      continue;
    }

    time_t diff = today - birthday_time;
    if (diff < 0) {
      birthday_tm.tm_year -= 1;
      birthday_tm.tm_isdst = -1;
      birthday_time = mktime(&birthday_tm);
      if (birthday_time == (time_t)-1) {
        continue;
      }
      diff = today - birthday_time;
    }

    if (diff < 0 || diff >= (time_t)SSH_CHATTER_BIRTHDAY_WINDOW_SECONDS) {
      continue;
    }

    size_t current_len = strnlen(names, sizeof(names));
    const size_t name_len = strnlen(pref->username, sizeof(pref->username));
    if (name_len == 0U) {
      continue;
    }

    if (current_len > 0U) {
      if (current_len + 2U >= sizeof(names)) {
        continue;
      }
      names[current_len++] = ',';
      names[current_len++] = ' ';
      names[current_len] = '\0';
    }

    if (name_len >= sizeof(names) - current_len) {
      continue;
    }

    memcpy(names + current_len, pref->username, name_len);
    current_len += name_len;
    names[current_len] = '\0';
    ++name_count;
  }

  if (name_count == 0U) {
    return;
  }

  snprintf(line, length, "Happy birthday to %s!\n", names);
}

static void host_refresh_motd_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  char birthday_line[SSH_CHATTER_MESSAGE_LIMIT];
  host_build_birthday_notice_locked(host, birthday_line, sizeof(birthday_line));

  if (birthday_line[0] != '\0') {
    snprintf(host->motd, sizeof(host->motd), "%s%s", birthday_line, host->motd_base);
  } else {
    snprintf(host->motd, sizeof(host->motd), "%s", host->motd_base);
  }
}

static void host_refresh_motd(host_t *host) {
  if (host == NULL) {
    return;
  }

  host_maybe_reload_motd_from_file(host);

  pthread_mutex_lock(&host->lock);
  host_refresh_motd_locked(host);
  pthread_mutex_unlock(&host->lock);
}

static bool host_try_load_motd_from_path(host_t *host, const char *path) {
  if (host == NULL || path == NULL || path[0] == '\0') {
    return false;
  }

  FILE *motd_file = fopen(path, "rb");
  if (motd_file == NULL) {
    return false;
  }

  struct stat file_info;
  bool have_info = false;
  struct timespec modified = {0, 0};
  int descriptor = fileno(motd_file);
  if (descriptor >= 0 && fstat(descriptor, &file_info) == 0) {
    modified = host_stat_mtime(&file_info);
    have_info = true;
  } else {
    time_t now = time(NULL);
    if (now != (time_t)-1) {
      modified.tv_sec = now;
      modified.tv_nsec = 0L;
      have_info = true;
    }
  }

  char motd_buffer[sizeof(host->motd)];
  size_t total_read = 0U;
  // TODO: Extract a shared helper (e.g. host_read_text_file) so these buffered
  // reads share the same error handling path as other file loaders.
  while (total_read < sizeof(motd_buffer) - 1U) {
    const size_t bytes_to_read = sizeof(motd_buffer) - 1U - total_read;
    const size_t chunk = fread(motd_buffer + total_read, 1U, bytes_to_read, motd_file);
    if (chunk == 0U) {
      if (ferror(motd_file)) {
        const int read_error = errno;
        const int close_result = fclose(motd_file);
        if (close_result != 0) {
          const int close_error = errno;
          humanized_log_error("host", "failed to close motd file", close_error);
        }
        humanized_log_error("host", "failed to read motd file", read_error);
        return false;
      }
      break;
    }
    total_read += chunk;
    if (feof(motd_file)) {
      break;
    }
  }

  motd_buffer[total_read] = '\0';

  if (fclose(motd_file) != 0) {
    const int close_error = errno;
    humanized_log_error("host", "failed to close motd file", close_error);
  }

  session_normalize_newlines(motd_buffer);

  pthread_mutex_lock(&host->lock);
  char motd_clean[4096];
  motd_clean[0] = '\0';
  size_t offset = 0U;
  char *next_line;
  char *motd_line = strtok_r(motd_buffer, "\n", &next_line);
  while (motd_line != NULL && offset < sizeof(motd_clean)) {
    const int written =
        snprintf(motd_clean + offset, sizeof(motd_clean) - offset, "%s\n", motd_line);
    if (written < 0 || (size_t)written >= sizeof(motd_clean) - offset) {
      offset = sizeof(motd_clean) - 1U;
      break;
    }
    offset += (size_t)written;
    motd_line = strtok_r(NULL, "\n", &next_line);
  }
  motd_clean[sizeof(motd_clean) - 1U] = '\0';
  snprintf(host->motd_base, sizeof(host->motd_base), "%s", motd_clean);
  snprintf(host->motd_path, sizeof(host->motd_path), "%s", path);
  host->motd_has_file = true;
  if (have_info) {
    host->motd_last_modified = modified;
  } else {
    host->motd_last_modified.tv_sec = 0;
    host->motd_last_modified.tv_nsec = 0L;
  }
  host_refresh_motd_locked(host);
  pthread_mutex_unlock(&host->lock);
  return true;
}

void host_set_motd(host_t *host, const char *motd) {
  if (host == NULL || motd == NULL) {
    return;
  }

  char motd_path[PATH_MAX];
  motd_path[0] = '\0';
  snprintf(motd_path, sizeof(motd_path), "%s", motd);
  trim_whitespace_inplace(motd_path);

  const size_t max_paths = 2U;
  const char *paths_to_try[2] = {NULL, NULL};
  size_t path_count = 0U;

  char expanded_path[PATH_MAX];
  expanded_path[0] = '\0';
  if (motd_path[0] == '~') {
    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0' &&
        (motd_path[1] == '\0' || motd_path[1] == '/')) {
      const int written = snprintf(expanded_path, sizeof(expanded_path), "%s%s", home, motd_path + 1);
      if (written > 0 && (size_t)written < sizeof(expanded_path) && path_count < max_paths) {
        paths_to_try[path_count++] = expanded_path;
      }
    }
  }

  if (motd_path[0] != '\0') {
    if (path_count < max_paths) {
      paths_to_try[path_count++] = motd_path;
    }
  }

  for (size_t idx = 0U; idx < path_count; ++idx) {
    if (paths_to_try[idx] != NULL && host_try_load_motd_from_path(host, paths_to_try[idx])) {
      return;
    }
  }

  char normalized[sizeof(host->motd)];
  snprintf(normalized, sizeof(normalized), "%s", motd);
  session_normalize_newlines(normalized);

  pthread_mutex_lock(&host->lock);
  if (motd_path[0] != '\0') {
    snprintf(host->motd_path, sizeof(host->motd_path), "%s", motd_path);
  } else {
    host->motd_path[0] = '\0';
  }
  host->motd_has_file = false;
  host->motd_last_modified.tv_sec = 0;
  host->motd_last_modified.tv_nsec = 0L;
  snprintf(host->motd_base, sizeof(host->motd_base), "%s", normalized);
  host_refresh_motd_locked(host);
  pthread_mutex_unlock(&host->lock);
}

bool host_post_client_message(host_t *host, const char *username, const char *message, const char *color_name,
                             const char *highlight_name, bool is_bold) {
  if (host == NULL || username == NULL || username[0] == '\0' || message == NULL) {
    return false;
  }

  chat_history_entry_t entry = {0};
  entry.is_user_message = true;
  snprintf(entry.username, sizeof(entry.username), "%s", username);
  snprintf(entry.message, sizeof(entry.message), "%s", message);
  entry.attachment_type = CHAT_ATTACHMENT_NONE;
  entry.user_is_bold = is_bold;

  const char *color_label = (color_name != NULL && color_name[0] != '\0') ? color_name : host->default_user_color_name;
  snprintf(entry.user_color_name, sizeof(entry.user_color_name), "%s", color_label);
  const char *highlight_label =
      (highlight_name != NULL && highlight_name[0] != '\0') ? highlight_name : host->default_user_highlight_name;
  snprintf(entry.user_highlight_name, sizeof(entry.user_highlight_name), "%s", highlight_label);

  const char *color_code = lookup_color_code(USER_COLOR_MAP, sizeof(USER_COLOR_MAP) / sizeof(USER_COLOR_MAP[0]), color_label);
  const char *highlight_code =
      lookup_color_code(HIGHLIGHT_COLOR_MAP, sizeof(HIGHLIGHT_COLOR_MAP) / sizeof(HIGHLIGHT_COLOR_MAP[0]), highlight_label);
  entry.user_color_code = color_code != NULL ? color_code : host->user_theme.userColor;
  entry.user_highlight_code = highlight_code != NULL ? highlight_code : host->user_theme.highlight;

  chat_history_entry_t stored = {0};
  if (!host_history_commit_entry(host, &entry, &stored)) {
    return false;
  }

  chat_room_broadcast_entry(&host->room, &stored, NULL);
  host_notify_external_clients(host, &stored);
  return true;
}

bool host_snapshot_last_captcha(host_t *host, char *question, size_t question_length, char *answer,
                               size_t answer_length, struct timespec *timestamp) {
  if (host == NULL) {
    return false;
  }

  pthread_mutex_lock(&host->lock);
  bool has_captcha = host->has_last_captcha;
  if (has_captcha) {
    if (question != NULL && question_length > 0U) {
      snprintf(question, question_length, "%s", host->last_captcha_question);
    }
    if (answer != NULL && answer_length > 0U) {
      snprintf(answer, answer_length, "%s", host->last_captcha_answer);
    }
    if (timestamp != NULL) {
      *timestamp = host->last_captcha_generated;
    }
  } else {
    if (question != NULL && question_length > 0U) {
      question[0] = '\0';
    }
    if (answer != NULL && answer_length > 0U) {
      answer[0] = '\0';
    }
    if (timestamp != NULL) {
      timestamp->tv_sec = 0;
      timestamp->tv_nsec = 0L;
    }
  }
  pthread_mutex_unlock(&host->lock);
  return has_captcha;
}

static void host_sleep_after_error(void) {
  struct timespec delay = {
      .tv_sec = 1,
      .tv_nsec = 0,
  };
  nanosleep(&delay, NULL);
}

void host_shutdown(host_t *host) {
  if (host == NULL) {
    return;
  }

  host_telnet_listener_stop(host);

  if (host->rss_thread_initialized) {
    atomic_store(&host->rss_thread_stop, true);
    pthread_join(host->rss_thread, NULL);
    host->rss_thread_initialized = false;
    atomic_store(&host->rss_thread_running, false);
  }

  if (host->security_clamav_thread_initialized) {
    atomic_store(&host->security_clamav_thread_stop, true);
    pthread_join(host->security_clamav_thread, NULL);
    host->security_clamav_thread_initialized = false;
    atomic_store(&host->security_clamav_thread_running, false);
  }

  if (host->bbs_watchdog_thread_initialized) {
    atomic_store(&host->bbs_watchdog_thread_stop, true);
    pthread_join(host->bbs_watchdog_thread, NULL);
    host->bbs_watchdog_thread_initialized = false;
    atomic_store(&host->bbs_watchdog_thread_running, false);
  }

  if (host->web_client != NULL) {
    webssh_client_destroy(host->web_client);
    host->web_client = NULL;
  }
  if (host->clients != NULL) {
    client_manager_destroy(host->clients);
    host->clients = NULL;
  }
  pthread_mutex_lock(&host->lock);
  free(host->history);
  host->history = NULL;
  host->history_capacity = 0U;
  host->history_count = 0U;
  pthread_mutex_unlock(&host->lock);
  free(host->join_activity);
  host->join_activity = NULL;
  host->join_activity_capacity = 0U;
  host->join_activity_count = 0U;
  pthread_mutex_lock(&host->room.lock);
  free(host->room.members);
  host->room.members = NULL;
  host->room.member_capacity = 0U;
  host->room.member_count = 0U;
  pthread_mutex_unlock(&host->room.lock);
  if (host->user_data_lock_initialized) {
    pthread_mutex_destroy(&host->user_data_lock);
    host->user_data_lock_initialized = false;
  }
}

int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory,
               const char *telnet_bind_addr, const char *telnet_port) {
  if (host == NULL) {
    return -1;
  }

  const char *address = (bind_addr != NULL && bind_addr[0] != '\0') ? bind_addr : "0.0.0.0";
  const char *bind_port = (port != NULL && port[0] != '\0') ? port : "2222";
  const char *telnet_bind = NULL;
  if (telnet_bind_addr != NULL) {
    telnet_bind = telnet_bind_addr;
  } else if (bind_addr != NULL && bind_addr[0] != '\0') {
    telnet_bind = bind_addr;
  } else {
    telnet_bind = address;
  }
  if (telnet_port != NULL && telnet_port[0] != '\0') {
    if (!host_telnet_listener_start(host, telnet_bind, telnet_port)) {
      const char *display_addr = (telnet_bind != NULL && telnet_bind[0] != '\0') ? telnet_bind : "*";
      printf("[telnet] telnet listener unavailable on %s:%s\n", display_addr, telnet_port);
    }
  } else {
    host_telnet_listener_stop(host);
  }
  const bool key_dir_specified = key_directory != NULL && key_directory[0] != '\0';
  const host_key_definition_t host_key_definitions[] = {
      {"ssh-ed25519", "ssh_host_ed25519_key", SSH_BIND_OPTIONS_IMPORT_KEY, true},
      {"ecdsa-sha2-nistp256", "ssh_host_ecdsa_key", SSH_BIND_OPTIONS_ECDSAKEY, false},
      {"ssh-rsa", "ssh_host_rsa_key", SSH_BIND_OPTIONS_RSAKEY, false},
  };
  const size_t host_key_count = sizeof(host_key_definitions) / sizeof(host_key_definitions[0]);

  while (true) {
    ssh_bind bind_handle = ssh_bind_new();
    if (bind_handle == NULL) {
      humanized_log_error("host", "failed to allocate ssh_bind", ENOMEM);
      host_sleep_after_error();
      continue;
    }

    ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
    ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);

    bool fatal_key_error = false;
    bool key_loaded = false;
    char preferred_algorithm[64];
    preferred_algorithm[0] = '\0';
    char algorithm_buffer[256];
    algorithm_buffer[0] = '\0';
    size_t algorithm_length = 0U;

    for (size_t idx = 0; idx < host_key_count; ++idx) {
      const host_key_definition_t *definition = &host_key_definitions[idx];
      char key_path[PATH_MAX];
      bool path_valid = false;
      char custom_candidate[PATH_MAX];
      bool attempted_custom = false;

      if (key_dir_specified) {
        attempted_custom = true;
        if (!host_join_key_path(key_directory, definition->filename, custom_candidate, sizeof(custom_candidate))) {
          humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
          fatal_key_error = true;
          break;
        }
        if (access(custom_candidate, R_OK) == 0) {
          snprintf(key_path, sizeof(key_path), "%s", custom_candidate);
          path_valid = true;
        }
      }

      if (!path_valid) {
        if (access(definition->filename, R_OK) == 0) {
          snprintf(key_path, sizeof(key_path), "%s", definition->filename);
          path_valid = true;
        } else {
          char fallback_path[PATH_MAX];
          const int written = snprintf(fallback_path, sizeof(fallback_path), "/etc/ssh/%s", definition->filename);
          if (written >= 0 && (size_t)written < sizeof(fallback_path) && access(fallback_path, R_OK) == 0) {
            snprintf(key_path, sizeof(key_path), "%s", fallback_path);
            path_valid = true;
          }
        }
      }

      if (!path_valid) {
        if (attempted_custom) {
          printf("[listener] %s host key not found at %s (skipping)\n", definition->algorithm, custom_candidate);
        }
        continue;
      }

      if (attempted_custom && strcmp(key_path, custom_candidate) != 0) {
        printf("[listener] using fallback %s host key from %s\n", definition->algorithm, key_path);
      }

      if (!host_bind_load_key(bind_handle, definition, key_path)) {
        continue;
      }

      if (!key_loaded) {
        snprintf(preferred_algorithm, sizeof(preferred_algorithm), "%s", definition->algorithm);
      }
      host_bind_append_algorithm(algorithm_buffer, sizeof(algorithm_buffer), &algorithm_length, definition->algorithm);
      key_loaded = true;
      printf("[listener] loaded %s host key from %s\n", definition->algorithm, key_path);
    }

    if (fatal_key_error) {
      ssh_bind_free(bind_handle);
      host_sleep_after_error();
      continue;
    }

    if (!key_loaded) {
      humanized_log_error("host", "no usable host keys found", ENOENT);
      ssh_bind_free(bind_handle);
      host_sleep_after_error();
      continue;
    }

    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, algorithm_buffer,
                                  "failed to configure host key algorithms");
    if (preferred_algorithm[0] != '\0') {
      host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HOSTKEY, preferred_algorithm,
                                    "failed to configure preferred host key");
    }
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_KEY_EXCHANGE, SSH_CHATTER_SUPPORTED_KEX_ALGORITHMS,
                                  "failed to configure key exchange algorithms");

    if (ssh_bind_listen(bind_handle) < 0) {
      humanized_log_error("host", ssh_get_error(bind_handle), EIO);
      ssh_bind_free(bind_handle);
      host_sleep_after_error();
      continue;
    }

    host->listener.handle = bind_handle;
    host->listener.last_error_time.tv_sec = 0;
    host->listener.last_error_time.tv_nsec = 0L;
    printf("[listener] listening on %s:%s\n", address, bind_port);

    bool restart_listener = false;
    while (!restart_listener) {
      ssh_session session = ssh_new();
      if (session == NULL) {
        humanized_log_error("host", "failed to allocate session", ENOMEM);
        continue;
      }

      if (ssh_bind_accept(bind_handle, session) == SSH_ERROR) {
        const int accept_error = errno;
        const char *bind_error = ssh_get_error(bind_handle);

        if (accept_error != 0) {
          char log_message[512];
          const char *system_message = strerror(accept_error);

          if (system_message != NULL && system_message[0] != '\0') {
            if (bind_error != NULL && bind_error[0] != '\0' &&
                !string_contains_case_insensitive(bind_error, system_message)) {
              snprintf(log_message, sizeof(log_message), "Socket error: %s (%s)", system_message,
                       bind_error);
            } else {
              snprintf(log_message, sizeof(log_message), "Socket error: %s", system_message);
            }
          } else if (bind_error != NULL && bind_error[0] != '\0') {
            snprintf(log_message, sizeof(log_message), "Socket error (code %d): %s", accept_error,
                     bind_error);
          } else {
            snprintf(log_message, sizeof(log_message), "Socket error (code %d)", accept_error);
          }

          humanized_log_error("host", log_message, accept_error);
        } else if (bind_error != NULL && bind_error[0] != '\0') {
          humanized_log_error("host", bind_error, EIO);
        } else {
          humanized_log_error("host", "Socket accept failed", EIO);
        }

        bool fatal_socket_error = accept_error != 0;
        switch (accept_error) {
          case 0:
          case EAGAIN:
#ifdef EWOULDBLOCK
#if EWOULDBLOCK != EAGAIN
          case EWOULDBLOCK:
#endif
#endif
          case EINTR:
          case ECONNRESET:
          case ECONNABORTED:
          case ETIMEDOUT:
          case ENOTCONN:
          case EPIPE:
            fatal_socket_error = false;
            break;
          case EBADF:
          case ENOTSOCK:
          case EINVAL:
            fatal_socket_error = true;
            break;
          default:
            if (accept_error != 0) {
              fatal_socket_error = true;
            }
            break;
        }

        if ((fatal_socket_error && bind_error != NULL)
           || string_contains_case_insensitive(bind_error, "kex")) {
            fatal_socket_error = false;
        }

        ssh_free(session);
        if (fatal_socket_error) {
          clock_gettime(CLOCK_MONOTONIC, &host->listener.last_error_time);
          if (host_listener_attempt_recover(host, bind_handle, address, bind_port)) {
            continue;
          }
          host->listener.restart_attempts += 1U;
          printf("[listener] scheduling full listener restart after socket error (attempt %u)\n",
                 host->listener.restart_attempts);
          restart_listener = true;
          break;
        }
        continue;
      }

      hostkey_probe_result_t hostkey_probe = session_probe_client_hostkey_algorithms(
          session, SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS, SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS_COUNT);
      if (hostkey_probe.status == HOSTKEY_SUPPORT_REJECTED) {
        char peer_address[NI_MAXHOST];
        session_describe_peer(session, peer_address, sizeof(peer_address));
        if (peer_address[0] == '\0') {
          strncpy(peer_address, "unknown", sizeof(peer_address) - 1U);
          peer_address[sizeof(peer_address) - 1U] = '\0';
        }

        if (hostkey_probe.offered_algorithms[0] != '\0') {
          printf("[reject] client %s does not accept one of [%s] host keys (client offered: %s)\n",
                 peer_address, SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS_DISPLAY, hostkey_probe.offered_algorithms);
        } else {
          printf("[reject] client %s does not accept one of [%s] host keys\n", peer_address,
                 SSH_CHATTER_REQUIRED_HOSTKEY_ALGORITHMS_DISPLAY);
        }

        ssh_disconnect(session);
        ssh_free(session);
        continue;
      }

      if (ssh_handle_key_exchange(session) != SSH_OK) {
        humanized_log_error("host", ssh_get_error(session), EPROTO);
        ssh_disconnect(session);
        ssh_free(session);
        continue;
      }

      char peer_address[NI_MAXHOST];
      session_describe_peer(session, peer_address, sizeof(peer_address));
      if (peer_address[0] == '\0') {
        strncpy(peer_address, "unknown", sizeof(peer_address) - 1U);
        peer_address[sizeof(peer_address) - 1U] = '\0';
      }

      printf("[connect] accepted client from %s\n", peer_address);

      session_ctx_t *ctx = calloc(1U, sizeof(session_ctx_t));
      if (ctx == NULL) {
        humanized_log_error("host", "failed to allocate session context", ENOMEM);
        ssh_disconnect(session);
        ssh_free(session);
        continue;
      }

      ctx->session = session;
      ctx->channel = NULL;
      ctx->transport_kind = SESSION_TRANSPORT_SSH;
      ctx->telnet_fd = -1;
      ctx->telnet_eof = false;
      ctx->telnet_pending_valid = false;
      ctx->owner = host;
      ctx->auth = (auth_profile_t){0};
      snprintf(ctx->client_ip, sizeof(ctx->client_ip), "%.*s", (int)sizeof(ctx->client_ip) - 1, peer_address);
      ctx->input_mode = SESSION_INPUT_MODE_CHAT;

      pthread_mutex_lock(&host->lock);
      ++host->connection_count;
      snprintf(ctx->user.name, sizeof(ctx->user.name), "Guest%zu", host->connection_count);
      ctx->user.is_operator = false;
      ctx->user.is_lan_operator = false;
      pthread_mutex_unlock(&host->lock);

      pthread_t thread_id;
      if (pthread_create(&thread_id, NULL, session_thread, ctx) != 0) {
        humanized_log_error("host", "failed to spawn session thread", errno);
        session_cleanup(ctx);
        continue;
      }

      pthread_detach(thread_id);
    }

    ssh_bind_free(bind_handle);
    host->listener.handle = NULL;

    if (!restart_listener) {
      host_sleep_after_error();
      continue;
    }

    struct timespec backoff = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };
    nanosleep(&backoff, NULL);

    if (host->listener.restart_attempts > 0U) {
      printf("[listener] attempting full listener restart after socket error (attempt %u)\n",
             host->listener.restart_attempts);
    } else {
      printf("[listener] attempting full listener restart after socket error\n");
    }

    if (host->listener.last_error_time.tv_sec != 0 || host->listener.last_error_time.tv_nsec != 0L) {
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      struct timespec elapsed = timespec_diff(&now, &host->listener.last_error_time);
      double elapsed_seconds = (double)elapsed.tv_sec + (double)elapsed.tv_nsec / 1000000000.0;
      printf("[listener] last fatal error occurred %.3f seconds ago\n", elapsed_seconds);
    }
  }

  return 0;
}
