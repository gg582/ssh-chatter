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
#include <inttypes.h>
#include <limits.h>
#include <wchar.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
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
#define SSH_CHATTER_HANDSHAKE_RETRY_LIMIT 3U

typedef struct {
  char question[256];
  char answer[64];
} captcha_prompt_t;

typedef enum {
  CAPTCHA_TEMPLATE_PRONOUN,
  CAPTCHA_TEMPLATE_PET_SPECIES,
} captcha_template_t;

typedef struct {
  const char *person_name;
  const char *descriptor;
  bool is_male;
  const char *pet_species;
  const char *pet_name;
  const char *pet_pronoun;
  captcha_template_t template_type;
} captcha_story_t;

static const captcha_story_t CAPTCHA_STORIES[] = {
    {"Jiho", "software engineer", true, "cat", "Hodu", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Sujin", "middle school teacher", false, "cat", "Dubu", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Minseok", "photographer", true, "cat", "Mimi", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Haeun", "florist", false, "cat", "Bori", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Yuna", "product designer", false, "cat", "Choco", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Donghyun", "barista", true, "cat", "Gaeul", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Seojun", "research scientist", true, "cat", "Nuri", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Ara", "ceramic artist", false, "cat", "Bam", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Kyungmin", "chef", true, "cat", "Tori", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Jisoo", "translator", false, "cat", "Haneul", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Emily", "librarian", false, "cat", "Whiskers", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Jacob", "firefighter", true, "cat", "Shadow", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Olivia", "graphic designer", false, "cat", "Pumpkin", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Noah", "high school coach", true, "cat", "Midnight", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Ava", "nurse", false, "cat", "Sunny", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Ethan", "software architect", true, "cat", "Clover", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Sophia", "baker", false, "cat", "Pebble", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Liam", "paramedic", true, "cat", "Smokey", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Isabella", "journalist", false, "cat", "Luna", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Mason", "carpenter", true, "cat", "Tiger", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Anya", "interpreter", false, "cat", "Pushok", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Dmitri", "aerospace engineer", true, "cat", "Barsik", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Elena", "doctor", false, "cat", "Sneg", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Nikolai", "history professor", true, "cat", "Murzik", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Irina", "pianist", false, "cat", "Mishka", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Sergei", "marine biologist", true, "cat", "Ryzhik", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Tatiana", "architect", false, "cat", "Zvezda", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Alexei", "journalist", true, "cat", "Kotya", "he", CAPTCHA_TEMPLATE_PRONOUN},
    {"Yulia", "theatre director", false, "cat", "Lapka", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Mikhail", "chef", true, "cat", "Tuman", NULL, CAPTCHA_TEMPLATE_PRONOUN},
    {"Hyeri", "illustrator", false, "dog", "Gureum", NULL, CAPTCHA_TEMPLATE_PET_SPECIES},
    {"Brandon", "park ranger", true, "dog", "Buddy", NULL, CAPTCHA_TEMPLATE_PET_SPECIES},
    {"Oksana", "music teacher", false, "dog", "Volna", NULL, CAPTCHA_TEMPLATE_PET_SPECIES},
};

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
  const size_t story_count = sizeof(CAPTCHA_STORIES) / sizeof(CAPTCHA_STORIES[0]);
  if (story_count == 0U) {
    snprintf(prompt->question, sizeof(prompt->question),
             "Tom is a man who has a cat named Tom. \"it\" is adorable. Answer what the double-quoted text refers to.");
    snprintf(prompt->answer, sizeof(prompt->answer), "%s", "Tom");
    return;
  }

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

  const captcha_story_t *story = &CAPTCHA_STORIES[basis % story_count];

  if (story->template_type == CAPTCHA_TEMPLATE_PRONOUN) {
    unsigned variant = basis ^ entropy ^ (basis >> 16U) ^ (entropy >> 16U);
    if (variant == 0U) {
      variant = 0x5f3759dfU;  // fallback mixing constant to avoid a degenerate branch
    }

    const bool refer_pet = (variant & 1U) != 0U;
    const bool use_pronoun = (variant & 2U) != 0U;

    const char *person_pronoun = story->is_male ? "he" : "she";
    const char *pet_pronoun = (story->pet_pronoun != NULL) ? story->pet_pronoun : "it";
    const char *answer = refer_pet ? story->pet_name : story->person_name;

    char quoted_buffer[128];
    const char *quoted_text = NULL;
    if (use_pronoun) {
      quoted_text = refer_pet ? pet_pronoun : person_pronoun;
    } else {
      if (refer_pet) {
        snprintf(quoted_buffer, sizeof(quoted_buffer), "the %s", story->pet_species);
      } else {
        snprintf(quoted_buffer, sizeof(quoted_buffer), "the %s", story->descriptor);
      }
      quoted_text = quoted_buffer;
    }

    snprintf(prompt->question, sizeof(prompt->question),
             "%s is a %s who has a %s named %s. \"%s\" is adorable. Answer what the double-quoted text refers to.",
             story->person_name, story->descriptor, story->pet_species, story->pet_name, quoted_text);
    snprintf(prompt->answer, sizeof(prompt->answer), "%s", answer);
    return;
  }

  snprintf(prompt->question, sizeof(prompt->question),
           "%s is a %s who has a %s named %s. What kind of pet does %s have? Answer in lowercase.",
           story->person_name, story->descriptor, story->pet_species, story->pet_name, story->person_name);
  snprintf(prompt->answer, sizeof(prompt->answer), "%s", story->pet_species);
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
  {"holy-light", "Christian sacred light on pure white/blue base", "bright-white", "blue", false, "blue", "black", "yellow", true},
  {"islam", "Iconic color of muslim, white/green base", "bright-white", "green", false, "green", "black", "bright-white", true},
  {"dharma-ochre", "Ochre robes of enlightenment and vitality", "yellow", "black", true, "red", "black", "yellow", true},
  {"yin-yang", "Balance of Black and White with Jade accent", "white", "black", false, "green", "black", "white", false},
  {"soviet-cold", "Cold blue/white terminal for scientific systems", "white", "blue", false, "white", "blue", "cyan", false},
  {"hi-tel", "1990s Korean BBS blue background and text style", "bright-white", "blue", true, "bright-white", "blue", "magenta", true},
  {"amiga-cli", "AmigaOS style with cyan/blue", "cyan", "blue", true, "cyan", "blue", "blue", true},
  {"jpn-pc98", "NEC PC-9801 subtle, earthy low-res tones", "yellow", "black", false, "red", "black", "yellow", false},
  {"deep-blue", "IBM Supercomputer monitoring interface style", "white", "blue", true, "cyan", "blue", "white", true},
  {"win10", "High contrast palette reminiscent of Windows 10", "cyan", "blue", true, "white", "blue", "yellow", true},
  {"korea", "Taegeuk-gi inspired black base with red and blue accents", "bright-blue", "blue", true, "bright-white", "blue", "red", true},
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
static void session_apply_background_fill(session_ctx_t *ctx);
static void session_write_rendered_line(session_ctx_t *ctx, const char *render_source);
static void session_send_caption_line(session_ctx_t *ctx, const char *message);
static void session_render_caption_with_offset(session_ctx_t *ctx, const char *message, size_t move_up);
static void session_send_line(session_ctx_t *ctx, const char *message);
static void session_send_plain_line(session_ctx_t *ctx, const char *message);
static void session_send_system_line(session_ctx_t *ctx, const char *message);
static void session_send_raw_text(session_ctx_t *ctx, const char *text);
static void session_render_banner(session_ctx_t *ctx);
static void session_render_separator(session_ctx_t *ctx, const char *label);
static void session_render_prompt(session_ctx_t *ctx, bool include_separator);
static void session_refresh_input_line(session_ctx_t *ctx);
static void session_set_input_text(session_ctx_t *ctx, const char *text);
static void session_local_echo_char(session_ctx_t *ctx, char ch);
static void session_local_backspace(session_ctx_t *ctx);
static void session_clear_input(session_ctx_t *ctx);
static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch);
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
static void chat_room_broadcast_entry(chat_room_t *room, const chat_history_entry_t *entry, const session_ctx_t *from);
static void chat_room_broadcast_caption(chat_room_t *room, const char *message);
static bool host_history_apply_reaction(host_t *host, uint64_t message_id, size_t reaction_index, chat_history_entry_t *updated_entry);
static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length);
static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source,
                                              const char *label, const char *message);
static session_ctx_t *chat_room_find_user(chat_room_t *room, const char *username);
static bool host_is_ip_banned(host_t *host, const char *ip);
static bool host_is_username_banned(host_t *host, const char *username);
static bool host_add_ban_entry(host_t *host, const char *username, const char *ip);
static bool host_remove_ban_entry(host_t *host, const char *token);
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
static void session_handle_nick(session_ctx_t *ctx, const char *arguments);
static void session_handle_pm(session_ctx_t *ctx, const char *arguments);
static void session_handle_motd(session_ctx_t *ctx);
static void session_handle_system_color(session_ctx_t *ctx, const char *arguments);
static void session_handle_palette(session_ctx_t *ctx, const char *arguments);
static void session_handle_translate(session_ctx_t *ctx, const char *arguments);
static void session_handle_set_trans_lang(session_ctx_t *ctx, const char *arguments);
static void session_handle_set_target_lang(session_ctx_t *ctx, const char *arguments);
static void session_handle_chat_spacing(session_ctx_t *ctx, const char *arguments);
static void session_handle_status(session_ctx_t *ctx, const char *arguments);
static void session_handle_showstatus(session_ctx_t *ctx, const char *arguments);
static void session_handle_weather(session_ctx_t *ctx, const char *arguments);
static void session_handle_pardon(session_ctx_t *ctx, const char *arguments);
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
static bool session_argument_is_disable(const char *token);
static bool session_fetch_weather_summary(const char *region, const char *city, char *summary, size_t summary_len);
static void session_handle_poll(session_ctx_t *ctx, const char *arguments);
static void session_handle_vote(session_ctx_t *ctx, size_t option_index);
static void session_handle_named_vote(session_ctx_t *ctx, size_t option_index, const char *label);
static void session_handle_elect_command(session_ctx_t *ctx, const char *arguments);
static void session_handle_vote_command(session_ctx_t *ctx, const char *arguments, bool allow_multiple);
static bool session_line_is_exit_command(const char *line);
static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line);
static bool session_parse_color_arguments(char *working, char **tokens, size_t max_tokens, size_t *token_count);
static size_t session_utf8_prev_char_len(const char *buffer, size_t length);
static int session_utf8_char_width(const char *bytes, size_t length);
static void host_history_record_system(host_t *host, const char *message);
static void session_send_history(session_ctx_t *ctx);
static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry);
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
static bool host_ip_has_grant_locked(host_t *host, const char *ip);
static bool host_ip_has_grant(host_t *host, const char *ip);
static bool host_add_operator_grant_locked(host_t *host, const char *ip);
static bool host_remove_operator_grant_locked(host_t *host, const char *ip);
static void host_apply_grant_to_ip(host_t *host, const char *ip);
static void host_revoke_grant_from_ip(host_t *host, const char *ip);
static void host_history_normalize_entry(host_t *host, chat_history_entry_t *entry);
static const char *chat_attachment_type_label(chat_attachment_type_t type);
static void host_state_resolve_path(host_t *host);
static void host_state_load(host_t *host);
static void host_state_save_locked(host_t *host);
static void host_bbs_resolve_path(host_t *host);
static void host_bbs_state_load(host_t *host);
static void host_bbs_state_save_locked(host_t *host);
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
static void session_bbs_capture_body_line(session_ctx_t *ctx, const char *line);
static void session_bbs_add_comment(session_ctx_t *ctx, const char *arguments);
static void session_bbs_regen_post(session_ctx_t *ctx, uint64_t id);
static void session_bbs_delete(session_ctx_t *ctx, uint64_t id);
static bbs_post_t *host_find_bbs_post_locked(host_t *host, uint64_t id);
static bbs_post_t *host_allocate_bbs_post_locked(host_t *host);
static void host_clear_bbs_post_locked(host_t *host, bbs_post_t *post);
static void session_bbs_render_post(session_ctx_t *ctx, const bbs_post_t *post);
static void host_update_last_captcha_prompt(host_t *host, const captcha_prompt_t *prompt);

static const uint32_t HOST_STATE_MAGIC = 0x53484354U; /* 'SHCT' */
static const uint32_t HOST_STATE_VERSION = 5U;

#define HOST_STATE_SOUND_ALIAS_LEN 32U

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
  uint8_t reserved[3];
  char birthday[16];
} host_state_preference_entry_t;

typedef struct host_state_grant_entry {
  char ip[SSH_CHATTER_IP_LEN];
} host_state_grant_entry_t;

static const uint32_t BBS_STATE_MAGIC = 0x42425331U; /* 'BBS1' */
static const uint32_t BBS_STATE_VERSION = 1U;

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
    {"reactos", "ReactOS"},      {"tyzen", "Tyzen"},
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

  strncpy(buffer, host, len - 1U);
  buffer[len - 1U] = '\0';
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
    ctx->user.is_lan_operator = true;
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
    memset(serialized.reserved, 0, sizeof(serialized.reserved));
    serialized.reserved[0] = pref->translation_caption_spacing;
    snprintf(serialized.birthday, sizeof(serialized.birthday), "%s", pref->birthday);

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
    if (version >= 5U) {
      if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
        success = false;
        break;
      }
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
      memset(serialized.reserved, 0, sizeof(serialized.reserved));
      serialized.birthday[0] = '\0';
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
      memset(serialized.reserved, 0, sizeof(serialized.reserved));
      serialized.birthday[0] = '\0';
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
    pref->translation_caption_spacing = serialized.reserved[0];
    ++host->preference_count;
  }

  memset(host->operator_grants, 0, sizeof(host->operator_grants));
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

static void host_bbs_state_save_locked(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->bbs_state_file_path[0] == '\0') {
    return;
  }

  char temp_path[PATH_MAX];
  int written = snprintf(temp_path, sizeof(temp_path), "%s.tmp", host->bbs_state_file_path);
  if (written < 0 || (size_t)written >= sizeof(temp_path)) {
    humanized_log_error("host", "bbs state file path is too long", ENAMETOOLONG);
    return;
  }

  FILE *fp = fopen(temp_path, "wb");
  if (fp == NULL) {
    humanized_log_error("host", "failed to open bbs state file", errno);
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
    int fd = fileno(fp);
    if (fd >= 0 && fsync(fd) != 0) {
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

  if (rename(temp_path, host->bbs_state_file_path) != 0) {
    humanized_log_error("host", "failed to update bbs state file", errno);
    unlink(temp_path);
  }
}

static void host_bbs_state_load(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->bbs_state_file_path[0] == '\0') {
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
    if (fread(&serialized, sizeof(serialized), 1U, fp) != 1U) {
      success = false;
      break;
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

    size_t tag_limit = serialized.tag_count;
    if (tag_limit > SSH_CHATTER_BBS_MAX_TAGS) {
      tag_limit = SSH_CHATTER_BBS_MAX_TAGS;
    }
    post->tag_count = tag_limit;
    for (size_t tag = 0U; tag < tag_limit; ++tag) {
      snprintf(post->tags[tag], sizeof(post->tags[tag]), "%s", serialized.tags[tag]);
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
static void session_apply_saved_preferences(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  user_preference_t snapshot = {0};
  bool has_snapshot = false;

  pthread_mutex_lock(&host->lock);
  user_preference_t *pref = host_find_preference_locked(host, ctx->user.name);
  if (pref != NULL) {
    snapshot = *pref;
    has_snapshot = true;
  }
  pthread_mutex_unlock(&host->lock);

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
  }

  session_force_dark_mode_foreground(ctx);
}

static bool session_argument_is_disable(const char *token) {
  if (token == NULL) {
    return false;
  }

  return strcasecmp(token, "off") == 0 || strcasecmp(token, "none") == 0 || strcasecmp(token, "disable") == 0 ||
         strcasecmp(token, "stop") == 0;
}

typedef struct translation_caption_job {
  char sanitized[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  translation_placeholder_t placeholders[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
  size_t placeholder_count;
  char target_language[SSH_CHATTER_LANG_NAME_LEN];
  size_t placeholder_lines;
  struct translation_caption_job *next;
} translation_caption_job_t;

typedef struct translation_caption_result {
  bool success;
  size_t placeholder_lines;
  char translated[SSH_CHATTER_TRANSLATION_WORKING_LEN];
  struct translation_caption_result *next;
} translation_caption_result_t;

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

  translation_caption_job_t *pending = NULL;
  translation_caption_result_t *ready = NULL;

  pthread_mutex_lock(&ctx->translation_mutex);
  pending = ctx->translation_pending_head;
  ctx->translation_pending_head = NULL;
  ctx->translation_pending_tail = NULL;
  ready = ctx->translation_ready_head;
  ctx->translation_ready_head = NULL;
  ctx->translation_ready_tail = NULL;
  pthread_mutex_unlock(&ctx->translation_mutex);

  while (pending != NULL) {
    translation_caption_job_t *next = pending->next;
    free(pending);
    pending = next;
  }

  while (ready != NULL) {
    translation_caption_result_t *next = ready->next;
    free(ready);
    ready = next;
  }

  ctx->translation_placeholder_active_lines = 0U;
}

static bool session_translation_queue_caption(session_ctx_t *ctx, const char *message, size_t placeholder_lines) {
  if (ctx == NULL || message == NULL) {
    return false;
  }

  if (!ctx->translation_enabled || !ctx->output_translation_enabled ||
      ctx->output_translation_language[0] == '\0' || message[0] == '\0') {
    return false;
  }

  if (!session_translation_worker_ensure(ctx)) {
    return false;
  }

  translation_caption_job_t *job = calloc(1U, sizeof(*job));
  if (job == NULL) {
    return false;
  }

  size_t placeholder_count = 0U;
  if (!translation_prepare_text(message, job->sanitized, sizeof(job->sanitized), job->placeholders, &placeholder_count)) {
    free(job);
    return false;
  }

  if (job->sanitized[0] == '\0') {
    free(job);
    return false;
  }

  job->placeholder_count = placeholder_count;
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
  if (ctx == NULL || ctx->channel == NULL || placeholder_lines == 0U) {
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

static void session_translation_flush_ready(session_ctx_t *ctx) {
  if (ctx == NULL || !ctx->translation_mutex_initialized) {
    return;
  }

  translation_caption_result_t *ready = NULL;

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
    translation_caption_result_t *next = ready->next;
    size_t placeholder_lines = ready->placeholder_lines;
    size_t move_up = 0U;
    if (placeholder_lines > 0U && ctx->translation_placeholder_active_lines >= placeholder_lines) {
      size_t remaining_after = ctx->translation_placeholder_active_lines - placeholder_lines;
      move_up = remaining_after + 1U;
    }

    if (translation_active) {
      const char *body = ready->translated;
      char annotated[SSH_CHATTER_TRANSLATION_WORKING_LEN + 64U];
      if (body[0] == '\0') {
        body = "translation unavailable.";
      }
      snprintf(annotated, sizeof(annotated), "    \342\206\263 %s", body);
      session_render_caption_with_offset(ctx, annotated, move_up);
      refreshed = true;
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

static void *session_translation_worker(void *arg) {
  session_ctx_t *ctx = (session_ctx_t *)arg;
  if (ctx == NULL) {
    return NULL;
  }

  for (;;) {
    translation_caption_job_t *job = NULL;

    pthread_mutex_lock(&ctx->translation_mutex);
    while (!ctx->translation_thread_stop && ctx->translation_pending_head == NULL) {
      pthread_cond_wait(&ctx->translation_cond, &ctx->translation_mutex);
    }

    if (ctx->translation_thread_stop) {
      pthread_mutex_unlock(&ctx->translation_mutex);
      break;
    }

    job = ctx->translation_pending_head;
    if (job != NULL) {
      ctx->translation_pending_head = job->next;
      if (ctx->translation_pending_head == NULL) {
        ctx->translation_pending_tail = NULL;
      }
    }
    pthread_mutex_unlock(&ctx->translation_mutex);

    if (job == NULL) {
      continue;
    }

    char translated_body[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    char restored[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    char detected[SSH_CHATTER_LANG_NAME_LEN];
    translated_body[0] = '\0';
    restored[0] = '\0';
    detected[0] = '\0';

    bool success = translator_translate(job->sanitized, job->target_language, translated_body, sizeof(translated_body),
                                        detected, sizeof(detected));
    char failure_message[128];
    failure_message[0] = '\0';
    if (success) {
      success = translation_restore_text(translated_body, restored, sizeof(restored), job->placeholders,
                                         job->placeholder_count);
      if (!success) {
        snprintf(failure_message, sizeof(failure_message), "⚠️ translation post-processing failed.");
      }
    } else {
      const char *error = translator_last_error();
      if (error != NULL && error[0] != '\0') {
        snprintf(failure_message, sizeof(failure_message), "⚠️ translation failed: %s", error);
      } else {
        snprintf(failure_message, sizeof(failure_message), "⚠️ translation failed.");
      }
    }

    translation_caption_result_t *result = calloc(1U, sizeof(*result));
    if (result != NULL) {
      result->success = success;
      result->placeholder_lines = job->placeholder_lines;
      if (success) {
        snprintf(result->translated, sizeof(result->translated), "%s", restored);
      } else {
        const char *payload = failure_message;
        if (payload[0] == '\0') {
          payload = "⚠️ translation unavailable.";
        }
        snprintf(result->translated, sizeof(result->translated), "%s", payload);
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

    free(job);
  }

  return NULL;
}

// session_apply_background_fill reapplies the palette background to the
// current terminal row so subsequent output starts from a clean, tinted
// baseline.
static void session_apply_background_fill(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const size_t bg_len = strlen(bg);

  if (bg_len > 0U) {
    ssh_channel_write(ctx->channel, bg, bg_len);
  }

  ssh_channel_write(ctx->channel, ANSI_CLEAR_LINE, sizeof(ANSI_CLEAR_LINE) - 1U);
  ssh_channel_write(ctx->channel, "\r", 1U);

  if (bg_len > 0U) {
    ssh_channel_write(ctx->channel, bg, bg_len);
  }
}

static void session_write_rendered_line(session_ctx_t *ctx, const char *render_source) {
  if (ctx == NULL || ctx->channel == NULL || render_source == NULL) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const size_t bg_len = strlen(bg);

  if (bg_len == 0U) {
    ssh_channel_write(ctx->channel, render_source, strlen(render_source));
    ssh_channel_write(ctx->channel, "\r\n", 2U);
    return;
  }

  ssh_channel_write(ctx->channel, bg, bg_len);
  ssh_channel_write(ctx->channel, ANSI_CLEAR_LINE, sizeof(ANSI_CLEAR_LINE) - 1U);
  ssh_channel_write(ctx->channel, "\r", 1U);

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

  ssh_channel_write(ctx->channel, expanded, out_idx);
  ssh_channel_write(ctx->channel, "\r\n", 2U);
  ssh_channel_write(ctx->channel, bg, bg_len);
}

static void session_send_caption_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  ssh_channel_write(ctx->channel, "\r", 1U);
  ssh_channel_write(ctx->channel, ANSI_INSERT_LINE, sizeof(ANSI_INSERT_LINE) - 1U);

  session_write_rendered_line(ctx, message);
}

static void session_render_caption_with_offset(session_ctx_t *ctx, const char *message, size_t move_up) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  if (move_up == 0U) {
    session_send_caption_line(ctx, message);
    return;
  }

  ssh_channel_write(ctx->channel, "\033[s", 3U);

  char command[32];
  int written = snprintf(command, sizeof(command), "\033[%zuA", move_up);
  if (written > 0 && (size_t)written < sizeof(command)) {
    ssh_channel_write(ctx->channel, command, (size_t)written);
  }

  ssh_channel_write(ctx->channel, "\r", 1U);
  session_write_rendered_line(ctx, message);
  ssh_channel_write(ctx->channel, "\033[u", 3U);
}

// session_send_line writes a single line while preserving the session's
// background color even when individual strings reset their ANSI attributes by
// clearing the row with the palette tint before printing.
static void session_send_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  char buffer[SSH_CHATTER_MESSAGE_LIMIT + 1U];
  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, message, SSH_CHATTER_MESSAGE_LIMIT);
  buffer[SSH_CHATTER_MESSAGE_LIMIT] = '\0';

  session_write_rendered_line(ctx, buffer);

  size_t placeholder_lines = 0U;
  const bool translation_ready = ctx->translation_enabled && ctx->output_translation_enabled &&
                                 ctx->output_translation_language[0] != '\0' && buffer[0] != '\0';
  if (translation_ready && !ctx->in_bbs_mode) {
    size_t spacing = ctx->translation_caption_spacing;
    if (spacing > 8U) {
      spacing = 8U;
    }
    placeholder_lines = spacing + 1U;
  }

  if (session_translation_queue_caption(ctx, buffer, placeholder_lines)) {
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
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
    return;
  }

  static const char kCaptionPrefix[] = "    \342\206\263";
  if (strncmp(message, kCaptionPrefix, sizeof(kCaptionPrefix) - 1U) == 0) {
    session_send_caption_line(ctx, message);
    return;
  }

  session_send_line(ctx, message);
}

static void session_send_system_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || ctx->channel == NULL || message == NULL) {
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
}

static void session_send_raw_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || ctx->channel == NULL || text == NULL) {
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

static void session_render_separator(session_ctx_t *ctx, const char *label) {
  if (ctx == NULL || label == NULL) {
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  const size_t total_width = 60U;
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

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s%s%s", hl, fg, bold, body, ANSI_RESET);
  session_send_line(ctx, line);
}

static void session_render_banner(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_apply_background_fill(ctx);

  static const char *kBanner[] = {
    "+====================================================+",
    "|    ____ _           _   _                         |",
    "|   / ___| |__   __ _| |_| |_ ___ _ __              |",
    "|  | |   | '_ \\ / _` | __| __/ _ \\ '__|             |",
    "|  | |___| | | | (_| | |_| ||  __/ |                |",
    "|   \\____|_| |_|\\__,_|\\__|\\__\\___|_|                |",
    "|                                                    |",
    "|   cute and tiny SSH chat written in C language.    |",
    "|   Type /help to see available commands.            |",
    "+====================================================+",
};


  for (size_t idx = 0; idx < sizeof(kBanner) / sizeof(kBanner[0]); ++idx) {
    session_send_system_line(ctx, kBanner[idx]);
  }

  char welcome[SSH_CHATTER_MESSAGE_LIMIT];
  size_t name_len = strlen(ctx->user.name);
  int welcome_padding = 47 - (int)name_len;
  if (welcome_padding < 0) {
    welcome_padding = 0;
  }

  snprintf(welcome, sizeof(welcome), "|  Welcome, %s!%*s|", ctx->user.name, welcome_padding, "");
  session_send_system_line(ctx, welcome);

  char version_line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t version_len = strlen(ctx->owner->version);
  int version_padding = 50 - (int)version_len;
  if (version_padding < 0) {
    version_padding = 0;
  }
  snprintf(version_line, sizeof(version_line), "|  %s%*s|", ctx->owner->version, version_padding, "");
  session_send_system_line(ctx, version_line);
  session_send_system_line(ctx, "+====================================================+");
  session_render_separator(ctx, "Chatroom");
}

static void session_render_prompt(session_ctx_t *ctx, bool include_separator) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  if (include_separator) {
    session_render_separator(ctx, "Input");
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";

  if (hl[0] != '\0') {
    ssh_channel_write(ctx->channel, hl, strlen(hl));
  }
  if (fg[0] != '\0') {
    ssh_channel_write(ctx->channel, fg, strlen(fg));
  }
  if (bold[0] != '\0') {
    ssh_channel_write(ctx->channel, bold, strlen(bold));
  }
  const char pipe_symbol[] = "│";
  ssh_channel_write(ctx->channel, pipe_symbol, sizeof(pipe_symbol) - 1U);

  ssh_channel_write(ctx->channel, ANSI_RESET, strlen(ANSI_RESET));
  if (bg[0] != '\0') {
    ssh_channel_write(ctx->channel, bg, strlen(bg));
  }
  ssh_channel_write(ctx->channel, " ", 1U);
  if (fg[0] != '\0') {
    ssh_channel_write(ctx->channel, fg, strlen(fg));
  }
  if (bold[0] != '\0') {
    ssh_channel_write(ctx->channel, bold, strlen(bold));
  }
  ssh_channel_write(ctx->channel, "> ", 2U);
  ssh_channel_write(ctx->channel, ANSI_RESET, strlen(ANSI_RESET));
  if (bg[0] != '\0') {
    ssh_channel_write(ctx->channel, bg, strlen(bg));
  }
  if (fg[0] != '\0') {
    ssh_channel_write(ctx->channel, fg, strlen(fg));
  }

  if (ctx->input_length > 0U) {
    ssh_channel_write(ctx->channel, ctx->input_buffer, ctx->input_length);
  }
}

static void session_refresh_input_line(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  if (bg[0] != '\0') {
    ssh_channel_write(ctx->channel, bg, strlen(bg));
  }

  static const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  ssh_channel_write(ctx->channel, clear_sequence, sizeof(clear_sequence) - 1U);

  if (bg[0] != '\0') {
    ssh_channel_write(ctx->channel, bg, strlen(bg));
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
  if (ctx == NULL || ctx->channel == NULL) {
    return;
  }

  if (ch == '\r' || ch == '\n') {
    ssh_channel_write(ctx->channel, "\r\n", 2U);
    return;
  }

  ssh_channel_write(ctx->channel, &ch, 1U);
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
  if (ctx == NULL || ctx->channel == NULL || ctx->input_length == 0U) {
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
    ssh_channel_write(ctx->channel, sequence, sizeof(sequence) - 1U);
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
  session_refresh_input_line(ctx);
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
  if (ctx == NULL || ctx->owner == NULL || ctx->channel == NULL || direction == 0) {
    return;
  }

  size_t total = host_history_total(ctx->owner);
  if (total == 0U) {
    session_send_system_line(ctx, "No chat history available yet.");
    return;
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
  ssh_channel_write(ctx->channel, clear_sequence, sizeof(clear_sequence) - 1U);
  ssh_channel_write(ctx->channel, "\r\n", 2U);

  if (direction < 0 && at_boundary && new_position == 0U) {
    if (position == 0U) {
      session_send_system_line(ctx, "Already at the latest messages.");
    }
    session_render_prompt(ctx, false);
    return;
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
    return;
  }

  for (size_t idx = 0; idx < copied; ++idx) {
    session_send_history_entry(ctx, &buffer[idx]);
  }

  if (direction < 0 && new_position == 0U) {
    session_send_system_line(ctx, "End of scrollback.");
  }

  session_render_prompt(ctx, false);
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
      session_history_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[1] == 'j') {
      session_history_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == '[') {
    if (sequence[2] == 'A') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == 'O') {
    if (sequence[2] == 'A') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 4U && sequence[1] == '[' && sequence[3] == '~') {
    if (sequence[2] == '5') {
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == '6') {
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  const bool bracket_sequence = (length >= 2U && sequence[1] == '[');
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (bracket_sequence) {
    return true;
  }
  return ch == 0x1b;
}

static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source, const char *label,
                                              const char *message) {
  if (ctx == NULL || ctx->channel == NULL || color_source == NULL || label == NULL || message == NULL) {
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
  if (ctx == NULL || ctx->channel == NULL || entry == NULL) {
    return;
  }

  if (entry->is_user_message) {
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

    char header[SSH_CHATTER_MESSAGE_LIMIT + 128];
    if (entry->message_id > 0U) {
      snprintf(header, sizeof(header), "[#%" PRIu64 "] %s%s%s%s%s %s", entry->message_id, highlight, bold, color,
               entry->username, ANSI_RESET, message_text);
    } else {
      snprintf(header, sizeof(header), "%s%s%s%s%s %s", highlight, bold, color, entry->username, ANSI_RESET,
               message_text);
    }
    session_send_plain_line(ctx, header);

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
    snprintf(chunk, sizeof(chunk), "%s ×%u", descriptor->icon, count);

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
  if (ctx == NULL || ctx->owner == NULL || ctx->channel == NULL) {
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

  return ctx->channel != NULL ? 0 : -1;
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
  snprintf(host->last_captcha_question, sizeof(host->last_captcha_question), "%s", prompt->question);
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
  if (ctx == NULL || ctx->channel == NULL) {
    return false;
  }

  captcha_prompt_t prompt;
  session_build_captcha_prompt(ctx, &prompt);
  host_update_last_captcha_prompt(ctx->owner, &prompt);
  session_send_system_line(ctx, "Before entering the room, solve this small puzzle.");
  session_send_system_line(ctx, prompt.question);
  session_send_system_line(ctx, "Type your answer and press Enter:");

  char answer[sizeof(prompt.answer)];
  size_t length = 0U;
  while (length + 1U < sizeof(answer)) {
    char ch = '\0';
    const int read_result = ssh_channel_read(ctx->channel, &ch, 1, 0);
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

  session_send_system_line(ctx, "Available commands:");
  session_send_system_line(ctx, "/help                 - show this message");
  session_send_system_line(ctx, "/exit                 - leave the chat");
  session_send_system_line(ctx, "/nick <name>          - change your display name");
  session_send_system_line(ctx, "/pm <username> <message> - send a private message");
  session_send_system_line(ctx, "/motd                - view the message of the day");
  session_send_system_line(ctx, "/status <message|clear> - set your profile status");
  session_send_system_line(ctx, "/showstatus <username> - view someone else's status");
  session_send_system_line(ctx, "/users               - announce the number of connected users");
  session_send_system_line(ctx, "/search <text>       - search for users whose name matches text");
  session_send_system_line(ctx, "/chat <message-id>   - show a past message by its identifier");
  session_send_system_line(ctx, "/image <url> [caption] - share an image link");
  session_send_system_line(ctx, "/video <url> [caption] - share a video link");
  session_send_system_line(ctx, "/audio <url> [caption] - share an audio clip");
  session_send_system_line(ctx, "/files <url> [caption] - share a downloadable file");
  session_send_system_line(ctx, "Up/Down arrows           - scroll recent chat history");
  session_send_system_line(ctx, "/color (text;highlight[;bold]) - style your handle");
  session_send_system_line(ctx,
                           "/systemcolor (fg;background[;highlight][;bold]) - style the interface (third value may "
                           "be highlight or bold; use /systemcolor reset to restore defaults)");
  session_send_system_line(ctx, "/set-trans-lang <language|off> - translate terminal output to a target language");
  session_send_system_line(ctx, "/set-target-lang <language|off> - translate your outgoing messages");
  session_send_system_line(ctx, "/weather <region> <city> - show the weather for a region and city");
  session_send_system_line(ctx, "/translate <on|off>    - enable or disable translation after configuring languages");
  session_send_system_line(ctx, "/chat-spacing <0-5>    - reserve blank lines before translated captions in chat");
  session_send_system_line(ctx, "/palette <name>        - apply a predefined interface palette (/palette list)");
  session_send_system_line(ctx, "/today               - discover today's function (once per day)");
  session_send_system_line(ctx, "/date <timezone>     - view the server time in another timezone");
  session_send_system_line(ctx, "/os <name>           - record the operating system you use");
  session_send_system_line(ctx, "/getos <username>    - look up someone else's recorded operating system");
  session_send_system_line(ctx, "/birthday YYYY-MM-DD - register your birthday");
  session_send_system_line(ctx, "/soulmate            - list users sharing your birthday");
  session_send_system_line(ctx, "/pair                - list users sharing your recorded OS");
  session_send_system_line(ctx, "/connected           - privately list everyone connected");
  session_send_system_line(ctx, "/grant <ip>          - grant operator access to an IP (LAN only)");
  session_send_system_line(ctx, "/revoke <ip>         - revoke an IP's operator access (LAN top admin)");
  session_send_system_line(ctx, "/poll <question>|<option...> - start or view a poll");
  session_send_system_line(ctx,
                           "/vote <label> <question>|<option...> - start or inspect a multiple-choice named poll (use /vote "
                           "@close <label> to end it)");
  session_send_system_line(ctx,
                           "/vote-single <label> <question>|<option...> - start or inspect a single-choice named poll");
  session_send_system_line(ctx, "/elect <label> <choice> - vote in a named poll by label");
  session_send_system_line(ctx, "/poke <username>      - send a bell to call a user");
  session_send_system_line(ctx, "/kick <username>      - disconnect a user (operator only)");
  session_send_system_line(ctx, "/ban <username>       - ban a user (operator only)");
  session_send_system_line(ctx, "/pardon <user|ip>     - remove a ban (operator only)");
  session_send_system_line(ctx,
                           "/good|/sad|/cool|/angry|/checked|/love|/wtf <id> - react to a message by number");
  session_send_system_line(ctx, "/1 .. /5             - vote for an option in the active poll");
  session_send_system_line(ctx,
                           "/bbs [list|read|post|comment|regen|delete] - open the bulletin board system (see /bbs for details, finish "
                           SSH_CHATTER_BBS_TERMINATOR " to post)");
  session_send_system_line(ctx, "Regular messages are shared with everyone.");
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
  if (ctx == NULL || line == NULL || line[0] == '\0') {
    return;
  }

  char normalized[SSH_CHATTER_MAX_INPUT_LEN];
  snprintf(normalized, sizeof(normalized), "%s", line);
  session_normalize_newlines(normalized);

  if (ctx->bbs_post_pending) {
    session_bbs_capture_body_line(ctx, normalized);
    return;
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

  if (normalized[0] == '/') {
    session_dispatch_command(ctx, normalized);
    return;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  bool allow_message = true;
  if (ctx->has_last_message_time) {
    time_t sec_delta = now.tv_sec - ctx->last_message_time.tv_sec;
    long nsec_delta = now.tv_nsec - ctx->last_message_time.tv_nsec;
    if (nsec_delta < 0L) {
      --sec_delta;
      nsec_delta += 1000000000L;
    }
    if (sec_delta < 0 || (sec_delta == 0 && nsec_delta < 1000000000L)) {
      allow_message = false;
    }
  }

  if (!allow_message) {
    session_send_system_line(ctx, "Please wait at least one second before sending another message.");
    return;
  }

  ctx->last_message_time = now;
  ctx->has_last_message_time = true;

  if (ctx->translation_enabled && ctx->input_translation_enabled && ctx->input_translation_language[0] != '\0') {
    char translated_text[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    char detected_lang[SSH_CHATTER_LANG_NAME_LEN];
    if (translator_translate(normalized, ctx->input_translation_language, translated_text, sizeof(translated_text),
                             detected_lang, sizeof(detected_lang))) {
      snprintf(ctx->last_detected_input_language, sizeof(ctx->last_detected_input_language), "%s", detected_lang);
      snprintf(normalized, sizeof(normalized), "%.*s", (int)sizeof(normalized) - 1, translated_text);
    } else {
      session_send_system_line(ctx, "Translation failed; sending your original message.");
    }
  }

  chat_history_entry_t entry = {0};
  if (!host_history_record_user(ctx->owner, ctx, normalized, &entry)) {
    return;
  }

  session_send_history_entry(ctx, &entry);
  chat_room_broadcast_entry(&ctx->owner->room, &entry, ctx);
  host_notify_external_clients(ctx->owner, &entry);
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
  snprintf(notice, sizeof(notice), "* %s has been kicked by %s", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);

  if (target->channel == NULL || target->session == NULL) {
    target->should_exit = true;
    target->has_joined_room = false;
    chat_room_remove(&ctx->owner->room, target);
    session_send_system_line(ctx, "User removed from the chat.");
  } else {
    session_send_system_line(target, "You have been kicked by an operator.");
    target->should_exit = true;
    ssh_channel_send_eof(target->channel);
    ssh_channel_close(target->channel);
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
  snprintf(notice, sizeof(notice), "* %s has been banned by %s", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
  session_send_system_line(ctx, "Ban applied.");
  printf("[ban] %s banned %s (%s)\n", ctx->user.name, target->user.name, target_ip[0] != '\0' ? target_ip : "unknown");

  if (target->channel != NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "You have been banned by %s.", ctx->user.name);
    session_send_system_line(target, message);
    target->should_exit = true;
    ssh_channel_send_eof(target->channel);
    ssh_channel_close(target->channel);
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
  ssh_channel_write(target->channel, "\a", 1U);
  session_send_system_line(ctx, "Poke sent.");
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
  if (target == NULL) {
    char not_found[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, not_found);
    return;
  }

  printf("[pm] %s -> %s: %s\n", ctx->user.name, target->user.name, message);

  char to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_target_label, sizeof(to_target_label), "%s -> you", ctx->user.name);
  session_send_private_message_line(target, ctx, to_target_label, message);

  char to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_sender_label, sizeof(to_sender_label), "you -> %s", target->user.name);
  session_send_private_message_line(ctx, ctx, to_sender_label, message);
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

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "There %s currently %zu user%s connected.",
           count == 1U ? "is" : "are", count, count == 1U ? "" : "s");

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
      "Usage: /os <windows|macos|linux|freebsd|ios|android|watchos|solaris|openbsd|netbsd|dragonflybsd|reactos|tyzen>";
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
  snprintf(announce, sizeof(announce), "* %s started poll #%" PRIu64 ": %s", ctx->user.name, host->poll.id, tokens[0]);
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
    snprintf(message, sizeof(message), "* %s closed poll [%s].", ctx->user.name, label);
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
  snprintf(announce, sizeof(announce), "* %s started poll [%s] #%" PRIu64 ": %.*s", ctx->user.name, label, snapshot.poll.id,
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

// Render an ASCII framed view of a post, including metadata and comments.
static void session_bbs_render_post(session_ctx_t *ctx, const bbs_post_t *post) {
  if (ctx == NULL || post == NULL || !post->in_use) {
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "BBS Post #%" PRIu64, post->id);
  session_render_separator(ctx, header);

  char created_buffer[32];
  char bumped_buffer[32];
  bbs_format_time(post->created_at, created_buffer, sizeof(created_buffer));
  bbs_format_time(post->bumped_at, bumped_buffer, sizeof(bumped_buffer));

  char metadata[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(metadata, sizeof(metadata), "Title : %s", post->title);
  session_send_system_line(ctx, metadata);
  snprintf(metadata, sizeof(metadata), "Author: %s", post->author);
  session_send_system_line(ctx, metadata);
  snprintf(metadata, sizeof(metadata), "Created: %s (bumped %s)", created_buffer, bumped_buffer);
  session_send_system_line(ctx, metadata);

  if (post->tag_count > 0U) {
    char tag_line[SSH_CHATTER_MESSAGE_LIMIT];
    int header_written = snprintf(tag_line, sizeof(tag_line), "Tags  : ");
    size_t offset = header_written > 0 ? (size_t)header_written : 0U;
    if (offset >= sizeof(tag_line)) {
      offset = sizeof(tag_line) - 1U;
    }
    for (size_t idx = 0U; idx < post->tag_count; ++idx) {
      if (offset + strlen(post->tags[idx]) + 2U >= sizeof(tag_line)) {
        break;
      }
      if (idx > 0U) {
        tag_line[offset++] = ',';
      }
      size_t len = strlen(post->tags[idx]);
      memcpy(tag_line + offset, post->tags[idx], len);
      offset += len;
      tag_line[offset] = '\0';
    }
    session_send_system_line(ctx, tag_line);
  } else {
    session_send_system_line(ctx, "Tags  : (none)");
  }

  session_render_separator(ctx, "Body");
  const char *body_cursor = post->body;
  while (body_cursor != NULL && *body_cursor != '\0') {
    const char *newline = strchr(body_cursor, '\n');
    if (newline == NULL) {
      session_send_system_line(ctx, body_cursor);
      break;
    }
    size_t len = (size_t)(newline - body_cursor);
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (len >= sizeof(line)) {
      len = sizeof(line) - 1U;
    }
    memcpy(line, body_cursor, len);
    line[len] = '\0';
    session_send_system_line(ctx, line);
    body_cursor = newline + 1;
  }
  if (post->body[0] == '\0') {
    session_send_system_line(ctx, "(empty)");
  }

  session_render_separator(ctx, "Comments");
  if (post->comment_count == 0U) {
    session_send_system_line(ctx, "No comments yet.");
  } else {
    for (size_t idx = 0U; idx < post->comment_count; ++idx) {
      const bbs_comment_t *comment = &post->comments[idx];
      char comment_time[32];
      bbs_format_time(comment->created_at, comment_time, sizeof(comment_time));
      char line[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(line, sizeof(line), "[%zu] %s (%s)", idx + 1U, comment->author, comment_time);
      session_send_system_line(ctx, line);
      session_send_system_line(ctx, comment->text);
    }
  }

  session_render_separator(ctx, "End");
}

// Show the BBS dashboard and mark the session as being in BBS mode.
static void session_bbs_show_dashboard(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  ctx->in_bbs_mode = true;
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

  session_render_separator(ctx, "BBS Posts");
  for (size_t idx = 0U; idx < count; ++idx) {
    char created_buffer[32];
    bbs_format_time(listings[idx].bumped_at, created_buffer, sizeof(created_buffer));
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    int title_preview = (int)strnlen(listings[idx].title, sizeof(listings[idx].title));
    if (title_preview > 80) {
      title_preview = 80;
    }
    if (listings[idx].tag_count == 0U) {
      snprintf(line, sizeof(line), "#%" PRIu64 " [%s] %.*s|(no tags)", listings[idx].id, created_buffer, title_preview,
               listings[idx].title);
    } else {
      char tag_buffer[SSH_CHATTER_MESSAGE_LIMIT];
      size_t offset = 0U;
      tag_buffer[0] = '\0';
      for (size_t tag = 0U; tag < listings[idx].tag_count; ++tag) {
        size_t len = strlen(listings[idx].tags[tag]);
        if (offset + len + 2U >= sizeof(tag_buffer)) {
          break;
        }
        if (tag > 0U) {
          tag_buffer[offset++] = ',';
        }
        memcpy(tag_buffer + offset, listings[idx].tags[tag], len);
        offset += len;
        tag_buffer[offset] = '\0';
      }
      int tags_preview = (int)strnlen(tag_buffer, sizeof(tag_buffer));
      if (tags_preview > 80) {
        tags_preview = 80;
      }
      snprintf(line, sizeof(line), "#%" PRIu64 " [%s] %.*s|%.*s", listings[idx].id, created_buffer, title_preview,
               listings[idx].title, tags_preview, tag_buffer);
    }
    session_send_system_line(ctx, line);
  }

  session_render_separator(ctx, "End");
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

  session_bbs_render_post(ctx, &snapshot);
}

// Create a new post using the provided argument format.
static void session_bbs_reset_pending_post(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->bbs_post_pending = false;
  ctx->pending_bbs_title[0] = '\0';
  ctx->pending_bbs_body[0] = '\0';
  ctx->pending_bbs_body_length = 0U;
  ctx->pending_bbs_tag_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_TAGS; ++idx) {
    ctx->pending_bbs_tags[idx][0] = '\0';
  }
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
  post->tag_count = ctx->pending_bbs_tag_count;
  for (size_t idx = 0U; idx < post->tag_count; ++idx) {
    snprintf(post->tags[idx], sizeof(post->tags[idx]), "%s", ctx->pending_bbs_tags[idx]);
  }

  bbs_post_t snapshot = *post;
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_bbs_reset_pending_post(ctx);

  session_send_system_line(ctx, "Post created.");
  session_bbs_render_post(ctx, &snapshot);
}

static void session_bbs_begin_post(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->bbs_post_pending) {
    session_send_system_line(ctx, "You are already composing a post. Finish it with " SSH_CHATTER_BBS_TERMINATOR ".");
    return;
  }

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
        memcpy(ctx->pending_bbs_tags[tag_count], tag_cursor, length);
        ctx->pending_bbs_tags[tag_count][length] = '\0';
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

  char title_line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(title_line, sizeof(title_line), "Composing '%s'", ctx->pending_bbs_title);
  session_send_system_line(ctx, title_line);
  char tag_buffer[SSH_CHATTER_BBS_MAX_TAGS * (SSH_CHATTER_BBS_TAG_LEN + 2)];
  tag_buffer[0] = '\0';
  size_t offset = 0U;
  for (size_t idx = 0U; idx < tag_count; ++idx) {
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
  snprintf(tags_line, sizeof(tags_line), "Tags: %s", tag_buffer);
  session_send_system_line(ctx, tags_line);
  if (default_tag_applied) {
    char default_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(default_line, sizeof(default_line), "No tags provided; default tag '%s' applied.", SSH_CHATTER_BBS_DEFAULT_TAG);
    session_send_system_line(ctx, default_line);
  }
  session_send_system_line(ctx, "Enter your post body. Type " SSH_CHATTER_BBS_TERMINATOR
                               " on a line by itself when you are finished (Ctrl+S inserts it automatically).");
  session_send_system_line(ctx, "Sending the terminator immediately will cancel the draft.");
  if (discarded_tags) {
    session_send_system_line(ctx, "Only the first four tags were kept. Extra tags were ignored.");
  }
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

  size_t available = sizeof(ctx->pending_bbs_body) - ctx->pending_bbs_body_length - 1U;
  if (available == 0U) {
    session_send_system_line(ctx, "Post body length limit reached. Additional text ignored.");
    return;
  }

  size_t line_length = strlen(line);
  bool needs_newline = ctx->pending_bbs_body_length > 0U;
  if (needs_newline) {
    if (available == 0U) {
      session_send_system_line(ctx, "Post body length limit reached. Additional text ignored.");
      return;
    }
    ctx->pending_bbs_body[ctx->pending_bbs_body_length++] = '\n';
    available--;
  }

  if (line_length > available) {
    line_length = available;
    session_send_system_line(ctx, "Line truncated to fit within the post size limit.");
  }

  if (line_length > 0U) {
    memcpy(ctx->pending_bbs_body + ctx->pending_bbs_body_length, line, line_length);
    ctx->pending_bbs_body_length += line_length;
  }

  ctx->pending_bbs_body[ctx->pending_bbs_body_length] = '\0';
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
  comment->created_at = time(NULL);
  post->bumped_at = comment->created_at;
  bbs_post_t snapshot = *post;
  host_bbs_state_save_locked(host);
  pthread_mutex_unlock(&host->lock);

  session_send_system_line(ctx, "Comment added.");
  session_bbs_render_post(ctx, &snapshot);
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

  session_send_system_line(ctx, "Post bumped to the top.");
  session_bbs_render_post(ctx, &snapshot);
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
    session_send_system_line(ctx, "Exited BBS mode.");
    return;
  }

  ctx->in_bbs_mode = true;

  if (strcmp(command, "list") == 0) {
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

static void session_handle_motd(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  char motd[sizeof(ctx->owner->motd)];

  pthread_mutex_lock(&ctx->owner->lock);
  snprintf(motd, sizeof(motd), "%s", ctx->owner->motd);
  pthread_mutex_unlock(&ctx->owner->lock);

  if (motd[0] == '\0') {
    session_send_system_line(ctx, "No message of the day is configured.");
    return;
  }

  session_send_raw_text(ctx, motd);
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
    snprintf(message, sizeof(message), "%s has not set a status.", target->user.name);
    session_send_system_line(ctx, message);
    return;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "%s's status: %s", target->user.name, target->status_message);
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
    session_translation_clear_queue(ctx);
    session_send_system_line(ctx, "Translation disabled. New messages will be delivered without translation.");
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
  if (enabled) {
    session_send_system_line(ctx, "Translation enabled. Configure directions with /set-trans-lang or /set-target-lang.");
  } else {
    session_translation_clear_queue(ctx);
    session_send_system_line(ctx, "Translation disabled. New messages will be delivered without translation.");
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
  snprintf(announcement, sizeof(announcement), "* %s is now known as %s", old_name, ctx->user.name);
  host_history_record_system(ctx->owner, announcement);
  chat_room_broadcast(&ctx->owner->room, announcement, NULL);
  session_apply_saved_preferences(ctx);
  session_send_system_line(ctx, "Display name updated.");
}

static void session_handle_exit(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->should_exit = true;
  session_send_system_line(ctx, "Disconnecting... bye!");
  if (ctx->channel != NULL) {
    ssh_channel_send_eof(ctx->channel);
  }
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

  pthread_mutex_lock(&host->lock);
  join_activity_entry_t *entry = host_find_join_activity_locked(host, ip);
  if (entry == NULL) {
    if (host->join_activity_count >= host->join_activity_capacity) {
      size_t new_capacity = host->join_activity_capacity > 0U ? host->join_activity_capacity * 2U : 8U;
      join_activity_entry_t *resized =
          realloc(host->join_activity, new_capacity * sizeof(join_activity_entry_t));
      if (resized == NULL) {
        pthread_mutex_unlock(&host->lock);
        return false;
      }
      host->join_activity = resized;
      host->join_activity_capacity = new_capacity;
    }

    entry = &host->join_activity[host->join_activity_count++];
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
  }

  struct timespec diff = timespec_diff(&now, &entry->last_attempt);
  const long long diff_ns = (long long)diff.tv_sec * 1000000000LL + (long long)diff.tv_nsec;
  const bool within_window = (entry->last_attempt.tv_sec != 0 || entry->last_attempt.tv_nsec != 0) &&
                             diff_ns <= 1000000000LL;

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

  if (entry->rapid_attempts >= 10U) {
    ban_ip = true;
  }
  if (entry->same_name_attempts >= 10U) {
    ban_same_name = true;
  }
  pthread_mutex_unlock(&host->lock);

  if (ban_ip || ban_same_name) {
    const char *ban_user = (username != NULL && username[0] != '\0') ? username : "";
    if (host_add_ban_entry(host, ban_user, ip)) {
      printf("[auto-ban] %s flagged for rapid reconnects\n", ip);
    }
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
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  return removed;
}

static bool session_parse_command(const char *line, const char *command, const char **arguments) {
  size_t command_len = strlen(command);

  if (strncmp(line, command, command_len) == 0) {
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

  else if (session_parse_command(line, "/ban", &args)) {
    session_handle_ban(ctx, args);
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
  else if (session_parse_command(line, "/chat-spacing", &args)) {
    session_handle_chat_spacing(ctx, args);
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
  if (ctx == NULL || ctx->session == NULL) {
    return false;
  }

  return ssh_get_fd(ctx->session) >= 0;
}

static void session_close_channel(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->channel == NULL) {
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
  ctx->input_history_count = 0U;
  ctx->input_history_position = -1;
  ctx->history_scroll_position = 0U;
  ctx->has_last_message_time = false;
  ctx->last_message_time.tv_sec = 0;
  ctx->last_message_time.tv_nsec = 0;
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

  session_translation_worker_shutdown(ctx);
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

  session_apply_theme_defaults(ctx);

  bool authenticated = false;
  unsigned int handshake_retries = 0U;
  while (true) {
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
    if (ctx->owner->motd[0] != '\0') {
      session_send_system_line(ctx, ctx->owner->motd);
    }
    session_send_system_line(ctx, "Type /help to explore available commands.");

    char join_message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(join_message, sizeof(join_message), "* %s has joined the chat", ctx->user.name);
    host_history_record_system(ctx->owner, join_message);
    chat_room_broadcast(&ctx->owner->room, join_message, NULL);
  }

  session_clear_input(ctx);
  session_render_prompt(ctx, true);

  char buffer[SSH_CHATTER_MAX_INPUT_LEN];
  while (!ctx->should_exit) {
    session_translation_flush_ready(ctx);

    const int bytes_read =
        ssh_channel_read_timeout(ctx->channel, buffer, sizeof(buffer) - 1U, 0, 200);
    if (bytes_read == SSH_AGAIN) {
      continue;
    }
    if (bytes_read == SSH_ERROR || bytes_read == SSH_EOF) {
      break;
    }
    if (bytes_read == 0) {
      if (ctx->channel != NULL && (ssh_channel_is_eof(ctx->channel) || !ssh_channel_is_open(ctx->channel))) {
        break;
      }
      continue;
    }
    if (bytes_read < 0) {
      break;
    }

    for (int idx = 0; idx < bytes_read; ++idx) {
      const char ch = buffer[idx];

      if (session_consume_escape_sequence(ctx, ch)) {
        continue;
      }

      if (ch == 0x13) {
        if (ctx->bbs_post_pending) {
          ctx->input_buffer[ctx->input_length] = '\0';
          bool had_body = ctx->input_length > 0U;
          if (had_body) {
            session_local_echo_char(ctx, '\n');
            session_history_record(ctx, ctx->input_buffer);
            session_bbs_capture_body_line(ctx, ctx->input_buffer);
          } else {
            session_local_echo_char(ctx, '\n');
          }

          const char *terminator = SSH_CHATTER_BBS_TERMINATOR;
          for (const char *cursor = terminator; *cursor != '\0'; ++cursor) {
            session_local_echo_char(ctx, *cursor);
          }
          session_local_echo_char(ctx, '\n');
          session_history_record(ctx, terminator);
          session_bbs_capture_body_line(ctx, terminator);
          session_clear_input(ctx);
          if (ctx->should_exit) {
            break;
          }
          session_render_prompt(ctx, false);
        }
        continue;
      }

      if (ch == '\r' || ch == '\n') {
        session_local_echo_char(ctx, '\n');
        if (ctx->input_length > 0U) {
          ctx->input_buffer[ctx->input_length] = '\0';
          session_history_record(ctx, ctx->input_buffer);
          session_process_line(ctx, ctx->input_buffer);
        }
        session_clear_input(ctx);
        if (ctx->should_exit) {
          break;
        }
        session_render_prompt(ctx, false);
        continue;
      }

      if (ch == '\b' || ch == 0x7f) {
        ctx->input_history_position = -1;
        ctx->history_scroll_position = 0U;
        session_local_backspace(ctx);
        continue;
      }

      if (ch == '\t') {
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
    snprintf(part_message, sizeof(part_message), "* %s has left the chat", ctx->user.name);
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
  snprintf(host->version, sizeof(host->version), "ssh-chatter (C, rolling release)");
  snprintf(host->motd, sizeof(host->motd),
  "Welcome to ssh-chat!\n"
  "\033[1G- Be polite to each other\n"
  "\033[1G- fun fact: this server is written in pure c.\n"
  "\033[1G============================================\n"
  "\033[1G _      ____  ____  _____ ____  _        ____  _ \n"
  "\033[1G/ \\__/|/  _ \\/  _ \\/  __//  __\\/ \\  /|  /   _\\/ \\\n"
  "\033[1G| |\\/||| / \\|| | \\||  \\  |  \\/|| |\\ ||  |  /  | |\n"
  "\033[1G| |  ||| \\_/|| |_/||  /_ |    /| | \\||  |  \\__\\_/\n"
  "\033[1G\\_/  \\|\\____/\\____/\\____\\\\_/\\_\\\\_/  \\|  \\____/(_)\n"
  "\033[1G                                                 \n"
  "\033[1G============================================\n");


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

  (void)host_try_load_motd_from_path(host, "/etc/ssh-chatter/motd");

  host_state_load(host);
  host_vote_state_load(host);
  host_bbs_state_load(host);

  host->clients = client_manager_create(host);
  if (host->clients == NULL) {
    humanized_log_error("host", "failed to create client manager", ENOMEM);
  } else {
    host->web_client = webssh_client_create(host, host->clients);
    if (host->web_client == NULL) {
      humanized_log_error("host", "failed to initialise webssh client", ENOMEM);
    }

  }
}

static bool host_try_load_motd_from_path(host_t *host, const char *path) {
  if (host == NULL || path == NULL || path[0] == '\0') {
    return false;
  }

  FILE *motd_file = fopen(path, "rb");
  if (motd_file == NULL) {
    return false;
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
        snprintf(motd_clean + offset, sizeof(motd_clean) - offset, "\033[1G%s\n", motd_line);
    if (written < 0 || (size_t)written >= sizeof(motd_clean) - offset) {
      offset = sizeof(motd_clean) - 1U;
      break;
    }
    offset += (size_t)written;
    motd_line = strtok_r(NULL, "\n", &next_line);
  }
  motd_clean[sizeof(motd_clean) - 1U] = '\0';
  snprintf(host->motd, sizeof(host->motd), "%s", motd_clean);
  pthread_mutex_unlock(&host->lock);
  return true;
}

void host_set_motd(host_t *host, const char *motd) {
  if (host == NULL || motd == NULL) {
    return;
  }

  if (host_try_load_motd_from_path(host, motd)) {
    return;
  }

  char normalized[sizeof(host->motd)];
  snprintf(normalized, sizeof(normalized), "%s", motd);
  session_normalize_newlines(normalized);

  pthread_mutex_lock(&host->lock);
  snprintf(host->motd, sizeof(host->motd), "%s", normalized);
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

void host_shutdown(host_t *host) {
  if (host == NULL) {
    return;
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
}

int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory) {
  if (host == NULL) {
    return -1;
  }

  const char *address = bind_addr != NULL ? bind_addr : "0.0.0.0";
  const char *bind_port = port != NULL ? port : "2222";
  const char *rsa_filename = "ssh_host_rsa_key";
  const char *rsa_key_path = NULL;
  char resolved_rsa_key[PATH_MAX];

  if (key_directory != NULL && key_directory[0] != '\0') {
    const size_t dir_len = strlen(key_directory);
    if (dir_len >= sizeof(resolved_rsa_key)) {
      humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
      return -1;
    }
    const bool needs_separator = dir_len > 0 && key_directory[dir_len - 1U] != '/';
    int written = snprintf(resolved_rsa_key, sizeof(resolved_rsa_key), "%s%s%s", key_directory,
                           needs_separator ? "/" : "", rsa_filename);
    if (written < 0 || (size_t)written >= sizeof(resolved_rsa_key)) {
      humanized_log_error("host", "host key directory path is too long", ENAMETOOLONG);
      return -1;
    }
    rsa_key_path = resolved_rsa_key;
  } else {
    const char *candidates[] = {rsa_filename, "/etc/ssh/ssh_host_rsa_key"};
    for (size_t idx = 0; idx < sizeof(candidates) / sizeof(candidates[0]); ++idx) {
      if (access(candidates[idx], R_OK) == 0) {
        rsa_key_path = candidates[idx];
        break;
      }
    }
  }

  if (rsa_key_path == NULL) {
    humanized_log_error("host", "unable to locate RSA host key", ENOENT);
    return -1;
  }

  if (access(rsa_key_path, R_OK) != 0) {
    humanized_log_error("host", "unable to access RSA host key", errno);
    return -1;
  }

  while (true) {
    ssh_bind bind_handle = ssh_bind_new();
    if (bind_handle == NULL) {
      humanized_log_error("host", "failed to allocate ssh_bind", ENOMEM);
      return -1;
    }

    ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDADDR, address);
    ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_BINDPORT_STR, bind_port);
    ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    errno = 0;
    bool key_loaded = false;
    if (ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_RSAKEY, rsa_key_path) == SSH_OK) {
      key_loaded = true;
    } else {
      const char *error_message = ssh_get_error(bind_handle);
      const bool unsupported_option = (error_message != NULL &&
                                       strstr(error_message, "Unknown ssh option") != NULL) ||
                                      errno == ENOTSUP;
      if (!unsupported_option) {
        humanized_log_error("host", error_message, errno != 0 ? errno : EIO);
        ssh_bind_free(bind_handle);
        return -1;
      }

      ssh_key imported_key = NULL;
      if (ssh_pki_import_privkey_file(rsa_key_path, NULL, NULL, NULL, &imported_key) != SSH_OK ||
          imported_key == NULL) {
        humanized_log_error("host", "failed to import RSA host key", EIO);
        ssh_bind_free(bind_handle);
        return -1;
      }

      const int import_result =
          ssh_bind_options_set(bind_handle, SSH_BIND_OPTIONS_IMPORT_KEY, imported_key);
      ssh_key_free(imported_key);
      if (import_result != SSH_OK) {
        humanized_log_error("host", ssh_get_error(bind_handle), errno != 0 ? errno : EIO);
        ssh_bind_free(bind_handle);
        return -1;
      }

      key_loaded = true;
    }

    if (!key_loaded) {
      humanized_log_error("host", "failed to configure host key", EIO);
      ssh_bind_free(bind_handle);
      return -1;
    }

    if (ssh_bind_listen(bind_handle) < 0) {
      humanized_log_error("host", ssh_get_error(bind_handle), EIO);
      ssh_bind_free(bind_handle);
      return -1;
    }

    host->listener.handle = bind_handle;
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
        humanized_log_error("host", bind_error, accept_error != 0 ? accept_error : EIO);

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
          printf("[listener] restarting after listener socket error\n");
          restart_listener = true;
          break;
        }
        continue;
      }

      if (ssh_handle_key_exchange(session) != SSH_OK) {
        humanized_log_error("host", ssh_get_error(session), EPROTO);
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
      ctx->owner = host;
      ctx->auth = (auth_profile_t){0};
      snprintf(ctx->client_ip, sizeof(ctx->client_ip), "%.*s", (int)sizeof(ctx->client_ip) - 1, peer_address);

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
      break;
    }

    struct timespec backoff = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };
    nanosleep(&backoff, NULL);
    printf("[listener] attempting to restart listener after socket error\n");
  }

  return 0;
}
