#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "headers/host.h"

#include <gc/gc.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static double host_elapsed_seconds(const struct timespec *start, const struct timespec *end) {
  if (start == NULL || end == NULL) {
    return 0.0;
  }

  time_t sec = end->tv_sec - start->tv_sec;
  long nsec = end->tv_nsec - start->tv_nsec;
  if (nsec < 0L) {
    --sec;
    nsec += 1000000000L;
  }
  if (sec < 0) {
    sec = 0;
    nsec = 0L;
  }

  return (double)sec + (double)nsec / 1000000000.0;
}

static void host_reset_session_bbs_view(session_ctx_t *session) {
  if (session == NULL) {
    return;
  }

  session->bbs_view_active = false;
  session->bbs_view_post_id = 0U;
  session->bbs_view_scroll_offset = 0U;
  session->bbs_view_total_lines = 0U;
  session->bbs_view_notice_pending = false;
  session->bbs_rendering_editor = false;
}

static size_t bbs_count_lines(const char *text) {
  if (text == NULL || text[0] == '\0') {
    return 0U;
  }

  size_t lines = 1U;
  for (const char *cursor = text; *cursor != '\0'; ++cursor) {
    if (*cursor == '\n') {
      ++lines;
    }
  }
  return lines;
}

static bool bbs_post_matches_topic(const bbs_post_t *post, const char *topic) {
  if (post == NULL || !post->in_use) {
    return false;
  }

  if (topic == NULL || topic[0] == '\0') {
    return true;
  }

  for (size_t idx = 0U; idx < post->tag_count; ++idx) {
    if (strcasecmp(post->tags[idx], topic) == 0) {
      return true;
    }
  }
  return false;
}

static void bbs_sort_indexes_by_bumped(const host_t *host, size_t *indexes, size_t count) {
  if (host == NULL || indexes == NULL) {
    return;
  }

  for (size_t outer = 0U; outer + 1U < count; ++outer) {
    size_t best = outer;
    for (size_t inner = outer + 1U; inner < count; ++inner) {
      const bbs_post_t *candidate = &host->bbs_posts[indexes[inner]];
      const bbs_post_t *current_best = &host->bbs_posts[indexes[best]];
      if (candidate->bumped_at > current_best->bumped_at) {
        best = inner;
      } else if (candidate->bumped_at == current_best->bumped_at &&
                 candidate->id > current_best->id) {
        best = inner;
      }
    }
    if (best != outer) {
      size_t tmp = indexes[outer];
      indexes[outer] = indexes[best];
      indexes[best] = tmp;
    }
  }
}

static size_t bbs_collect_indexes(const host_t *host, const char *topic, size_t *indexes, size_t capacity) {
  if (host == NULL || indexes == NULL || capacity == 0U) {
    return 0U;
  }

  size_t count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    if (count >= capacity) {
      break;
    }
    const bbs_post_t *post = &host->bbs_posts[idx];
    if (!post->in_use) {
      continue;
    }
    if (!bbs_post_matches_topic(post, topic)) {
      continue;
    }
    indexes[count++] = idx;
  }

  bbs_sort_indexes_by_bumped(host, indexes, count);
  return count;
}

static bool bbs_apply_selection(session_ctx_t *session, const bbs_post_t *post) {
  if (session == NULL || post == NULL) {
    return false;
  }

  session->bbs_view_active = true;
  session->bbs_view_post_id = post->id;
  session->bbs_view_scroll_offset = 0U;
  session->bbs_view_total_lines = bbs_count_lines(post->body);
  session->bbs_view_notice_pending = false;
  return true;
}

static bool bbs_focus_adjacent(const host_t *host, session_ctx_t *session, const char *topic, bool forward,
                               bool wrap) {
  if (host == NULL || session == NULL) {
    return false;
  }

  size_t indexes[SSH_CHATTER_BBS_MAX_POSTS];
  size_t count = bbs_collect_indexes(host, topic, indexes, SSH_CHATTER_BBS_MAX_POSTS);
  if (count == 0U) {
    host_reset_session_bbs_view(session);
    return false;
  }

  size_t current_pos = count;
  if (session->bbs_view_post_id != 0U) {
    for (size_t idx = 0U; idx < count; ++idx) {
      const bbs_post_t *candidate = &host->bbs_posts[indexes[idx]];
      if (candidate->id == session->bbs_view_post_id) {
        current_pos = idx;
        break;
      }
    }
  }

  size_t target_pos = 0U;
  if (current_pos >= count) {
    target_pos = forward ? 0U : (count - 1U);
  } else if (forward) {
    if (current_pos + 1U < count) {
      target_pos = current_pos + 1U;
    } else if (wrap) {
      target_pos = 0U;
    } else {
      return false;
    }
  } else {
    if (current_pos > 0U) {
      target_pos = current_pos - 1U;
    } else if (wrap) {
      target_pos = count - 1U;
    } else {
      return false;
    }
  }

  const bbs_post_t *target = &host->bbs_posts[indexes[target_pos]];
  return bbs_apply_selection(session, target);
}

bool host_bbs_focus_next_post(host_t *host, session_ctx_t *session, const char *topic, bool wrap) {
  return bbs_focus_adjacent(host, session, topic, true, wrap);
}

bool host_bbs_focus_previous_post(host_t *host, session_ctx_t *session, const char *topic, bool wrap) {
  return bbs_focus_adjacent(host, session, topic, false, wrap);
}

void host_bbs_reset_view(session_ctx_t *session) {
  host_reset_session_bbs_view(session);
}

void host_set_session_idle_timeout(host_t *host, unsigned int seconds) {
  if (host == NULL) {
    return;
  }

  host->session_idle_timeout_seconds = seconds;
}

unsigned int host_get_session_idle_timeout(const host_t *host) {
  if (host == NULL) {
    return 0U;
  }

  return host->session_idle_timeout_seconds;
}

static bool host_pick_reference_time(const struct timespec *hint, struct timespec *out_time) {
  if (out_time == NULL) {
    return false;
  }

  if (hint != NULL) {
    *out_time = *hint;
    return true;
  }

  if (clock_gettime(CLOCK_MONOTONIC, out_time) != 0) {
    return false;
  }

  return true;
}

bool host_session_idle_expired(const host_t *host, const session_ctx_t *session, const struct timespec *now) {
  if (host == NULL || session == NULL) {
    return false;
  }

  if (host->session_idle_timeout_seconds == 0U) {
    return false;
  }

  if (!session->has_last_message_time) {
    return false;
  }

  struct timespec reference_now = {0, 0};
  if (!host_pick_reference_time(now, &reference_now)) {
    return false;
  }

  double elapsed = host_elapsed_seconds(&session->last_message_time, &reference_now);
  return elapsed >= (double)host->session_idle_timeout_seconds;
}

void host_note_session_activity(host_t *host, session_ctx_t *session, const struct timespec *now) {
  (void)host;
  if (session == NULL) {
    return;
  }

  struct timespec reference_now = {0, 0};
  if (!host_pick_reference_time(now, &reference_now)) {
    return;
  }

  session->last_message_time = reference_now;
  session->has_last_message_time = true;
}

void host_init(host_t *host, auth_profile_t *auth) {
  if (host == NULL) {
    return;
  }

  memset(host, 0, sizeof(*host));
  host->auth = auth;
  host->session_idle_timeout_seconds = 0U;
  pthread_mutex_init(&host->lock, NULL);
  pthread_mutex_init(&host->user_data_lock, NULL);
  host->user_data_lock_initialized = true;
  pthread_mutex_init(&host->alpha_landers_lock, NULL);
  host->alpha_landers_lock_initialized = true;
}

void host_set_motd(host_t *host, const char *motd) {
  if (host == NULL) {
    return;
  }

  if (motd == NULL) {
    host->motd[0] = '\0';
    return;
  }

  size_t length = strlen(motd);
  if (length >= sizeof(host->motd)) {
    length = sizeof(host->motd) - 1U;
  }
  memcpy(host->motd, motd, length);
  host->motd[length] = '\0';
}

int host_serve(host_t *host, const char *bind_addr, const char *port, const char *key_directory,
               const char *telnet_bind_addr, const char *telnet_port) {
  (void)host;
  (void)bind_addr;
  (void)port;
  (void)key_directory;
  (void)telnet_bind_addr;
  (void)telnet_port;
  return 0;
}

bool host_post_client_message(host_t *host, const char *username, const char *message, const char *color_name,
                             const char *highlight_name, bool is_bold) {
  (void)color_name;
  (void)highlight_name;
  (void)is_bold;
  if (host == NULL || username == NULL || message == NULL) {
    return false;
  }

  (void)host;
  (void)username;
  (void)message;
  return true;
}

void host_shutdown(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->user_data_lock_initialized) {
    pthread_mutex_destroy(&host->user_data_lock);
    host->user_data_lock_initialized = false;
  }
  if (host->alpha_landers_lock_initialized) {
    pthread_mutex_destroy(&host->alpha_landers_lock);
    host->alpha_landers_lock_initialized = false;
  }
  pthread_mutex_destroy(&host->lock);
}

bool host_snapshot_last_captcha(host_t *host, char *question, size_t question_length, char *answer,
                               size_t answer_length, struct timespec *timestamp) {
  if (host == NULL) {
    return false;
  }

  if (!host->has_last_captcha) {
    return false;
  }

  if (question != NULL && question_length > 0U) {
    size_t copy = 0U;
    while (copy < sizeof(host->last_captcha_question) && host->last_captcha_question[copy] != '\0') {
      ++copy;
    }
    if (copy >= question_length) {
      copy = question_length - 1U;
    }
    memcpy(question, host->last_captcha_question, copy);
    question[copy] = '\0';
  }
  if (answer != NULL && answer_length > 0U) {
    size_t copy = 0U;
    while (copy < sizeof(host->last_captcha_answer) && host->last_captcha_answer[copy] != '\0') {
      ++copy;
    }
    if (copy >= answer_length) {
      copy = answer_length - 1U;
    }
    memcpy(answer, host->last_captcha_answer, copy);
    answer[copy] = '\0';
  }
  if (timestamp != NULL) {
    *timestamp = host->last_captcha_generated;
  }
  return true;
}

void *GC_CALLOC(size_t len, size_t t_len) {
  if (t_len != 0U && len > SIZE_MAX / t_len) {
    errno = ENOMEM;
    return NULL;
  }

  size_t total = len * t_len;
  void *memory = GC_malloc(total);
  if (memory != NULL) {
    memset(memory, 0, total);
  }
  return memory;
}
