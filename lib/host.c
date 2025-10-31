#define SSH_CHATTER_CONNECTION_GUARD_WINDOW_NS 5000000000LL
#define SSH_CHATTER_CONNECTION_GUARD_THRESHOLD 8U
#define SSH_CHATTER_CONNECTION_GUARD_BLOCK_BASE_NS 2000000000LL
#define SSH_CHATTER_CONNECTION_GUARD_BLOCK_STEP_NS 2000000000LL
#define SSH_CHATTER_CONNECTION_GUARD_BLOCK_MAX_NS 60000000000LL
#define SSH_CHATTER_CONNECTION_GUARD_RETENTION_NS 300000000000LL
#define SSH_CHATTER_CONNECTION_GUARD_BAN_THRESHOLD 5U
#define SSH_CHATTER_ERROR_BACKOFF_BASE_NS 1000000000LL
#define SSH_CHATTER_ERROR_BACKOFF_MAX_NS 15000000000LL
#define SSH_CHATTER_ERROR_BACKOFF_STABLE_NS 10000000000LL
static long long timespec_to_ns(const struct timespec *value) {
  if (value == NULL) {
    return 0LL;
  }

  return (long long)value->tv_sec * 1000000000LL + (long long)value->tv_nsec;
}

static struct timespec timespec_add_ns(const struct timespec *start, long long nanoseconds) {
  struct timespec result = {0, 0};
  if (start != NULL) {
    result = *start;
  }

  if (nanoseconds < 0) {
    return result;
  }

  result.tv_sec += (time_t)(nanoseconds / 1000000000LL);
  result.tv_nsec += (long)(nanoseconds % 1000000000LL);
  if (result.tv_nsec >= 1000000000L) {
    result.tv_sec += result.tv_nsec / 1000000000L;
    result.tv_nsec %= 1000000000L;
  }
  return result;
}

typedef struct connection_guard_result {
  bool blocked;
  bool escalate_ban;
  struct timespec blocked_until;
  size_t attempt_count;
  unsigned int block_count;
} connection_guard_result_t;

static void host_connection_guard_prune_locked(host_t *host, const struct timespec *now) {
  if (host == NULL || now == NULL || host->connection_guard_count == 0U) {
    return;
  }

  size_t write_idx = 0U;
  const size_t original_count = host->connection_guard_count;
  for (size_t idx = 0U; idx < original_count; ++idx) {
    connection_guard_entry_t *entry = &host->connection_guard[idx];
    if (entry->ip[0] == '\0') {
      continue;
    }

    if (entry->last_seen.tv_sec != 0 || entry->last_seen.tv_nsec != 0) {
      struct timespec age = timespec_diff(now, &entry->last_seen);
      long long age_ns = timespec_to_ns(&age);
      if (age_ns > SSH_CHATTER_CONNECTION_GUARD_RETENTION_NS) {
        continue;
      }
    }

    if (write_idx != idx) {
      host->connection_guard[write_idx] = *entry;
    }
    ++write_idx;
  }

  if (write_idx < original_count) {
    size_t cleared = original_count - write_idx;
    memset(&host->connection_guard[write_idx], 0, cleared * sizeof(host->connection_guard[write_idx]));
  }
  host->connection_guard_count = write_idx;
}

static connection_guard_entry_t *host_find_connection_guard_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL) {
    return NULL;
  }

  for (size_t idx = 0U; idx < host->connection_guard_count; ++idx) {
    connection_guard_entry_t *entry = &host->connection_guard[idx];
    if (strncmp(entry->ip, ip, SSH_CHATTER_IP_LEN) == 0) {
      return entry;
    }
  }

  return NULL;
}

static connection_guard_entry_t *host_ensure_connection_guard_locked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return NULL;
  }

  connection_guard_entry_t *entry = host_find_connection_guard_locked(host, ip);
  if (entry != NULL) {
    return entry;
  }

  if (host->connection_guard_count >= host->connection_guard_capacity) {
    size_t new_capacity = host->connection_guard_capacity > 0U ? host->connection_guard_capacity * 2U : 16U;
    connection_guard_entry_t *resized =
        realloc(host->connection_guard, new_capacity * sizeof(connection_guard_entry_t));
    if (resized == NULL) {
      return NULL;
    }
    host->connection_guard = resized;
    memset(&host->connection_guard[host->connection_guard_capacity], 0,
           (new_capacity - host->connection_guard_capacity) * sizeof(connection_guard_entry_t));
    host->connection_guard_capacity = new_capacity;
  }

  entry = &host->connection_guard[host->connection_guard_count++];
  memset(entry, 0, sizeof(*entry));
  snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
  return entry;
}

static connection_guard_result_t host_connection_guard_register(host_t *host, const char *ip) {
  connection_guard_result_t result = {0};
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return result;
  }

  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);

  pthread_mutex_lock(&host->lock);
  host_connection_guard_prune_locked(host, &now);
  connection_guard_entry_t *entry = host_ensure_connection_guard_locked(host, ip);
  if (entry == NULL) {
    pthread_mutex_unlock(&host->lock);
    return result;
  }

  entry->last_seen = now;

  if (entry->blocked_until.tv_sec != 0 || entry->blocked_until.tv_nsec != 0) {
    if (timespec_compare(&entry->blocked_until, &now) > 0) {
      result.blocked = true;
      result.blocked_until = entry->blocked_until;
      result.block_count = entry->block_count;
      result.attempt_count = entry->attempts;
      pthread_mutex_unlock(&host->lock);
      return result;
    }
    entry->blocked_until.tv_sec = 0;
    entry->blocked_until.tv_nsec = 0L;
  }

  if (entry->window_start.tv_sec == 0 && entry->window_start.tv_nsec == 0) {
    entry->window_start = now;
    entry->attempts = 0U;
  } else {
    struct timespec diff = timespec_diff(&now, &entry->window_start);
    long long window_ns = timespec_to_ns(&diff);
    if (window_ns > SSH_CHATTER_CONNECTION_GUARD_WINDOW_NS) {
      entry->window_start = now;
      entry->attempts = 0U;
      if (window_ns > SSH_CHATTER_CONNECTION_GUARD_RETENTION_NS) {
        entry->block_count = 0U;
      }
    }
  }

  if (entry->attempts < SIZE_MAX) {
    entry->attempts += 1U;
  }
  result.attempt_count = entry->attempts;
  result.block_count = entry->block_count;

  if (entry->attempts >= SSH_CHATTER_CONNECTION_GUARD_THRESHOLD) {
    size_t attempt_snapshot = entry->attempts;
    if (entry->block_count < UINT_MAX) {
      entry->block_count += 1U;
    }
    long long penalty_ns = SSH_CHATTER_CONNECTION_GUARD_BLOCK_BASE_NS +
                           (long long)(entry->block_count > 0U ? entry->block_count - 1U : 0U) *
                               SSH_CHATTER_CONNECTION_GUARD_BLOCK_STEP_NS;
    if (penalty_ns > SSH_CHATTER_CONNECTION_GUARD_BLOCK_MAX_NS) {
      penalty_ns = SSH_CHATTER_CONNECTION_GUARD_BLOCK_MAX_NS;
    }
    entry->blocked_until = timespec_add_ns(&now, penalty_ns);
    entry->window_start = now;
    entry->attempts = 0U;

    result.blocked = true;
    result.blocked_until = entry->blocked_until;
    result.block_count = entry->block_count;
    result.attempt_count = attempt_snapshot;
    if (entry->block_count >= SSH_CHATTER_CONNECTION_GUARD_BAN_THRESHOLD) {
      result.escalate_ban = true;
    }
  }

  pthread_mutex_unlock(&host->lock);
  return result;
}

static void host_error_guard_register_success(host_t *host) {
  if (host == NULL) {
    return;
  }

  host->health_guard.consecutive_errors = 0U;
  host->health_guard.last_error_time.tv_sec = 0;
  host->health_guard.last_error_time.tv_nsec = 0L;
}

  host->connection_guard = NULL;
  host->connection_guard_count = 0U;
  host->connection_guard_capacity = 0U;
  host->health_guard.consecutive_errors = 0U;
  host->health_guard.last_error_time.tv_sec = 0;
  host->health_guard.last_error_time.tv_nsec = 0L;
static void host_sleep_after_error(host_t *host) {
  struct timespec now = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &now);

  unsigned int streak = 1U;
  if (host != NULL) {
    if (host->health_guard.last_error_time.tv_sec != 0 || host->health_guard.last_error_time.tv_nsec != 0) {
      struct timespec diff = timespec_diff(&now, &host->health_guard.last_error_time);
      long long diff_ns = timespec_to_ns(&diff);
      if (diff_ns <= SSH_CHATTER_ERROR_BACKOFF_STABLE_NS && host->health_guard.consecutive_errors < UINT_MAX) {
        streak = host->health_guard.consecutive_errors + 1U;
      }
    }

    host->health_guard.consecutive_errors = streak;
    host->health_guard.last_error_time = now;
  }

  long long multiplier = (long long)streak;
  if (multiplier <= 0) {
    multiplier = 1LL;
  }

  const long long max_multiplier = SSH_CHATTER_ERROR_BACKOFF_MAX_NS / SSH_CHATTER_ERROR_BACKOFF_BASE_NS;
  if (multiplier > max_multiplier) {
    multiplier = max_multiplier;
  }

  long long delay_ns = SSH_CHATTER_ERROR_BACKOFF_BASE_NS * multiplier;
  if (delay_ns > SSH_CHATTER_ERROR_BACKOFF_MAX_NS) {
    delay_ns = SSH_CHATTER_ERROR_BACKOFF_MAX_NS;
  }
  if (delay_ns < SSH_CHATTER_ERROR_BACKOFF_BASE_NS) {
    delay_ns = SSH_CHATTER_ERROR_BACKOFF_BASE_NS;
  }

      .tv_sec = (time_t)(delay_ns / 1000000000LL),
      .tv_nsec = (long)(delay_ns % 1000000000LL),
  free(host->connection_guard);
  host->connection_guard = NULL;
  host->connection_guard_capacity = 0U;
  host->connection_guard_count = 0U;
  host->health_guard.consecutive_errors = 0U;
  host->health_guard.last_error_time.tv_sec = 0;
  host->health_guard.last_error_time.tv_nsec = 0L;
      host_sleep_after_error(host);
      host_sleep_after_error(host);
      host_sleep_after_error(host);
      host_sleep_after_error(host);
    host_error_guard_register_success(host);
      connection_guard_result_t guard = host_connection_guard_register(host, peer_address);
      if (guard.blocked) {
        struct timespec now_block = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &now_block);
        double wait_seconds = 0.0;
        if (timespec_compare(&guard.blocked_until, &now_block) > 0) {
          struct timespec remaining = timespec_diff(&guard.blocked_until, &now_block);
          wait_seconds = (double)remaining.tv_sec + (double)remaining.tv_nsec / 1000000000.0;
        }
        printf("[throttle] rate-limited connection from %s (attempts=%zu, penalty=%.2f seconds)\n",
               peer_address, guard.attempt_count, wait_seconds);
        ssh_disconnect(session);
        ssh_free(session);
        if (guard.escalate_ban && host_add_ban_entry(host, "", peer_address)) {
          printf("[auto-ban] %s banned after repeated connection flooding\n", peer_address);
        }
        continue;
      }

      if (guard.escalate_ban && host_add_ban_entry(host, "", peer_address)) {
        printf("[auto-ban] %s banned after repeated connection flooding\n", peer_address);
      }

      host_error_guard_register_success(host);
      host_sleep_after_error(host);
