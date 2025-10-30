#include <signal.h>
#define HOST_MODERATION_WORKER_STABLE_SECONDS 30.0
#define HOST_MODERATION_MAX_RESTART_ATTEMPTS 5U
                                         const char *username, const char *ip, session_ctx_t *session,
                                         bool post_send);
static void host_moderation_backoff(unsigned int attempts);
static bool host_moderation_spawn_worker(host_t *host);
static void host_moderation_close_worker(host_t *host);
static bool host_moderation_recover_worker(host_t *host, const char *diagnostic);
                                         const host_moderation_ipc_response_t *response, const char *message);
static double host_elapsed_seconds(const struct timespec *start, const struct timespec *end);
static void host_moderation_backoff(unsigned int attempts) {
  struct timespec delay = {
      .tv_sec = (attempts < 3U) ? 1L : ((attempts < 6U) ? 5L : 30L),
      .tv_nsec = 0L,
  };
  nanosleep(&delay, NULL);
}

static void host_moderation_close_worker(host_t *host) {
  if (host == NULL) {
    return;
  }

  if (host->moderation.request_fd >= 0) {
    close(host->moderation.request_fd);
    host->moderation.request_fd = -1;
  }
  if (host->moderation.response_fd >= 0) {
    close(host->moderation.response_fd);
    host->moderation.response_fd = -1;
  }

  if (host->moderation.worker_pid > 0) {
    int status = 0;
    pid_t result = waitpid(host->moderation.worker_pid, &status, WNOHANG);
    if (result == 0) {
      (void)kill(host->moderation.worker_pid, SIGTERM);
      (void)waitpid(host->moderation.worker_pid, &status, 0);
    }
    host->moderation.worker_pid = -1;
  }
}

static bool host_moderation_spawn_worker(host_t *host) {
  if (host == NULL) {
    return false;
  }

  int request_pipe[2] = {-1, -1};
  int response_pipe[2] = {-1, -1};

  if (pipe(request_pipe) != 0) {
    return false;
  }
  if (pipe(response_pipe) != 0) {
    close(request_pipe[0]);
    close(request_pipe[1]);
    return false;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(request_pipe[0]);
    close(request_pipe[1]);
    close(response_pipe[0]);
    close(response_pipe[1]);
    return false;
  }

  if (pid == 0) {
    close(request_pipe[1]);
    close(response_pipe[0]);
    host_moderation_worker_loop(request_pipe[0], response_pipe[1]);
  }

  close(request_pipe[0]);
  close(response_pipe[1]);

  host->moderation.worker_pid = pid;
  host->moderation.request_fd = request_pipe[1];
  host->moderation.response_fd = response_pipe[0];

  if (clock_gettime(CLOCK_MONOTONIC, &host->moderation.worker_start_time) != 0) {
    host->moderation.worker_start_time.tv_sec = 0;
    host->moderation.worker_start_time.tv_nsec = 0;
  }

  return true;
}

static bool host_moderation_recover_worker(host_t *host, const char *diagnostic) {
  if (host == NULL) {
    return false;
  }

  const char *reason = (diagnostic != NULL && diagnostic[0] != '\0') ? diagnostic : "moderation worker failure";

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
    double runtime = host_elapsed_seconds(&host->moderation.worker_start_time, &now);
    if (runtime >= HOST_MODERATION_WORKER_STABLE_SECONDS && host->moderation.restart_attempts > 0U) {
      host->moderation.restart_attempts = 0U;
    }
  } else {
    host->moderation.restart_attempts = 0U;
  }

  unsigned int attempt = host->moderation.restart_attempts + 1U;

  char detail[256];
  snprintf(detail, sizeof(detail), "moderation worker panic (%s)", reason);
  humanized_log_error("moderation", detail, EIO);
  printf("[moderation] worker panic (%s); scheduling restart attempt %u\n", reason, attempt);

  host_moderation_close_worker(host);
  host_moderation_flush_pending(host, reason);

  if (attempt > HOST_MODERATION_MAX_RESTART_ATTEMPTS) {
    humanized_log_error("moderation", "too many moderation worker panics; disabling moderation filter", EIO);
    pthread_mutex_lock(&host->moderation.mutex);
    host->moderation.active = false;
    host->moderation.stop = true;
    pthread_cond_broadcast(&host->moderation.cond);
    pthread_mutex_unlock(&host->moderation.mutex);
    atomic_store(&host->security_filter_enabled, false);
    return false;
  }

  host_moderation_backoff(attempt);

  if (!host_moderation_spawn_worker(host)) {
    humanized_log_error("moderation", "failed to restart moderation worker", EIO);
    pthread_mutex_lock(&host->moderation.mutex);
    host->moderation.active = false;
    host->moderation.stop = true;
    pthread_cond_broadcast(&host->moderation.cond);
    pthread_mutex_unlock(&host->moderation.mutex);
    atomic_store(&host->security_filter_enabled, false);
    return false;
  }

  host->moderation.restart_attempts = attempt;

  pthread_mutex_lock(&host->moderation.mutex);
  host->moderation.active = true;
  host->moderation.stop = false;
  pthread_cond_broadcast(&host->moderation.cond);
  pthread_mutex_unlock(&host->moderation.mutex);

  printf("[moderation] worker recovered after panic (attempt %u)\n", attempt);
  return true;
}

    GC_FREE(task);
      bool recovered = host_moderation_recover_worker(host, failure_reason);
      GC_FREE(task);
      if (!recovered) {
        break;
      }
      failure_reason = NULL;
      continue;
      bool recovered = host_moderation_recover_worker(host, failure_reason);
      GC_FREE(task);
      if (!recovered) {
        break;
      }
      failure_reason = NULL;
      continue;
      message = (char *)GC_MALLOC(message_length + 1U);
        char *discard = (char *)GC_MALLOC(message_length);
          GC_FREE(discard);
        bool recovered = host_moderation_recover_worker(host, failure_reason);
        GC_FREE(task);
        if (!recovered) {
          break;
        }
        failure_reason = NULL;
        continue;
        bool recovered = host_moderation_recover_worker(host, failure_reason);
        GC_FREE(message);
        GC_FREE(task);
        if (!recovered) {
          break;
        }
        failure_reason = NULL;
        continue;
    if (message != NULL) {
      GC_FREE(message);
    }
    GC_FREE(task);
    failure_reason = NULL;
  host->moderation.restart_attempts = 0U;
  host->moderation.worker_start_time.tv_sec = 0;
  host->moderation.worker_start_time.tv_nsec = 0;
  if (!host_moderation_spawn_worker(host)) {
  host_moderation_close_worker(host);
  host->moderation.restart_attempts = 0U;
  host->moderation.worker_start_time.tv_sec = 0;
  host->moderation.worker_start_time.tv_nsec = 0;
  host_moderation_task_t *task =
      (host_moderation_task_t *)GC_MALLOC(sizeof(*task));
