#define _POSIX_C_SOURCE 200809L

#include "lib/headers/host.h"
#include "lib/headers/humanized/humanized.h"

#include <errno.h>
#include <getopt.h>
#include <gc/gc.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <time.h>

#define HOST_STABLE_RESET_SECONDS 10.0

static void print_usage(const char *prog_name) {
  fprintf(stderr,
          "Usage: %s [-a address] [-p port] [-m motd_file] [-k host_key_dir] [-T telnet_port|off]\n"
          "       %s [-h]\n"
          "       %s [-V]\n",
          prog_name, prog_name, prog_name);
}

static double timespec_elapsed_seconds(const struct timespec *start, const struct timespec *end) {
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

static void sleep_before_restart(unsigned int attempts) {
  struct timespec restart_delay = {
      .tv_sec = attempts < 5U ? 1L : (attempts < 10U ? 5L : 30L),
      .tv_nsec = 0L,
  };
  nanosleep(&restart_delay, NULL);
}

int main(int argc, char **argv) {
  setlocale(LC_ALL, "");
  GC_INIT();

  const char *bind_address = NULL;
  const char *bind_port = NULL;
  const char *motd = NULL;
  const char *host_key_dir = NULL;
  const char *telnet_port = "2323";
  bool telnet_enabled = true;
  char telnet_bind_storage[64];
  telnet_bind_storage[0] = '\0';
  bool telnet_bind_overridden = false;
  char telnet_port_storage[16];
  telnet_port_storage[0] = '\0';

  int opt = 0;
  while ((opt = getopt(argc, argv, "a:p:m:k:T:hV")) != -1) {
    switch (opt) {
      case 'a':
        bind_address = optarg;
        break;
      case 'p':
        bind_port = optarg;
        break;
      case 'm':
        motd = optarg;
        break;
      case 'k':
        host_key_dir = optarg;
        break;
      case 'T':
        if (optarg != NULL &&
            (strcmp(optarg, "off") == 0 || strcmp(optarg, "disable") == 0 || strcmp(optarg, "none") == 0)) {
          telnet_enabled = false;
          telnet_port = NULL;
          telnet_bind_overridden = false;
        } else if (optarg != NULL) {
          const char *value = optarg;
          const char *colon = strchr(value, ':');
          if (colon != NULL) {
            size_t host_len = (size_t)(colon - value);
            if (host_len >= sizeof(telnet_bind_storage)) {
              fprintf(stderr,
                      "telnet bind address is too long; ignoring override and using default listener address\n");
              telnet_bind_storage[0] = '\0';
              telnet_bind_overridden = false;
            } else if (host_len > 0U) {
              memcpy(telnet_bind_storage, value, host_len);
              telnet_bind_storage[host_len] = '\0';
              telnet_bind_overridden = true;
            } else {
              telnet_bind_overridden = false;
            }

            const char *port_part = colon + 1;
            if (port_part[0] == '\0') {
              telnet_port = "2323";
            } else {
              size_t port_len = strlen(port_part);
              if (port_len >= sizeof(telnet_port_storage)) {
                fprintf(stderr, "telnet port is too long; using default port 2323\n");
                telnet_port = "2323";
              } else {
                memcpy(telnet_port_storage, port_part, port_len + 1);
                telnet_port = telnet_port_storage;
              }
            }
          } else {
            telnet_bind_overridden = false;
            if (value[0] == '\0') {
              telnet_port = "2323";
            } else {
              size_t port_len = strlen(value);
              if (port_len >= sizeof(telnet_port_storage)) {
                fprintf(stderr, "telnet port is too long; using default port 2323\n");
                telnet_port = "2323";
              } else {
                memcpy(telnet_port_storage, value, port_len + 1);
                telnet_port = telnet_port_storage;
              }
            }
          }
          telnet_enabled = true;
        }
        break;
      case 'h':
        print_usage(argv[0]);
        return EXIT_SUCCESS;
      case 'V':
        printf("ssh-chatter (C)\n");
        return EXIT_SUCCESS;
      default:
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
  }

  if (!telnet_enabled) {
    telnet_port = NULL;
    telnet_bind_overridden = false;
  } else if (telnet_port != NULL && telnet_port[0] == '\0') {
    telnet_port = "2323";
  }

  const char *telnet_bind_address = telnet_bind_overridden ? telnet_bind_storage : NULL;

  auth_profile_t default_profile = {0};
  unsigned int restart_attempts = 0U;

  while (true) {
    host_t *host = calloc(1, sizeof(*host));
    if (host == NULL) {
      ++restart_attempts;
      humanized_log_error("daemon", "failed to allocate host state", errno != 0 ? errno : ENOMEM);
      printf("[daemon] retrying host startup (attempt %u)\n", restart_attempts);
      sleep_before_restart(restart_attempts);
      continue;
    }

    host_init(host, &default_profile);

    if (motd != NULL) {
      host_set_motd(host, motd);
    }

    const char *address = bind_address != NULL ? bind_address : "0.0.0.0";
    const char *port = bind_port != NULL ? bind_port : "2222";
    printf("Starting ssh-chatter on %s:%s\n", address, port);

    struct timespec serve_start;
    clock_gettime(CLOCK_MONOTONIC, &serve_start);
    errno = 0;
    const int serve_result = host_serve(host, bind_address, bind_port, host_key_dir, telnet_bind_address, telnet_port);
    const int serve_errno = errno;
    struct timespec serve_end;
    clock_gettime(CLOCK_MONOTONIC, &serve_end);

    host_shutdown(host);
    free(host);
    host = NULL;

    if (serve_result == 0) {
      return EXIT_SUCCESS;
    }

    double runtime_seconds = timespec_elapsed_seconds(&serve_start, &serve_end);
    bool skip_restart_delay = false;
    if (runtime_seconds >= HOST_STABLE_RESET_SECONDS) {
      if (restart_attempts > 0U) {
        printf("[daemon] host ran for %.3f seconds; clearing restart backoff\n", runtime_seconds);
      }
      restart_attempts = 0U;
      skip_restart_delay = true;
    }

    ++restart_attempts;

    char detail[128];
    if (serve_result != 0) {
      snprintf(detail, sizeof(detail), "host_serve failed (code %d)", serve_result);
    } else {
      snprintf(detail, sizeof(detail), "host_serve returned unexpectedly");
    }
    humanized_log_error("daemon", detail, serve_errno != 0 ? serve_errno : EIO);
    printf("[daemon] restarting ssh-chatter (attempt %u)\n", restart_attempts);

    if (!skip_restart_delay) {
      sleep_before_restart(restart_attempts);
    }
  }
}
