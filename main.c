#define _POSIX_C_SOURCE 200809L

#include "lib/headers/host.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <time.h>

static void print_usage(const char *prog_name) {
  fprintf(stderr,
          "Usage: %s [-a address] [-p port] [-m motd_file] [-k host_key_dir]\n"
          "       %s [-h]\n"
          "       %s [-V]\n",
          prog_name, prog_name, prog_name);
}

int main(int argc, char **argv) {
  setlocale(LC_ALL, "");

  const char *bind_address = NULL;
  const char *bind_port = NULL;
  const char *motd = NULL;
  const char *host_key_dir = NULL;

  int opt = 0;
  while ((opt = getopt(argc, argv, "a:p:m:k:hV")) != -1) {
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

  auth_profile_t default_profile = {0};
  unsigned int restart_attempts = 0U;

  while (true) {
    host_t *host = calloc(1, sizeof(*host));
    if (host == NULL) {
      fprintf(stderr, "failed to allocate host state\n");
      return EXIT_FAILURE;
    }

    host_init(host, &default_profile);

    if (motd != NULL) {
      host_set_motd(host, motd);
    }

    const char *address = bind_address != NULL ? bind_address : "0.0.0.0";
    const char *port = bind_port != NULL ? bind_port : "2222";
    printf("Starting ssh-chatter on %s:%s\n", address, port);

    errno = 0;
    const int serve_result = host_serve(host, bind_address, bind_port, host_key_dir);
    const int serve_errno = errno;

    host_shutdown(host);
    free(host);
    host = NULL;

    if (serve_result == 0) {
      return EXIT_SUCCESS;
    }

    ++restart_attempts;

    const char *error_message = serve_errno != 0 ? strerror(serve_errno) : "unknown error";
    fprintf(stderr, "ssh-chatter encountered an internal error (code %d): %s\n", serve_result,
            error_message);
    fprintf(stderr, "Restarting ssh-chatter (attempt %u)...\n", restart_attempts);

    struct timespec restart_delay = {
        .tv_sec = restart_attempts < 5U ? 1L : (restart_attempts < 10U ? 5L : 30L),
        .tv_nsec = 0L,
    };
    nanosleep(&restart_delay, NULL);
  }
}
