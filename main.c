#include "lib/headers/host.h"

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

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
  host_t host;
  host_init(&host, &default_profile);

  if (motd != NULL) {
    host_set_motd(&host, motd);
  }

  printf("Starting ssh-chatter on %s:%s\n", bind_address != NULL ? bind_address : "0.0.0.0",
         bind_port != NULL ? bind_port : "2222");

  const int serve_result = host_serve(&host, bind_address, bind_port, host_key_dir);
  host_shutdown(&host);
  if (serve_result != 0) {
    fprintf(stderr, "Failed to start ssh-chatter: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
