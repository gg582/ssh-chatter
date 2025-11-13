#ifndef SSH_CHATTER_HOST_INTERNAL_H
#define SSH_CHATTER_HOST_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "../headers/host.h"
#include "../headers/client.h"
#include "../headers/webssh_client.h"
#include "../headers/matrix_client.h"
#include "../headers/translator.h"
#include "../headers/translation_helpers.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <inttypes.h>
#include <libgen.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../headers/memory_manager.h"
#include "../ssh_chatter_sync.h"
#include "humanized/humanized.h"

#endif // SSH_CHATTER_HOST_INTERNAL_H
