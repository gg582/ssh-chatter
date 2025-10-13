#ifndef HOST_H
#define HOST_H
#define MESSAGE_LIMIT 512 // 2-byte wide char: 256 letters limit
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifdef WINDOWS_MSVC
  #include <errno.h>
#elif UNIX_COMPATIBLE
  #include <error.h>
#endif
#include <time.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include "theme.h"
#define MAX_USERS 512
#define MAX_INPUT_LEN 1024
/* Include PThread to declare pthread_mutex_t in ChatRoom structure */

typedef struct MessageUser {
  chat name[24];
  int isOp;
} MessageUser;

typedef struct ChatRoom {
  pthread_mutex_t lock;
  MessageUser * members[512];
} ChatRoom;

typedef struct Auth {
  bool isBanned;
  bool isOperator;
  bool isObserver;
} Auth;

typedef struct SSHListener {
  ssh_bind bind;
  void (*HandlerFunc)(ssh_session);
} SSHListener;

typedef struct Host {
  ChatRoom room;
  SSHListener listener;
  Auth * auth;
  UserTheme userTheme;
  SystemTheme sysTheme;
  char version[64];
  char motd[256];
  int count;
  pthread_mutex_t mu;
} Host;

#endif
