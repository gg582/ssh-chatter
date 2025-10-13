#ifndef CONTEXT_SESSION_H
#define CONTEXT_SESSION_H

#include<libssh/libssh.h>
#include<libssh/server.h>
#include "host.h"

typedef struct SessionCtx {
  ssh_session session;
  ssh_channel channel;
  MessageUser user;
  Auth        auth;
} SessionCtx;

#endif
