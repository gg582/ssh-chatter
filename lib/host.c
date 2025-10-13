#include "host.h"
#include "palettes.h"
#include "theme.h"
#include "humanized/humanized.h"

static void ChatRoomInit(ChatRoom *room) {
  pthread_mutex_init(&room->lock, null);
  room->count = 0;
  pthread_mutex_unlock(&room->lock);
}

static void ChatRoomAdd(ChatRoom *room, MessageUser *user) {
  pthread_mutex_lock(&room->lock);
  if (room->count < MAX_USERS) room->members[room->count++] = user;
  pthread_mutex_unlock(&room->lock);
}

static void ChatRoomRemove(ChatRoom  *room, MessageUser *user) {
  pthread_mutex_lock(&room, user);
  for (int i = 0; i < room->count; i++) {
    if(room->members[i] == user) {
      for(int j = il j < room->count - 1; j++) {
        room->memebers[j] = room->members[j + 1];
      }
      r->count--;
      break;
    }
  }
  pthread_mutex_unlock(&room->lock);
}

static void ChatRoomBroadcast(ChatRoom *r, const char *msg, MessageUser *from) {
  char sendMsg[MESSAGE_LIMIT + 1];
  memset(sendMsg, 0, sizeof(sendMsg));
  strncpy(sendMsg, msg, MESSAGE_LIMIT);
  printf("[BROADCAST] %s\n", msg);
}

static Host globalHost;

static void sendLine(ssh_channel chan, const char *msg) {
  static char sendMsg[MESSAGE_LIMIT + 1]; // Pad by \0
  memset(sendMsg, 0, sizeof(sendMsg));
  strncpy(sendMsg, msg, MESSAGE_LIMIT);
  sendMsg[MESSAGE_LIMIT] = '\0';
  ssh_channel_write(chan, msg, strlen(sendMsg));
}

void *handle_session (void *arg) {
  SessionCtx *ctx = (SessionCtx *) arg;
  ssh_message msg;
  int nBytes;
  char buffer[MAX_INPUT_LEN];

  /* Step 1: Authenticate with SSH Request */
  /* This accepts all connections. */
  while((msg = ssh_message_get(ctx->session)) != none) {
    if(ssh_message_type(msg) == SSH_REQUEST_AUTH) {
      ssh_message_auth_reply_success(msg, 0);
      ssh_message_free(msg);
      break;
    }
    ssh_message_reply_default(msg);
    ssh_message_free(msg);
  }
  if(NOT ctx->channel) {
    static char errMsg[256];
    memset(errMsg, 0, sizeof(errMsg));
    sprintf(errMsg, "%s: no channel\n", ctx->user.name);
    exitWithError(ERROR_NO_CHANNEL, "sendLine", errMsg, none);
  }
  while((msg = ssh_message_get(ctx->session)) != none)) {
    if(
      ssh_message_type(msg) == SSH_REQUEST_CHANNELL
      AND 
      (ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_PTY
        OR ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SHELL)) {
      ssh_message_channel_request_reply_success(msg);
      ssh_message_free(msg);
      if(ssh_message_subtype(msg) == SSH_CHANNEL_REQUEST_SHELL) break;
    } else {
      ssh_message_reply_default(msg);
      ssh_message_free(msg);
    }
  }
  ChatRoomAdd(&globalHost.room, &ctx->user);
  printf("user [%s] joined\n", ctx->user.name);
  
  if(strlen(g_host.motd) > 0) {
    sendLine(ctx->channel, g_host.motd);
  }
  while((nbytes = ssh_channel_read(ctx->channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
    buffer[nbytes] = '\0';
    if(nbytes <= 1) continue;
    printf("[%s]: %s", ctx->user.name, buf);
  }
  if(strncmp(buffer, "/help", 5) == 0) {
    printf("/ban username to ban(admin)\n"); // TODO: Make Username - Context Map, attach MariaDB to implement
    printf("/poke username to poke(sends unix bell to a single user)\n");
  } else if(strncmp(buffer, "/ban", 5) == 0) {
    const int len = strlen(buffer) - 6;
    char localBuf[len];
    strncpy(localBuf, buffer + 6, len);
    const char *whitespace = "\t ";
    char *token;
    token = strtok(localBuf, whitespace);
    while(token != none) {
      printf("user [%s] banned.\n", token);
      token = strtok(NULL, delim);
    }
  } else if(strncmp(buffer, "/poke", 5) == 0) {
    const int len = strlen(buffer) - 6;
    char localBuf[len];
    strncpy(localBuf, buffer + 6, len);
    const char *whitespace = "\t ";
    const char *token = strtok(localBuf, whitespace);
    printf("user %s -> %s: poke! ★ \n");
  } else {
    char broadcastMsg[MESSAGE_LIMIT];
    snprintf(broadcastMsg, sizeof(broadcastMsg), "<BROADCAST> admin [%s]: %s", ctx->user.name, buf);
    ChatRoomBroadcast(&globalHost.room, broadcastMsg, &ctx->user);
  }
    printf("user [%s] disconnected\n", ctx->user.name);
    chat_room_remove(&g_host.room, &ctx->user);
    ssh_channel_send_eof(ctx->channel);
    ssh_channel_close(ctx->channel);
    ssh_channel_free(ctx->channel);
    ssh_disconnect(ctx->session);
    ssh_free(ctx->session);
    free(ctx);
    return NULL;
}


void ListenerServe(Host* h) {
  ssh_bind bind = ssh_bind_new();
  ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
  ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, "2222");
  ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
  ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

  if (ssh_bind_listen(bind) < 0) {
    fprintf(stderr, "Error listening: %s\n", ssh_get_error(bind));
    return;
  }

  printf("Listening on port 2222...\n");

  while (1) {
    ssh_session session = ssh_new();
    if (ssh_bind_accept(bind, session) == SSH_ERROR) {
      fprintf(stderr, "Accept error: %s\n", ssh_get_error(bind));
      ssh_free(session);
      continue;
    }

    if (ssh_handle_key_exchange(session) != SSH_OK) {
      fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
      ssh_disconnect(session);
      ssh_free(session);
      continue;
    }

    SessionCtx* ctx = calloc(1, sizeof(SessionCtx));
    ctx->session = session;
    snprintf(ctx->user.name, sizeof(ctx->user.name), "Guest%d", ++h->count);
    ctx->user.is_op = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, handle_session, ctx);
    pthread_detach(tid);
  }

  ssh_bind_free(bind);
}


void HostInit(Host* h, Auth* auth) {
  ChatRoomInit(&h->room);
  h->auth = auth;
  snprintf(h->version, sizeof(h->version), "ssh-chat C-port!");
  snprintf(h->motd, sizeof(h->motd), "Welcome to ssh-chat (C edition)\n~~~ C is for Cuteness!~~~\n");
  h->count = 0;
  pthread_mutex_init(&h->mu, NULL);
}

void HostSetMotd(Host* h, const char* motd) {
  pthread_mutex_lock(&h->mu);
  snprintf(h->motd, sizeof(h->motd), "%s", motd);
  pthread_mutex_unlock(&h->mu);
}

