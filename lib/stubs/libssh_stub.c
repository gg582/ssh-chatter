#include "libssh/libssh.h"
#include "libssh/server.h"

#include <stdlib.h>
#include <string.h>

int ssh_get_fd(ssh_session session) {
  (void)session;
  return -1;
}

ssh_session ssh_new(void) {
  return calloc(1, sizeof(struct ssh_session_struct));
}

void ssh_free(ssh_session session) {
  free(session);
}

int ssh_handle_key_exchange(ssh_session session) {
  (void)session;
  return SSH_OK;
}

const char *ssh_get_error(void *error_source) {
  (void)error_source;
  return "libssh stub error";
}

ssh_message ssh_message_get(ssh_session session) {
  (void)session;
  return NULL;
}

int ssh_message_type(ssh_message message) {
  if (message == NULL) {
    return -1;
  }
  return message->type;
}

int ssh_message_subtype(ssh_message message) {
  if (message == NULL) {
    return -1;
  }
  return message->subtype;
}

const char *ssh_message_auth_user(ssh_message message) {
  if (message == NULL) {
    return NULL;
  }
  return message->user;
}

void ssh_message_auth_reply_success(ssh_message message, int partial) {
  (void)message;
  (void)partial;
}

void ssh_message_free(ssh_message message) {
  free(message);
}

void ssh_message_reply_default(ssh_message message) {
  (void)message;
}

ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message message) {
  (void)message;
  return calloc(1, sizeof(struct ssh_channel_struct));
}

void ssh_message_channel_request_reply_success(ssh_message message) {
  (void)message;
}

ssh_channel ssh_channel_new(void) {
  return calloc(1, sizeof(struct ssh_channel_struct));
}

int ssh_channel_write(ssh_channel channel, const void *data, size_t len) {
  (void)channel;
  (void)data;
  return (int)len;
}

int ssh_channel_read(ssh_channel channel, void *data, size_t len, int is_stderr) {
  (void)channel;
  (void)data;
  (void)len;
  (void)is_stderr;
  return 0;
}

int ssh_channel_send_eof(ssh_channel channel) {
  (void)channel;
  return SSH_OK;
}

int ssh_channel_close(ssh_channel channel) {
  (void)channel;
  return SSH_OK;
}

void ssh_channel_free(ssh_channel channel) {
  free(channel);
}

int ssh_disconnect(ssh_session session) {
  (void)session;
  return SSH_OK;
}

ssh_bind ssh_bind_new(void) {
  return calloc(1, sizeof(struct ssh_bind_struct));
}

void ssh_bind_free(ssh_bind bind) {
  free(bind);
}

int ssh_bind_options_set(ssh_bind bind, ssh_bind_options_e type, const void *value) {
  (void)bind;
  (void)type;
  (void)value;
  return SSH_OK;
}

int ssh_bind_listen(ssh_bind bind) {
  (void)bind;
  return SSH_OK;
}

int ssh_bind_accept(ssh_bind bind, ssh_session session) {
  (void)bind;
  (void)session;
  return SSH_ERROR;
}

int ssh_pki_import_privkey_file(const char *filename, const char *passphrase,
                                void *auth_fn, void *auth_data, ssh_key *pkey) {
  (void)filename;
  (void)passphrase;
  (void)auth_fn;
  (void)auth_data;
  if (pkey == NULL) {
    return SSH_ERROR;
  }
  *pkey = calloc(1, sizeof(struct ssh_key_struct));
  if (*pkey == NULL) {
    return SSH_ERROR;
  }
  return SSH_OK;
}

void ssh_key_free(ssh_key key) {
  free(key);
}
