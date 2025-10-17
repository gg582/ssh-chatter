#ifndef LIBSSH_LIBSSH_H
#define LIBSSH_LIBSSH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ssh_session_struct {
  int placeholder;
} *ssh_session;

typedef struct ssh_channel_struct {
  int placeholder;
} *ssh_channel;

typedef struct ssh_message_struct {
  int type;
  int subtype;
  char user[32];
  char service[32];
} *ssh_message;

typedef struct ssh_bind_struct {
  int placeholder;
} *ssh_bind;

typedef struct ssh_key_struct {
  int placeholder;
} *ssh_key;

typedef enum {
  SSH_OK = 0,
  SSH_ERROR = -1
} ssh_status_t;

#define SSH_AGAIN -2
#define SSH_EOF -127

#define SSH_REQUEST_AUTH 1
#define SSH_REQUEST_CHANNEL_OPEN 2
#define SSH_REQUEST_CHANNEL 3
#define SSH_REQUEST_SERVICE 4
#define SSH_REQUEST_GLOBAL 5

#define SSH_CHANNEL_SESSION 1
#define SSH_CHANNEL_DIRECT_TCPIP 2
#define SSH_CHANNEL_FORWARDED_TCPIP 3
#define SSH_CHANNEL_X11 4
#define SSH_CHANNEL_AUTH_AGENT 5

#define SSH_CHANNEL_REQUEST_PTY 1
#define SSH_CHANNEL_REQUEST_EXEC 2
#define SSH_CHANNEL_REQUEST_SHELL 3
#define SSH_CHANNEL_REQUEST_ENV 4
#define SSH_CHANNEL_REQUEST_SUBSYSTEM 5
#define SSH_CHANNEL_REQUEST_WINDOW_CHANGE 6
#define SSH_CHANNEL_REQUEST_X11 7

int ssh_get_fd(ssh_session session);
ssh_session ssh_new(void);
void ssh_free(ssh_session session);

int ssh_handle_key_exchange(ssh_session session);
const char *ssh_get_error(void *error_source);

ssh_message ssh_message_get(ssh_session session);
int ssh_message_type(ssh_message message);
int ssh_message_subtype(ssh_message message);
const char *ssh_message_auth_user(ssh_message message);
void ssh_message_auth_reply_success(ssh_message message, int partial);
const char *ssh_message_service_service(ssh_message message);
int ssh_message_service_reply_success(ssh_message message);
void ssh_message_free(ssh_message message);
void ssh_message_reply_default(ssh_message message);
ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message message);
void ssh_message_channel_request_reply_success(ssh_message message);
int ssh_message_channel_request_open_reply_accept_channel(ssh_message message,
                                                         ssh_channel channel);

ssh_channel ssh_channel_new(ssh_session session);
int ssh_channel_write(ssh_channel channel, const void *data, size_t len);
int ssh_channel_read(ssh_channel channel, void *data, size_t len, int is_stderr);
int ssh_channel_read_timeout(ssh_channel channel, void *data, uint32_t len, int is_stderr, int timeout_ms);
int ssh_channel_send_eof(ssh_channel channel);
int ssh_channel_close(ssh_channel channel);
void ssh_channel_free(ssh_channel channel);

int ssh_disconnect(ssh_session session);

int ssh_pki_import_privkey_file(const char *filename, const char *passphrase,
                                void *auth_fn, void *auth_data, ssh_key *pkey);
void ssh_key_free(ssh_key key);

#ifdef __cplusplus
}
#endif

#endif
