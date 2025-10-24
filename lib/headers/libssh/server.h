#ifndef LIBSSH_SERVER_H
#define LIBSSH_SERVER_H

#include "libssh.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SSH_BIND_OPTIONS_BINDADDR,
  SSH_BIND_OPTIONS_BINDPORT,
  SSH_BIND_OPTIONS_BINDPORT_STR,
  SSH_BIND_OPTIONS_HOSTKEY,
  SSH_BIND_OPTIONS_DSAKEY,
  SSH_BIND_OPTIONS_RSAKEY,
  SSH_BIND_OPTIONS_BANNER,
  SSH_BIND_OPTIONS_LOG_VERBOSITY,
  SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
  SSH_BIND_OPTIONS_ECDSAKEY,
  SSH_BIND_OPTIONS_IMPORT_KEY,
  SSH_BIND_OPTIONS_ED25519KEY,
  SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS,
  SSH_BIND_OPTIONS_KEY_EXCHANGE
} ssh_bind_options_e;

ssh_bind ssh_bind_new(void);
void ssh_bind_free(ssh_bind bind);
int ssh_bind_options_set(ssh_bind bind, ssh_bind_options_e type, const void *value);
int ssh_bind_listen(ssh_bind bind);
int ssh_bind_accept(ssh_bind bind, ssh_session session);

#ifdef __cplusplus
}
#endif

#endif
