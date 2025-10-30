#include "matrix_client.h"
#define SSH_CHATTER_STRONG_CIPHERS "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
#define SSH_CHATTER_STRONG_MACS "hmac-sha2-512,hmac-sha2-256"
#define SSH_CHATTER_SECURE_COMPRESSION "none"
  host->matrix_client = NULL;
  host->security_layer_initialized = security_layer_init(&host->security_layer);
  if (!host->security_layer_initialized) {
    humanized_log_error("security", "failed to initialise layered message encryption", errno != 0 ? errno : EIO);
  }
    if (host->security_layer_initialized) {
      host->matrix_client = matrix_client_create(host, host->clients, &host->security_layer);
      if (host->matrix_client == NULL) {
        humanized_log_error("matrix", "matrix backend inactive; check CHATTER_MATRIX_* configuration", EINVAL);
      }
    }

  if (host->matrix_client != NULL) {
    matrix_client_destroy(host->matrix_client);
    host->matrix_client = NULL;
  }
  if (host->security_layer_initialized) {
    security_layer_free(&host->security_layer);
    host->security_layer_initialized = false;
  }
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_CIPHERS_C_S, SSH_CHATTER_STRONG_CIPHERS,
                                  "failed to configure forward cipher suite");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_CIPHERS_S_C, SSH_CHATTER_STRONG_CIPHERS,
                                  "failed to configure reverse cipher suite");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HMAC_C_S, SSH_CHATTER_STRONG_MACS,
                                  "failed to configure forward MAC list");
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_HMAC_S_C, SSH_CHATTER_STRONG_MACS,
                                  "failed to configure reverse MAC list");
#ifdef SSH_BIND_OPTIONS_COMPRESSION_C_S
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_COMPRESSION_C_S, SSH_CHATTER_SECURE_COMPRESSION,
                                  "failed to restrict forward compression mode");
#endif
#ifdef SSH_BIND_OPTIONS_COMPRESSION_S_C
    host_bind_set_optional_string(bind_handle, SSH_BIND_OPTIONS_COMPRESSION_S_C, SSH_CHATTER_SECURE_COMPRESSION,
                                  "failed to restrict reverse compression mode");
#endif
