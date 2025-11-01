#define _POSIX_C_SOURCE 200809L

#include "headers/security_layer.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gc_compat.h"

#define SECURITY_ONION_PREFIX "TorOnion/v1:"

static bool security_layer_derive_subkeys(security_layer_t *layer) {
  if (layer == NULL) {
    errno = EINVAL;
    return false;
  }

  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
      errno = ENOMEM;
      return false;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0U;
    unsigned char counter = (unsigned char)(idx + 1U);

    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, layer->master_key, sizeof(layer->master_key)) != 1 ||
        EVP_DigestUpdate(mdctx, &counter, sizeof(counter)) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1 || digest_len < 32U) {
      EVP_MD_CTX_free(mdctx);
      errno = EIO;
      return false;
    }

    memcpy(layer->subkeys[idx], digest, 32U);
    EVP_MD_CTX_free(mdctx);
  }

  return true;
}

bool security_layer_init(security_layer_t *layer) {
  if (layer == NULL) {
    errno = EINVAL;
    return false;
  }

  memset(layer, 0, sizeof(*layer));

  if (RAND_bytes(layer->master_key, sizeof(layer->master_key)) != 1) {
    errno = EIO;
    return false;
  }

  if (!security_layer_derive_subkeys(layer)) {
    OPENSSL_cleanse(layer->master_key, sizeof(layer->master_key));
    memset(layer->subkeys, 0, sizeof(layer->subkeys));
    layer->ready = false;
    return false;
  }

  layer->ready = true;
  return true;
}

void security_layer_free(security_layer_t *layer) {
  if (layer == NULL) {
    return;
  }

  OPENSSL_cleanse(layer->master_key, sizeof(layer->master_key));
  OPENSSL_cleanse(layer->subkeys, sizeof(layer->subkeys));
  layer->ready = false;
}

typedef struct security_layer_component {
  unsigned char iv[SECURITY_LAYER_IV_LEN];
  unsigned char tag[SECURITY_LAYER_TAG_LEN];
  unsigned char *ciphertext;
  size_t cipher_len;
} security_layer_component_t;

static void security_layer_component_reset(security_layer_component_t *component) {
  if (component == NULL) {
    return;
  }

  if (component->ciphertext != NULL) {
    OPENSSL_cleanse(component->ciphertext, component->cipher_len);
    free(component->ciphertext);
    component->ciphertext = NULL;
  }
  component->cipher_len = 0U;
  memset(component->iv, 0, sizeof(component->iv));
  memset(component->tag, 0, sizeof(component->tag));
}

static bool security_layer_encode_component(const security_layer_component_t *component, char **encoded_out) {
  if (component == NULL || encoded_out == NULL) {
    errno = EINVAL;
    return false;
  }

  size_t buffer_len = component->cipher_len + SECURITY_LAYER_IV_LEN + SECURITY_LAYER_TAG_LEN;
  unsigned char *buffer = (unsigned char *)GC_MALLOC(buffer_len == 0U ? 1U : buffer_len);
  if (buffer == NULL) {
    errno = ENOMEM;
    return false;
  }

  memcpy(buffer, component->iv, SECURITY_LAYER_IV_LEN);
  memcpy(buffer + SECURITY_LAYER_IV_LEN, component->tag, SECURITY_LAYER_TAG_LEN);
  if (component->cipher_len > 0U) {
    memcpy(buffer + SECURITY_LAYER_IV_LEN + SECURITY_LAYER_TAG_LEN, component->ciphertext, component->cipher_len);
  }

  size_t encoded_len = 4U * ((buffer_len + 2U) / 3U);
  char *encoded = (char *)GC_MALLOC(encoded_len + 1U);
  if (encoded == NULL) {
    OPENSSL_cleanse(buffer, buffer_len);
    free(buffer);
    errno = ENOMEM;
    return false;
  }

  int written = EVP_EncodeBlock((unsigned char *)encoded, buffer, (int)buffer_len);
  OPENSSL_cleanse(buffer, buffer_len);
  free(buffer);
  if (written <= 0) {
    OPENSSL_cleanse(encoded, encoded_len + 1U);
    free(encoded);
    errno = EIO;
    return false;
  }

  encoded[written] = '\0';
  *encoded_out = encoded;
  return true;
}

bool security_layer_encrypt_message(const security_layer_t *layer, const char *plaintext,
                                    char *out, size_t out_len) {
  if (layer == NULL || !layer->ready || plaintext == NULL || out == NULL || out_len == 0U) {
    errno = EINVAL;
    return false;
  }

  size_t plain_len = strlen(plaintext);
  if (plain_len > (size_t)INT_MAX) {
    errno = EOVERFLOW;
    return false;
  }

  unsigned char *working = NULL;
  if (plain_len > 0U) {
    working = (unsigned char *)GC_MALLOC(plain_len);
    if (working == NULL) {
      errno = ENOMEM;
      return false;
    }
    memcpy(working, plaintext, plain_len);
  } else {
    working = (unsigned char *)GC_MALLOC(1U);
    if (working == NULL) {
      errno = ENOMEM;
      return false;
    }
  }

  size_t working_len = plain_len;
  security_layer_component_t layers[SECURITY_LAYER_LEVELS];
  memset(layers, 0, sizeof(layers));

  bool success = true;
  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    security_layer_component_t *component = &layers[idx];
    if (RAND_bytes(component->iv, sizeof(component->iv)) != 1) {
      errno = EIO;
      success = false;
      break;
    }

    component->cipher_len = working_len;
    component->ciphertext = NULL;
    if (working_len > 0U) {
      component->ciphertext = (unsigned char *)GC_MALLOC(working_len);
      if (component->ciphertext == NULL) {
        errno = ENOMEM;
        success = false;
        break;
      }
    } else {
      component->ciphertext = (unsigned char *)GC_MALLOC(1U);
      if (component->ciphertext == NULL) {
        errno = ENOMEM;
        success = false;
        break;
      }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
      errno = ENOMEM;
      success = false;
      break;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(component->iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, layer->subkeys[idx], component->iv) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      errno = EIO;
      success = false;
      break;
    }

    int cipher_written = 0;
    if (working_len > 0U) {
      if (EVP_EncryptUpdate(ctx, component->ciphertext, &cipher_written, working, (int)working_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        errno = EIO;
        success = false;
        break;
      }
    } else {
      int tmp_len = 0;
      if (EVP_EncryptUpdate(ctx, component->ciphertext, &tmp_len, NULL, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        errno = EIO;
        success = false;
        break;
      }
      cipher_written = 0;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, component->ciphertext + cipher_written, &final_len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      errno = EIO;
      success = false;
      break;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SECURITY_LAYER_TAG_LEN, component->tag) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      errno = EIO;
      success = false;
      break;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (component->cipher_len > 0U && (size_t)(cipher_written + final_len) != component->cipher_len) {
      success = false;
      errno = EIO;
      break;
    }

    OPENSSL_cleanse(working, working_len);
    free(working);
    working = component->ciphertext;
    working_len = component->cipher_len;
    component->ciphertext = working;
  }

  if (!success) {
    OPENSSL_cleanse(working, working_len);
    free(working);
    for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
      if (layers[idx].ciphertext == working) {
        layers[idx].ciphertext = NULL;
      }
      security_layer_component_reset(&layers[idx]);
    }
    return false;
  }

  char *encoded_layers[SECURITY_LAYER_LEVELS];
  memset(encoded_layers, 0, sizeof(encoded_layers));
  size_t required_len = strlen(SECURITY_ONION_PREFIX);

  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    if (!security_layer_encode_component(&layers[SECURITY_LAYER_LEVELS - 1U - idx], &encoded_layers[idx])) {
      success = false;
      break;
    }
    required_len += strlen(encoded_layers[idx]);
    if (idx + 1U < SECURITY_LAYER_LEVELS) {
      required_len += 1U;
    }
  }

  if (success) {
    if (required_len >= out_len) {
      errno = ENOSPC;
      success = false;
    } else {
      size_t offset = 0U;
      memcpy(out + offset, SECURITY_ONION_PREFIX, strlen(SECURITY_ONION_PREFIX));
      offset += strlen(SECURITY_ONION_PREFIX);
      for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
        size_t len = strlen(encoded_layers[idx]);
        memcpy(out + offset, encoded_layers[idx], len);
        offset += len;
        if (idx + 1U < SECURITY_LAYER_LEVELS) {
          out[offset++] = '.';
        }
      }
      out[offset] = '\0';
    }
  }

  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    if (encoded_layers[idx] != NULL) {
      OPENSSL_cleanse(encoded_layers[idx], strlen(encoded_layers[idx]));
      free(encoded_layers[idx]);
    }
  }

  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    if (layers[idx].ciphertext == working) {
      layers[idx].ciphertext = NULL;
    }
    security_layer_component_reset(&layers[idx]);
  }

  OPENSSL_cleanse(working, working_len);
  free(working);

  return success;
}

static bool security_layer_decode_segment(const char *segment, unsigned char **buffer_out, size_t *length_out) {
  if (segment == NULL || buffer_out == NULL || length_out == NULL) {
    errno = EINVAL;
    return false;
  }

  size_t segment_len = strlen(segment);
  unsigned char *decoded = (unsigned char *)GC_MALLOC((segment_len * 3U) / 4U + 4U);
  if (decoded == NULL) {
    errno = ENOMEM;
    return false;
  }

  int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)segment, (int)segment_len);
  if (decoded_len < 0) {
    OPENSSL_cleanse(decoded, (size_t)((segment_len * 3U) / 4U + 4U));
    free(decoded);
    errno = EIO;
    return false;
  }

  size_t pad = 0U;
  if (segment_len >= 1U && segment[segment_len - 1U] == '=') {
    pad++;
  }
  if (segment_len >= 2U && segment[segment_len - 2U] == '=') {
    pad++;
  }
  size_t usable_len = (size_t)decoded_len - pad;

  if (usable_len < SECURITY_LAYER_IV_LEN + SECURITY_LAYER_TAG_LEN) {
    OPENSSL_cleanse(decoded, (size_t)((segment_len * 3U) / 4U + 4U));
    free(decoded);
    errno = EINVAL;
    return false;
  }

  *buffer_out = decoded;
  *length_out = usable_len;
  return true;
}

bool security_layer_decrypt_message(const security_layer_t *layer, const char *envelope,
                                    char *plaintext, size_t plaintext_len) {
  if (layer == NULL || !layer->ready || envelope == NULL || plaintext == NULL || plaintext_len == 0U) {
    errno = EINVAL;
    return false;
  }

  const size_t prefix_len = strlen(SECURITY_ONION_PREFIX);
  if (strncmp(envelope, SECURITY_ONION_PREFIX, prefix_len) != 0) {
    errno = EINVAL;
    return false;
  }

  const char *payload = envelope + prefix_len;
  if (payload[0] == '\0') {
    errno = EINVAL;
    return false;
  }

  char *copy = strdup(payload);
  if (copy == NULL) {
    errno = ENOMEM;
    return false;
  }

  char *segments[SECURITY_LAYER_LEVELS];
  size_t segment_count = 0U;
  char *saveptr = NULL;
  char *token = strtok_r(copy, ".", &saveptr);
  while (token != NULL && segment_count < SECURITY_LAYER_LEVELS) {
    segments[segment_count++] = token;
    token = strtok_r(NULL, ".", &saveptr);
  }

  if (segment_count != SECURITY_LAYER_LEVELS || token != NULL) {
    OPENSSL_cleanse(copy, strlen(copy));
    free(copy);
    errno = EINVAL;
    return false;
  }

  unsigned char *current_cipher = NULL;
  size_t current_len = 0U;
  bool success = true;

  for (size_t idx = 0U; idx < SECURITY_LAYER_LEVELS; ++idx) {
    size_t layer_index = SECURITY_LAYER_LEVELS - 1U - idx;
    unsigned char *decoded = NULL;
    size_t decoded_len = 0U;
    if (!security_layer_decode_segment(segments[idx], &decoded, &decoded_len)) {
      success = false;
      break;
    }

    const unsigned char *iv = decoded;
    const unsigned char *tag = decoded + SECURITY_LAYER_IV_LEN;
    const unsigned char *cipher_segment = decoded + SECURITY_LAYER_IV_LEN + SECURITY_LAYER_TAG_LEN;
    size_t cipher_len = decoded_len - SECURITY_LAYER_IV_LEN - SECURITY_LAYER_TAG_LEN;

    if (idx == 0U) {
      current_len = cipher_len;
      if (cipher_len > (size_t)INT_MAX) {
        OPENSSL_cleanse(decoded, decoded_len);
        free(decoded);
        errno = EOVERFLOW;
        success = false;
        break;
      }
      current_cipher = (unsigned char *)GC_MALLOC(cipher_len > 0U ? cipher_len : 1U);
      if (current_cipher == NULL) {
        OPENSSL_cleanse(decoded, decoded_len);
        free(decoded);
        errno = ENOMEM;
        success = false;
        break;
      }
      if (cipher_len > 0U) {
        memcpy(current_cipher, cipher_segment, cipher_len);
      }
    } else {
      if (cipher_len != current_len) {
        OPENSSL_cleanse(decoded, decoded_len);
        free(decoded);
        errno = EIO;
        success = false;
        break;
      }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
      OPENSSL_cleanse(decoded, decoded_len);
      free(decoded);
      errno = ENOMEM;
      success = false;
      break;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)SECURITY_LAYER_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, layer->subkeys[layer_index], iv) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      OPENSSL_cleanse(decoded, decoded_len);
      free(decoded);
      errno = EIO;
      success = false;
      break;
    }

    unsigned char *plaintext_layer = (unsigned char *)GC_MALLOC(current_len > 0U ? current_len : 1U);
    if (plaintext_layer == NULL) {
      EVP_CIPHER_CTX_free(ctx);
      OPENSSL_cleanse(decoded, decoded_len);
      free(decoded);
      errno = ENOMEM;
      success = false;
      break;
    }

    int out_len = 0;
    if (current_len > 0U) {
      if (EVP_DecryptUpdate(ctx, plaintext_layer, &out_len, current_cipher, (int)current_len) != 1) {
        OPENSSL_cleanse(plaintext_layer, current_len);
        free(plaintext_layer);
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(decoded, decoded_len);
        free(decoded);
        errno = EIO;
        success = false;
        break;
      }
    } else {
      int tmp_len = 0;
      if (EVP_DecryptUpdate(ctx, plaintext_layer, &tmp_len, NULL, 0) != 1) {
        OPENSSL_cleanse(plaintext_layer, 1U);
        free(plaintext_layer);
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(decoded, decoded_len);
        free(decoded);
        errno = EIO;
        success = false;
        break;
      }
      out_len = 0;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SECURITY_LAYER_TAG_LEN, (void *)tag) != 1) {
      OPENSSL_cleanse(plaintext_layer, current_len > 0U ? current_len : 1U);
      free(plaintext_layer);
      EVP_CIPHER_CTX_free(ctx);
      OPENSSL_cleanse(decoded, decoded_len);
      free(decoded);
      errno = EIO;
      success = false;
      break;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext_layer + out_len, &final_len) != 1) {
      OPENSSL_cleanse(plaintext_layer, current_len > 0U ? current_len : 1U);
      free(plaintext_layer);
      EVP_CIPHER_CTX_free(ctx);
      OPENSSL_cleanse(decoded, decoded_len);
      free(decoded);
      errno = EIO;
      success = false;
      break;
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(decoded, decoded_len);
    free(decoded);

    size_t plain_len = (size_t)out_len + (size_t)final_len;
    if (plain_len != current_len) {
      OPENSSL_cleanse(plaintext_layer, current_len > 0U ? current_len : 1U);
      free(plaintext_layer);
      errno = EIO;
      success = false;
      break;
    }

    OPENSSL_cleanse(current_cipher, current_len);
    free(current_cipher);
    current_cipher = plaintext_layer;
  }

  OPENSSL_cleanse(copy, strlen(copy));
  free(copy);

  if (!success) {
    OPENSSL_cleanse(current_cipher, current_len);
    free(current_cipher);
    return false;
  }

  if (current_len >= plaintext_len) {
    OPENSSL_cleanse(current_cipher, current_len);
    free(current_cipher);
    errno = ENOSPC;
    return false;
  }

  if (current_len > 0U) {
    memcpy(plaintext, current_cipher, current_len);
  }
  plaintext[current_len] = '\0';

  OPENSSL_cleanse(current_cipher, current_len);
  free(current_cipher);
  return true;
}
