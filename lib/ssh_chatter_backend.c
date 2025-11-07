#include "headers/ssh_chatter_backend.h"

#include "headers/translation_helpers.h"
#include "headers/translator.h"

#include <string.h>

void ssh_chatter_backend_init(void)
{
    translator_global_init();
}

static void backend_copy_string(char *dest, size_t dest_len, const char *source)
{
    if (dest == NULL || dest_len == 0U) {
        return;
    }

    if (source == NULL) {
        dest[0] = '\0';
        return;
    }

    size_t copy_len = strlen(source);
    if (copy_len >= dest_len) {
        copy_len = dest_len - 1U;
    }

    memcpy(dest, source, copy_len);
    dest[copy_len] = '\0';
}

bool ssh_chatter_backend_translate_line(const char *message,
                                        const char *target_language,
                                        char *translated, size_t translated_len,
                                        char *detected_language,
                                        size_t detected_len)
{
    if (translated != NULL && translated_len > 0U) {
        translated[0] = '\0';
    }
    if (detected_language != NULL && detected_len > 0U) {
        detected_language[0] = '\0';
    }

    if (message == NULL || target_language == NULL || translated == NULL ||
        translated_len == 0U) {
        return false;
    }

    char stripped[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    if (translation_strip_no_translate_prefix(message, stripped,
                                              sizeof(stripped))) {
        backend_copy_string(translated, translated_len, stripped);
        if (detected_language != NULL && detected_len > 0U) {
            detected_language[0] = '\0';
        }
        return true;
    }

    ssh_chatter_backend_init();

    translation_placeholder_t
        placeholders[SSH_CHATTER_MAX_TRANSLATION_PLACEHOLDERS];
    size_t placeholder_count = 0U;
    char sanitized[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    if (!translation_prepare_text(message, sanitized, sizeof(sanitized),
                                  placeholders, &placeholder_count)) {
        return false;
    }

    if (sanitized[0] == '\0') {
        return true;
    }

    char detected_buffer[SSH_CHATTER_LANG_NAME_LEN];
    char translated_body[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    if (!translator_translate(sanitized, target_language, translated_body,
                              sizeof(translated_body), detected_buffer,
                              sizeof(detected_buffer))) {
        return false;
    }

    char restored[SSH_CHATTER_TRANSLATION_WORKING_LEN];
    if (!translation_restore_text(translated_body, restored, sizeof(restored),
                                  placeholders, placeholder_count)) {
        return false;
    }

    backend_copy_string(translated, translated_len, restored);
    if (detected_language != NULL) {
        backend_copy_string(detected_language, detected_len, detected_buffer);
    }

    return true;
}
