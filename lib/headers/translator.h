#ifndef SSH_CHATTER_TRANSLATOR_H
#define SSH_CHATTER_TRANSLATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

void translator_global_init(void);

bool translator_translate(const char *text, const char *target_language,
                          char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len);

const char *translator_last_error(void);

bool translator_last_error_was_quota(void);

void translator_set_gemini_enabled(bool enabled);
bool translator_is_gemini_enabled(void);
bool translator_is_gemini_manually_disabled(void);
bool translator_gemini_backoff_remaining(struct timespec *remaining);
bool translator_is_ollama_only(void);

#endif
