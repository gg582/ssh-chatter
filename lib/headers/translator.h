#ifndef SSH_CHATTER_TRANSLATOR_H
#define SSH_CHATTER_TRANSLATOR_H

#include <stdbool.h>
#include <stddef.h>

void translator_global_init(void);

bool translator_translate(const char *text, const char *target_language,
                          char *translation, size_t translation_len,
                          char *detected_language, size_t detected_len);

#endif
