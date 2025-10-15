#ifndef SSH_CHATTER_BOT_H
#define SSH_CHATTER_BOT_H

#include <stdbool.h>
#include <time.h>

struct host;
struct client_manager;

typedef struct chat_bot chat_bot_t;

chat_bot_t *chat_bot_create(struct host *host, struct client_manager *manager);
bool chat_bot_start(chat_bot_t *bot);
void chat_bot_shutdown(chat_bot_t *bot);
void chat_bot_destroy(chat_bot_t *bot);
bool chat_bot_is_enabled(const chat_bot_t *bot);
void chat_bot_set_captcha_hint(chat_bot_t *bot, const char *question, const char *answer);
bool chat_bot_snapshot_captcha_hint(chat_bot_t *bot, char *question, size_t question_length, char *answer,
                                    size_t answer_length, struct timespec *timestamp);

#endif
