#ifndef SSH_CHATTER_BOT_H
#define SSH_CHATTER_BOT_H

#include <stdbool.h>

struct host;
struct client_manager;

typedef struct chat_bot chat_bot_t;

chat_bot_t *chat_bot_create(struct host *host, struct client_manager *manager);
bool chat_bot_start(chat_bot_t *bot);
void chat_bot_shutdown(chat_bot_t *bot);
void chat_bot_destroy(chat_bot_t *bot);
bool chat_bot_is_enabled(const chat_bot_t *bot);

#endif
