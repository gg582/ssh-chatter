#ifndef BUBBLE_H
#define BUBBLE_H

#include "host.h"

#define MAX_BUBBLE_WIDTH 60 // Maximum display width for chat bubble lines

void session_send_bubble_message(session_ctx_t *ctx, bool is_user, const char *message, bool auto_wrap);

#endif
