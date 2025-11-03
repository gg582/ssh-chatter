#ifndef BUBBLE_H
#define BUBBLE_H

#include "host.h"

void session_draw_bubble_top(session_ctx_t *ctx, bool is_user, bool is_continuous);
void session_send_bubble_message(session_ctx_t *ctx, bool is_user, const char *message);
void session_draw_bubble_middle(session_ctx_t *ctx, bool is_user, const char *line);
void session_draw_bubble_bottom(session_ctx_t *ctx, bool is_user, bool is_continuous);

#endif
