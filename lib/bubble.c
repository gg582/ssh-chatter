#include "../headers/bubble.h"
#include "../headers/host.h"

void session_draw_bubble_top(session_ctx_t *ctx, bool is_user, bool /*is_continuous*/) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    snprintf(line, sizeof(line), "%s%s╭─%s%s", bg, fg, ANSI_RESET, bg);
    session_send_raw_text(ctx, line);
}

void session_draw_bubble_middle(session_ctx_t *ctx, bool is_user, const char *text) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    snprintf(line, sizeof(line), "%s%s│ %s%s%s", bg, fg, ANSI_RESET, text, bg);
    session_send_raw_text(ctx, line);
}

void session_draw_bubble_bottom(session_ctx_t *ctx, bool is_user, bool /*is_continuous*/) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    snprintf(line, sizeof(line), "%s%s╰─%s", bg, fg, ANSI_RESET);
    session_send_raw_text(ctx, line);
}
