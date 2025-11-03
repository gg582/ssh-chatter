#include "../headers/bubble.h"
#include "../headers/host.h"
#include <string.h>
#include <wchar.h>
#include <stdlib.h> // For mbstowcs

// Helper function to calculate the display width of a string, ignoring ANSI escape codes
static int get_display_width(const char *text) {
    int width = 0;
    const char *ptr = text;
    mbstate_t state;
    memset(&state, 0, sizeof(state));

    while (*ptr != '\0') {
        if (*ptr == '\033') { // ANSI escape sequence
            while (*ptr != '\0' && *ptr != 'm') {
                ptr++;
            }
            if (*ptr == 'm') {
                ptr++;
            }
        } else {
            wchar_t wc;
            size_t len = mbrtowc(&wc, ptr, strlen(ptr), &state);
            if (len == (size_t)-1 || len == (size_t)-2) { // Invalid or incomplete multibyte sequence
                width += 1; // Treat as single-width character
                ptr++;
            } else {
                int char_width = wcwidth(wc);
                if (char_width > 0) {
                    width += char_width;
                }
                ptr += len;
            }
        }
    }
    return width;
}

void session_send_bubble_message(session_ctx_t *ctx, bool is_user, const char *message) {
    if (ctx == NULL || message == NULL) {
        return;
    }

    char message_copy[SSH_CHATTER_MESSAGE_LIMIT];
    strncpy(message_copy, message, sizeof(message_copy) - 1);
    message_copy[sizeof(message_copy) - 1] = '\0';

    char *lines[SSH_CHATTER_MESSAGE_LIMIT / 2]; // Assuming average line length of 2
    int line_count = 0;
    int max_width = 0;

    char *rest = message_copy;
    char *line_token;
    while ((line_token = strtok_r(rest, "\n", &rest)) != NULL && line_count < (int)(sizeof(lines) / sizeof(lines[0]))) {
        lines[line_count++] = line_token;
        int current_width = get_display_width(line_token);
        if (current_width > max_width) {
            max_width = current_width;
        }
    }

    if (line_count == 0) {
        return;
    }

    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    // Top border
    char top_border[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(top_border, sizeof(top_border), "%s%s╭", bg, fg);
    for (int i = 0; i < max_width + 2; ++i) {
        strncat(top_border, "─", sizeof(top_border) - strlen(top_border) - 1);
    }
    strncat(top_border, "╮", sizeof(top_border) - strlen(top_border) - 1);
    strncat(top_border, ANSI_RESET, sizeof(top_border) - strlen(top_border) - 1);
    session_send_raw_text(ctx, top_border);

    // Middle lines
    for (int i = 0; i < line_count; ++i) {
        char middle_line[SSH_CHATTER_MESSAGE_LIMIT];
        int current_width = get_display_width(lines[i]);
        snprintf(middle_line, sizeof(middle_line), "%s%s│ %s%s%s", bg, fg, ANSI_RESET, lines[i], bg);
        for (int j = 0; j < max_width - current_width; ++j) {
            strncat(middle_line, " ", sizeof(middle_line) - strlen(middle_line) - 1);
        }
        strncat(middle_line, " │", sizeof(middle_line) - strlen(middle_line) - 1);
        strncat(middle_line, ANSI_RESET, sizeof(middle_line) - strlen(middle_line) - 1);
        session_send_raw_text(ctx, middle_line);
    }

    // Bottom border
    char bottom_border[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(bottom_border, sizeof(bottom_border), "%s%s╰", bg, fg);
    for (int i = 0; i < max_width + 2; ++i) {
        strncat(bottom_border, "─", sizeof(bottom_border) - strlen(bottom_border) - 1);
    }
    strncat(bottom_border, "╯", sizeof(bottom_border) - strlen(bottom_border) - 1);
    strncat(bottom_border, ANSI_RESET, sizeof(bottom_border) - strlen(bottom_border) - 1);
    session_send_raw_text(ctx, bottom_border);
}

void session_draw_bubble_top(session_ctx_t *ctx, bool is_user, bool /*is_continuous*/) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    // This function is likely deprecated or used for single-line bubbles.
    // For multi-line bubbles, session_send_bubble_message should be used.
    // For now, we'll make it draw a simple top border.
    snprintf(line, sizeof(line), "%s%s╭───╮%s", bg, fg, ANSI_RESET);
    session_send_raw_text(ctx, line);
}

void session_draw_bubble_middle(session_ctx_t *ctx, bool is_user, const char *text) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    // This function is likely deprecated or used for single-line bubbles.
    // For multi-line bubbles, session_send_bubble_message should be used.
    // For now, we'll make it draw a simple middle line with borders.
    snprintf(line, sizeof(line), "%s%s│ %s%s%s │%s", bg, fg, ANSI_RESET, text, bg, ANSI_RESET);
    session_send_raw_text(ctx, line);
}

void session_draw_bubble_bottom(session_ctx_t *ctx, bool is_user, bool /*is_continuous*/) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *bg = is_user ? ctx->user_highlight_code : ctx->system_bg_code;
    const char *fg = is_user ? ctx->user_color_code : ctx->system_fg_code;

    // This function is likely deprecated or used for single-line bubbles.
    // For multi-line bubbles, session_send_bubble_message should be used.
    // For now, we'll make it draw a simple bottom border.
    snprintf(line, sizeof(line), "%s%s╰───╯%s", bg, fg, ANSI_RESET);
    session_send_raw_text(ctx, line);
}
