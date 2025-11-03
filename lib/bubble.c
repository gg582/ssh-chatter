#include "../headers/bubble.h"
#include "../headers/host.h"
#include <string.h>
#include <wchar.h>
#include <stdlib.h> // For mbstowcs, strdup, free
#include <locale.h> // For setlocale
#include <wctype.h> // For iswspace, wcwidth

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

// Helper function to wrap text into multiple lines based on max_width
// Returns the number of lines, and populates the 'lines' array with pointers to dynamically allocated strings.
// The caller is responsible for freeing these strings.
static int wrap_text_to_lines(const char *text, int max_width, char *lines[], int max_lines) {
    int line_count = 0;
    const char *current_ptr = text;

    // Set locale for wide character functions
    setlocale(LC_ALL, "");

    while (*current_ptr != '\0' && line_count < max_lines) {
        const char *line_start = current_ptr;
        const char *best_break_pos = NULL; // Position for a newline or space break
        int current_line_display_width = 0;
        const char *temp_ptr = current_ptr;
        const char *last_space_pos = NULL; // Last space encountered before max_width
        
        // Find the end of the current logical line (either a newline or max_width)
        while (*temp_ptr != '\0') {
            if (*temp_ptr == '\n') {
                best_break_pos = temp_ptr;
                break; // Explicit newline, break here
            }

            // Handle ANSI escape codes
            if (*temp_ptr == '\033') {
                while (*temp_ptr != '\0' && *temp_ptr != 'm') {
                    temp_ptr++;
                }
                if (*temp_ptr == 'm') {
                    temp_ptr++;
                }
                continue; // Continue to next character after ANSI sequence
            }

            // Calculate character width
            wchar_t wc;
            mbstate_t state;
            memset(&state, 0, sizeof(state));
            size_t len = mbrtowc(&wc, temp_ptr, strlen(temp_ptr), &state);

            if (len == (size_t)-1 || len == (size_t)-2) { // Invalid or incomplete multibyte sequence
                current_line_display_width += 1;
                temp_ptr++;
            } else {
                int char_width = wcwidth(wc);
                if (char_width > 0) {
                    current_line_display_width += char_width;
                }
                if (iswspace(wc)) { // Found a space, potential break point
                    last_space_pos = temp_ptr;
                }
                temp_ptr += len;
            }

            if (current_line_display_width > max_width) {
                break; // Exceeded max width, need to break
            }
        }

        // Determine the actual break position
        size_t segment_len;
        if (best_break_pos != NULL) { // Explicit newline found
            segment_len = (size_t)(best_break_pos - line_start);
            current_ptr = best_break_pos + 1; // Start next line after newline
        } else if (current_line_display_width > max_width && last_space_pos != NULL && last_space_pos > line_start) {
            // Break at the last space before max_width
            segment_len = (size_t)(last_space_pos - line_start);
            current_ptr = last_space_pos + 1; // Start next line after space
        } else {
            // No suitable space break, or word is longer than max_width, or end of string
            // Break at temp_ptr (which is either end of string or where max_width was exceeded)
            segment_len = (size_t)(temp_ptr - line_start);
            current_ptr = temp_ptr;
        }

        // Allocate and copy the line segment
        lines[line_count] = (char *)malloc(segment_len + 1);
        if (!lines[line_count]) {
            // Handle allocation failure: free previously allocated lines and return
            for (int i = 0; i < line_count; ++i) {
                free(lines[i]);
            }
            return 0;
        }
        strncpy(lines[line_count], line_start, segment_len);
        lines[line_count][segment_len] = '\0';
        line_count++;
    }
    return line_count;
}

void session_send_bubble_message(session_ctx_t *ctx, bool is_user, const char *message) {
    if (ctx == NULL || message == NULL) {
        return;
    }

    char *wrapped_lines[SSH_CHATTER_MESSAGE_LIMIT / 2]; // Array to hold wrapped lines
    int line_count = wrap_text_to_lines(message, MAX_BUBBLE_WIDTH, wrapped_lines, sizeof(wrapped_lines) / sizeof(wrapped_lines[0]));
    int max_width = 0;

    for (int i = 0; i < line_count; ++i) {
        int current_width = get_display_width(wrapped_lines[i]);
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
        int current_width = get_display_width(wrapped_lines[i]);
        snprintf(middle_line, sizeof(middle_line), "%s%s│ %s%s%s", bg, fg, ANSI_RESET, wrapped_lines[i], bg);
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

    // Free the dynamically allocated wrapped lines
    for (int i = 0; i < line_count; ++i) {
        free(wrapped_lines[i]);
    }
}
