// Session output, history delivery, and client-facing helpers.

static void session_send_plain_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || message == NULL) {
    return;
  }

  static const char kCaptionPrefix[] = "    \342\206\263";
  if (strncmp(message, kCaptionPrefix, sizeof(kCaptionPrefix) - 1U) == 0) {
    session_send_caption_line(ctx, message);
    return;
  }

  session_send_line(ctx, message);
}

static void session_send_reply_tree(session_ctx_t *ctx, uint64_t parent_message_id, uint64_t parent_reply_id, size_t depth) {
  if (ctx == NULL || ctx->owner == NULL || parent_message_id == 0U) {
    return;
  }

  if (depth > 32U) {
    return;
  }

  host_t *host = ctx->owner;

  size_t match_count = 0U;
  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < host->reply_count; ++idx) {
    const chat_reply_entry_t *candidate = &host->replies[idx];
    if (!candidate->in_use) {
      continue;
    }
    if (candidate->parent_message_id == parent_message_id && candidate->parent_reply_id == parent_reply_id) {
      ++match_count;
    }
  }

  if (match_count == 0U) {
    pthread_mutex_unlock(&host->lock);
    return;
  }

  chat_reply_entry_t *snapshot = GC_CALLOC(match_count, sizeof(*snapshot));
  if (snapshot == NULL) {
    pthread_mutex_unlock(&host->lock);
    return;
  }

  size_t copy_idx = 0U;
  for (size_t idx = 0U; idx < host->reply_count && copy_idx < match_count; ++idx) {
    const chat_reply_entry_t *candidate = &host->replies[idx];
    if (!candidate->in_use) {
      continue;
    }
    if (candidate->parent_message_id == parent_message_id && candidate->parent_reply_id == parent_reply_id) {
      snapshot[copy_idx++] = *candidate;
    }
  }
  pthread_mutex_unlock(&host->lock);

  for (size_t idx = 0U; idx < copy_idx; ++idx) {
    const chat_reply_entry_t *reply = &snapshot[idx];

    size_t indent_len = depth * 4U;
    char indent[128];
    if (indent_len >= sizeof(indent)) {
      indent_len = sizeof(indent) - 1U;
    }
    memset(indent, ' ', indent_len);
    indent[indent_len] = '\0';

    const char *target_prefix = (reply->parent_reply_id == 0U) ? "#" : "r#";
    uint64_t target_id = (reply->parent_reply_id == 0U) ? reply->parent_message_id : reply->parent_reply_id;

    char line[SSH_CHATTER_MESSAGE_LIMIT + 160];
    snprintf(line, sizeof(line), "%s↳ [r#%" PRIu64 " → %s%" PRIu64 "] %s: %s", indent, reply->reply_id, target_prefix,
             target_id, reply->username, reply->message);
    session_send_plain_line(ctx, line);

    session_send_reply_tree(ctx, parent_message_id, reply->reply_id, depth + 1U);
  }

}

static bool host_lookup_member_ip(host_t *host, const char *username, char *ip, size_t length) {
  if (host == NULL || username == NULL || ip == NULL || length == 0U) {
    return false;
  }

  session_ctx_t *member = chat_room_find_user(&host->room, username);
  if (member == NULL || member->client_ip[0] == '\0') {
    return false;
  }

  snprintf(ip, length, "%s", member->client_ip);
  return true;
}

static void session_telnet_capture_startup_metadata(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->telnet_fd < 0) {
    return;
  }

  while (!ctx->telnet_eof) {
    struct pollfd pfd = {
        .fd = ctx->telnet_fd,
        .events = POLLIN,
        .revents = 0,
    };

    int poll_result = poll(&pfd, 1, 0);
    if (poll_result <= 0 || (pfd.revents & POLLIN) == 0) {
      break;
    }

    unsigned char byte = 0U;
    int read_result = session_telnet_read_byte(ctx, &byte, 0);
    if (read_result == SSH_AGAIN) {
      break;
    }
    if (read_result <= 0) {
      break;
    }

    if (byte != 0U) {
      if (!ctx->telnet_pending_valid) {
        ctx->telnet_pending_char = (int)byte;
        ctx->telnet_pending_valid = true;
      }
      break;
    }
  }
}

typedef struct provider_prefix {
    const char *prefix;
    const char *label;
  } provider_prefix_t;

  static const provider_prefix_t kProviderPrefixes[] = {
      {"39.7.", "Korean ISP"},       {"58.120.", "Korean ISP"}, {"59.0.", "Korean ISP"},
      {"61.32.", "Korean ISP"},      {"211.36.", "Korean ISP"}, {"218.144.", "Korean ISP"},
      {"73.", "US ISP"},             {"96.", "US ISP"},         {"107.", "US ISP"},
      {"174.", "US ISP"},            {"2600:", "US ISP"},       {"2604:", "US ISP"},
      {"2605:", "US ISP"},           {"2607:", "US ISP"},       {"2609:", "US ISP"},
      {"1.0.", "Japanese ISP"},       {"106.130.", "Japanese ISP"}, {"118.103.", "Japanese ISP"},
      {"126.", "Japanese ISP"},       {"133.", "Japanese ISP"},     {"153.", "Japanese ISP"},
      {"210.", "Japanese ISP"},       {"219.", "Japanese ISP"},     {"220.", "Japanese ISP"},
      {"2400:", "Japanese ISP"},     {"2404:", "Japanese ISP"},   {"2406:", "Japanese ISP"},
      {"2408:", "Japanese ISP"},
      {"24.114.", "Canadian ISP"},   {"142.", "Canadian ISP"}, {"2603:", "Canadian ISP"},
      {"185.", "EU ISP"},            {"195.", "EU ISP"},       {"2a00:", "EU ISP"},
      {"2a02:", "EU ISP"},           {"2a03:", "EU ISP"},      {"2a09:", "EU ISP"},
      {"5.18.", "Russian ISP"},      {"37.", "Russian ISP"},   {"91.", "Russian ISP"},
      {"36.", "Chinese ISP"},        {"42.", "Chinese ISP"},   {"139.", "Chinese ISP"},
      {"2408:", "Chinese ISP"},      {"2409:", "Chinese ISP"}, {"49.", "Indian ISP"},
      {"103.", "Indian ISP"},        {"106.", "Indian ISP"},   {"2405:", "Indian ISP"},
      {"2406:", "Indian ISP"},       {"100.64.", "Carrier-grade NAT"}};

static bool session_detect_provider_ip(const char *ip, char *label, size_t length) {
  if (label != NULL && length > 0U) {
    label[0] = '\0';
  }

  if (ip == NULL || ip[0] == '\0' || label == NULL || length == 0U) {
    return false;
  }

  for (size_t idx = 0U; idx < sizeof(kProviderPrefixes) / sizeof(kProviderPrefixes[0]); ++idx) {
    const provider_prefix_t *entry = &kProviderPrefixes[idx];
    size_t prefix_len = strlen(entry->prefix);
    if (strncasecmp(ip, entry->prefix, prefix_len) == 0) {
      snprintf(label, length, "%s", entry->label);
      return true;
    }
  }

  return false;
}

  static const struct {
    const char *label;
    session_ui_language_t language;
  } kProviderLanguageMapping[] = {
      {"Korean ISP", SESSION_UI_LANGUAGE_KO},
      {"US ISP", SESSION_UI_LANGUAGE_EN},
      {"Canadian ISP", SESSION_UI_LANGUAGE_EN},
      {"EU ISP", SESSION_UI_LANGUAGE_EN},
      {"Russian ISP", SESSION_UI_LANGUAGE_RU},
      {"Chinese ISP", SESSION_UI_LANGUAGE_ZH},
      {"Indian ISP", SESSION_UI_LANGUAGE_EN},
      {"Japanese ISP", SESSION_UI_LANGUAGE_JP},
  };


static session_ui_language_t session_client_geo_language(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return SESSION_UI_LANGUAGE_COUNT;
  }

  char label[64];
  if (!session_detect_provider_ip(ctx->client_ip, label, sizeof(label))) {
    return SESSION_UI_LANGUAGE_COUNT;
  }

  for (size_t idx = 0U; idx < sizeof(kProviderLanguageMapping) / sizeof(kProviderLanguageMapping[0]); ++idx) {
    if (strcasecmp(label, kProviderLanguageMapping[idx].label) == 0) {
      return kProviderLanguageMapping[idx].language;
    }
  }

  return SESSION_UI_LANGUAGE_COUNT;
}

static bool session_blocklist_add(session_ctx_t *ctx, const char *ip, const char *username, bool ip_wide,
                                  bool *already_present) {
  if (ctx == NULL) {
    if (already_present != NULL) {
      *already_present = false;
    }
    return false;
  }

  if (already_present != NULL) {
    *already_present = false;
  }

  char normalized_ip[SSH_CHATTER_IP_LEN] = {0};
  char normalized_user[SSH_CHATTER_USERNAME_LEN] = {0};

  if (ip != NULL && ip[0] != '\0') {
    snprintf(normalized_ip, sizeof(normalized_ip), "%s", ip);
  }

  if (username != NULL && username[0] != '\0') {
    snprintf(normalized_user, sizeof(normalized_user), "%s", username);
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    if (ip_wide) {
      if (normalized_ip[0] != '\0' && strncmp(entry->ip, normalized_ip, SSH_CHATTER_IP_LEN) == 0) {
        if (already_present != NULL) {
          *already_present = true;
        }
        return false;
      }
    } else {
      if (normalized_user[0] != '\0' && strncmp(entry->username, normalized_user, SSH_CHATTER_USERNAME_LEN) == 0 &&
          !entry->ip_wide) {
        if (already_present != NULL) {
          *already_present = true;
        }
        return false;
      }
    }
  }

  size_t free_index = SSH_CHATTER_MAX_BLOCKED;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    if (!ctx->block_entries[idx].in_use) {
      free_index = idx;
      break;
    }
  }

  if (free_index >= SSH_CHATTER_MAX_BLOCKED) {
    return false;
  }

  session_block_entry_t *slot = &ctx->block_entries[free_index];
  memset(slot, 0, sizeof(*slot));
  slot->in_use = true;
  slot->ip_wide = ip_wide;
  if (normalized_ip[0] != '\0') {
    snprintf(slot->ip, sizeof(slot->ip), "%s", normalized_ip);
  }
  if (normalized_user[0] != '\0') {
    snprintf(slot->username, sizeof(slot->username), "%s", normalized_user);
  }

  if (ctx->block_entry_count < SSH_CHATTER_MAX_BLOCKED) {
    ctx->block_entry_count += 1U;
  }

  return true;
}

static bool session_blocklist_remove(session_ctx_t *ctx, const char *token) {
  if (ctx == NULL || token == NULL || token[0] == '\0') {
    return false;
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    if ((entry->ip[0] != '\0' && strncmp(entry->ip, token, SSH_CHATTER_IP_LEN) == 0) ||
        (entry->username[0] != '\0' && strncmp(entry->username, token, SSH_CHATTER_USERNAME_LEN) == 0)) {
      memset(entry, 0, sizeof(*entry));
      if (ctx->block_entry_count > 0U) {
        ctx->block_entry_count -= 1U;
      }
      return true;
    }
  }

  return false;
}

static void session_blocklist_show(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->block_entry_count == 0U) {
    session_send_system_line(ctx, "No blocked users or IPs.");
    return;
  }

  session_send_system_line(ctx, "Blocked targets:");
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    const session_block_entry_t *entry = &ctx->block_entries[idx];
    if (!entry->in_use) {
      continue;
    }

    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (entry->ip_wide && entry->ip[0] != '\0') {
      if (entry->username[0] != '\0') {
        snprintf(line, sizeof(line), "- %s (all users from this IP, originally [%s])", entry->ip, entry->username);
      } else {
        snprintf(line, sizeof(line), "- %s (all users from this IP)", entry->ip);
      }
    } else if (entry->username[0] != '\0') {
      if (entry->ip[0] != '\0') {
        snprintf(line, sizeof(line), "- [%s] (only this user, IP %s)", entry->username, entry->ip);
      } else {
        snprintf(line, sizeof(line), "- [%s]", entry->username);
      }
    } else {
      snprintf(line, sizeof(line), "- entry #%zu", idx + 1U);
    }
    session_send_system_line(ctx, line);
  }
}

static bool session_bbs_should_defer_breaking(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || message == NULL) {
    return false;
  }

  if (!ctx->bbs_post_pending || ctx->bbs_rendering_editor) {
    return false;
  }

  if (strstr(message, SSH_CHATTER_RSS_BREAKING_PREFIX) != NULL) {
    return true;
  }

  if (strcasestr(message, "breaking news") != NULL || strcasestr(message, "breaking:") != NULL ||
      strcasestr(message, "urgent") != NULL || strcasestr(message, "alert") != NULL) {
    return true;
  }

  if (strstr(message, "속보") != NULL || strstr(message, "速報") != NULL) {
    return true;
  }

  return false;
}

static void session_bbs_buffer_breaking_notice(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || message == NULL) {
    return;
  }

  size_t limit = SSH_CHATTER_BBS_BREAKING_MAX;
  if (limit == 0U) {
    return;
  }

  if (ctx->bbs_breaking_count < limit) {
    snprintf(ctx->bbs_breaking_messages[ctx->bbs_breaking_count],
             sizeof(ctx->bbs_breaking_messages[ctx->bbs_breaking_count]), "%s", message);
    ctx->bbs_breaking_count += 1U;
  } else {
    for (size_t idx = 1U; idx < limit; ++idx) {
      snprintf(ctx->bbs_breaking_messages[idx - 1U], sizeof(ctx->bbs_breaking_messages[idx - 1U]), "%s",
               ctx->bbs_breaking_messages[idx]);
    }
    snprintf(ctx->bbs_breaking_messages[limit - 1U], sizeof(ctx->bbs_breaking_messages[limit - 1U]), "%s", message);
  }

  session_bbs_render_editor(ctx, NULL);
}

static bool session_should_hide_entry(session_ctx_t *ctx, const chat_history_entry_t *entry) {
  if (ctx == NULL || entry == NULL) {
    return false;
  }

  if (!entry->is_user_message) {
    return false;
  }

  if (ctx->block_entry_count == 0U) {
    return false;
  }

  if (strncmp(entry->username, ctx->user.name, SSH_CHATTER_USERNAME_LEN) == 0) {
    return false;
  }

  char entry_ip[SSH_CHATTER_IP_LEN] = {0};
  if (ctx->owner != NULL) {
    host_lookup_member_ip(ctx->owner, entry->username, entry_ip, sizeof(entry_ip));
  }

  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
    const session_block_entry_t *block = &ctx->block_entries[idx];
    if (!block->in_use) {
      continue;
    }

    bool ip_match = false;
    bool user_match = false;

    if (block->ip[0] != '\0' && entry_ip[0] != '\0' &&
        strncmp(block->ip, entry_ip, SSH_CHATTER_IP_LEN) == 0) {
      ip_match = true;
    }

    if (block->username[0] != '\0' &&
        strncmp(block->username, entry->username, SSH_CHATTER_USERNAME_LEN) == 0) {
      user_match = true;
    }

    if (block->ip_wide) {
      if (ip_match) {
        return true;
      }
      if (!ip_match && entry_ip[0] == '\0' && user_match) {
        return true;
      }
    } else {
      if (user_match) {
        return true;
      }
    }
  }

  return false;
}

// this displays a message to a chatting room.
static void session_send_system_line(session_ctx_t *ctx, const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || message == NULL) {
    return;
  }

  if (session_bbs_should_defer_breaking(ctx, message)) {
    session_bbs_buffer_breaking_notice(ctx, message);
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  if (message[0] == '\0') {
    char formatted_empty[SSH_CHATTER_MESSAGE_LIMIT];
    size_t offset = 0U;
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, bg);
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, fg);
    offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, bold);
    session_append_fragment(formatted_empty, sizeof(formatted_empty), offset, ANSI_RESET);
    session_send_line(ctx, formatted_empty);
    return;
  }

  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 !ctx->in_bbs_mode && !ctx->in_rss_mode;
  const bool multiline_message = strchr(message, '\n') != NULL;
  bool translation_block = false;
  bool previous_suppress = ctx->translation_suppress_output;
  if (translation_ready && multiline_message && !ctx->translation_suppress_output) {
    translation_block = true;
    ctx->translation_suppress_output = true;
  }

  const char *cursor = message;
  for (;;) {
    const char *newline = strchr(cursor, '\n');
    size_t segment_length = newline != NULL ? (size_t)(newline - cursor) : strlen(cursor);
    if (segment_length >= SSH_CHATTER_MESSAGE_LIMIT) {
      segment_length = SSH_CHATTER_MESSAGE_LIMIT - 1U;
    }

    char segment[SSH_CHATTER_MESSAGE_LIMIT];
    memcpy(segment, cursor, segment_length);
    segment[segment_length] = '\0';

    char formatted[SSH_CHATTER_MESSAGE_LIMIT];
    size_t offset = 0U;
    offset = session_append_fragment(formatted, sizeof(formatted), offset, bg);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, fg);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, bold);
    offset = session_append_fragment(formatted, sizeof(formatted), offset, segment);
    session_append_fragment(formatted, sizeof(formatted), offset, ANSI_RESET);
    session_send_line(ctx, formatted);

    if (newline == NULL) {
      break;
    }

    cursor = newline + 1;
    if (*cursor == '\r') {
      ++cursor;
    }

    if (*cursor == '\0') {
      char formatted_empty[SSH_CHATTER_MESSAGE_LIMIT];
      size_t empty_offset = 0U;
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, bg);
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, fg);
      empty_offset = session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, bold);
      session_append_fragment(formatted_empty, sizeof(formatted_empty), empty_offset, ANSI_RESET);
      session_send_line(ctx, formatted_empty);
      break;
    }
  }

  if (translation_block) {
    ctx->translation_suppress_output = previous_suppress;
    if (!ctx->translation_suppress_output) {
      session_translation_queue_block(ctx, message);
      session_translation_flush_ready(ctx);
    }
    return;
  }

  ctx->translation_suppress_output = previous_suppress;
}

static void session_send_raw_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || !session_transport_active(ctx) || text == NULL) {
    return;
  }

  const char *cursor = text;
  while (*cursor != '\0') {
    const char *newline = strchr(cursor, '\n');
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    if (newline == NULL) {
      snprintf(line, sizeof(line), "%s", cursor);
      session_send_plain_line(ctx, line);
      break;
    }

    size_t length = (size_t)(newline - cursor);
    if (length >= sizeof(line)) {
      length = sizeof(line) - 1U;
    }
    memcpy(line, cursor, length);
    line[length] = '\0';
    session_send_plain_line(ctx, line);

    cursor = newline + 1;
    if (*cursor == '\r') {
      ++cursor;
    }
    if (*cursor == '\0') {
      session_send_plain_line(ctx, "");
    }
  }
}

static void session_send_raw_text_bulk(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL || text == NULL) {
    return;
  }

  const bool scope_allows_translation =
      (!translator_should_limit_to_chat_bbs() || ctx->translation_manual_scope_override);
  const bool translation_ready = scope_allows_translation && ctx->translation_enabled &&
                                 ctx->output_translation_enabled && ctx->output_translation_language[0] != '\0' &&
                                 !ctx->in_bbs_mode && !ctx->in_rss_mode;

  bool previous_suppress = ctx->translation_suppress_output;
  if (translation_ready && !ctx->translation_suppress_output) {
    ctx->translation_suppress_output = true;
  }

  session_send_raw_text(ctx, text);

  ctx->translation_suppress_output = previous_suppress;

  if (translation_ready && !previous_suppress && text[0] != '\0') {
    session_translation_queue_block(ctx, text);
    session_translation_flush_ready(ctx);
  }
}

static void session_format_separator_line(session_ctx_t *ctx, const char *label, char *out, size_t length) {
  if (out == NULL || length == 0U) {
    return;
  }

  out[0] = '\0';

  if (ctx == NULL || label == NULL) {
    return;
  }

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";

  const size_t total_width = 80U;
  char label_block[96];
  snprintf(label_block, sizeof(label_block), " %s ", label);
  size_t label_len = strnlen(label_block, sizeof(label_block) - 1U);
  if (label_len > total_width) {
    label_len = total_width;
    label_block[label_len] = '\0';
  }

  size_t dash_total = total_width > label_len ? total_width - label_len : 0U;
  size_t left = dash_total / 2U;
  size_t right = dash_total - left;

  char body[128];
  size_t offset = 0U;
  for (size_t idx = 0U; idx < left && offset + 1U < sizeof(body); ++idx) {
    body[offset++] = '-';
  }
  if (offset + label_len < sizeof(body)) {
    memcpy(body + offset, label_block, label_len);
    offset += label_len;
  }
  for (size_t idx = 0U; idx < right && offset < sizeof(body); ++idx) {
    body[offset++] = '-';
  }
  body[offset] = '\0';

  snprintf(out, length, "%s%s%s%s%s", hl, fg, bold, body, ANSI_RESET);
}

static void session_render_separator(session_ctx_t *ctx, const char *label) {
  if (ctx == NULL || label == NULL) {
    return;
  }

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  session_format_separator_line(ctx, label, line, sizeof(line));
  if (line[0] != '\0') {
    session_send_line(ctx, line);
  }
}

static void session_clear_screen(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  static const char kClearSequence[] = "\033[2J\033[H";
  session_channel_write(ctx, kClearSequence, sizeof(kClearSequence) - 1U);
}

static void session_bbs_prepare_canvas(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_clear_screen(ctx);
  session_apply_background_fill(ctx);
}

static void session_bbs_recalculate_line_count(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  size_t count = 0U;
  if (ctx->pending_bbs_body_length > 0U) {
    count = 1U;
    for (size_t idx = 0U; idx < ctx->pending_bbs_body_length; ++idx) {
      if (ctx->pending_bbs_body[idx] == '\n') {
        ++count;
      }
    }
  }

  ctx->pending_bbs_line_count = count;
  if (ctx->pending_bbs_cursor_line > count) {
    ctx->pending_bbs_cursor_line = count;
    ctx->pending_bbs_editing_line = false;
  }
}

static bool session_bbs_get_line_range(const session_ctx_t *ctx, size_t line_index, size_t *start, size_t *length) {
  if (ctx == NULL || start == NULL || length == NULL) {
    return false;
  }

  if (line_index >= ctx->pending_bbs_line_count) {
    return false;
  }

  size_t offset = 0U;
  size_t current = 0U;
  while (current < line_index && offset < ctx->pending_bbs_body_length) {
    const char *newline = memchr(ctx->pending_bbs_body + offset, '\n', ctx->pending_bbs_body_length - offset);
    if (newline == NULL) {
      return false;
    }
    offset = (size_t)(newline - ctx->pending_bbs_body) + 1U;
    ++current;
  }

  if (offset > ctx->pending_bbs_body_length) {
    return false;
  }

  size_t end = ctx->pending_bbs_body_length;
  const char *newline = memchr(ctx->pending_bbs_body + offset, '\n', ctx->pending_bbs_body_length - offset);
  if (newline != NULL) {
    end = (size_t)(newline - ctx->pending_bbs_body);
  }

  *start = offset;
  *length = end - offset;
  return true;
}

static void session_bbs_copy_line(const session_ctx_t *ctx, size_t line_index, char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return;
  }

  buffer[0] = '\0';
  size_t start = 0U;
  size_t line_length = 0U;
  if (!session_bbs_get_line_range(ctx, line_index, &start, &line_length)) {
    return;
  }

  if (line_length >= length) {
    line_length = length - 1U;
  }

  if (line_length > 0U) {
    memcpy(buffer, ctx->pending_bbs_body + start, line_length);
  }
  buffer[line_length] = '\0';
}

static size_t session_editor_body_capacity(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return 0U;
  }

  if (ctx->editor_mode == SESSION_EDITOR_MODE_ASCIIART) {
    if (ctx->asciiart_target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE &&
        USER_DATA_PROFILE_PICTURE_LEN < SSH_CHATTER_ASCIIART_BUFFER_LEN) {
      return USER_DATA_PROFILE_PICTURE_LEN;
    }
    return SSH_CHATTER_ASCIIART_BUFFER_LEN;
  }

  return sizeof(ctx->pending_bbs_body);
}

static size_t session_editor_max_lines(const session_ctx_t *ctx) {
  if (ctx != NULL && ctx->editor_mode == SESSION_EDITOR_MODE_ASCIIART) {
    return SSH_CHATTER_ASCIIART_MAX_LINES;
  }

  return SIZE_MAX;
}

static bool session_bbs_append_line(session_ctx_t *ctx, const char *line, char *status, size_t status_length) {
  if (ctx == NULL) {
    return false;
  }

  const bool ascii_mode = ctx->editor_mode == SESSION_EDITOR_MODE_ASCIIART;
  if (status != NULL && status_length > 0U) {
    status[0] = '\0';
  }

  if (line == NULL) {
    line = "";
  }

  const char *length_limit_message =
      ascii_mode ? "ASCII art buffer is full. Additional text ignored." : "Post body length limit reached. Additional text ignored.";
  const char *line_limit_message = ascii_mode ? "ASCII art line limit reached. Additional text ignored."
                                             : "Post line limit reached. Additional text ignored.";
  const char *line_truncated_message = ascii_mode ? "Line truncated to fit within the ASCII art size limit."
                                                  : "Line truncated to fit within the post size limit.";

  size_t capacity = session_editor_body_capacity(ctx);
  if (capacity == 0U) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "%s", length_limit_message);
    }
    return false;
  }

  if (ctx->pending_bbs_body_length >= capacity - 1U) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "%s", length_limit_message);
    }
    return false;
  }

  session_bbs_recalculate_line_count(ctx);
  size_t max_lines = session_editor_max_lines(ctx);
  if (ctx->pending_bbs_line_count >= max_lines) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "%s", line_limit_message);
    }
    return false;
  }

  size_t available = capacity - ctx->pending_bbs_body_length - 1U;
  if (available == 0U) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "%s", length_limit_message);
    }
    return false;
  }

  bool needs_newline = ctx->pending_bbs_body_length > 0U;
  if (needs_newline) {
    if (available == 0U) {
      if (status != NULL && status_length > 0U) {
        snprintf(status, status_length, "%s", length_limit_message);
      }
      return false;
    }
    ctx->pending_bbs_body[ctx->pending_bbs_body_length++] = '\n';
    --available;
  }

  size_t line_length = strlen(line);
  if (line_length > available) {
    line_length = available;
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "%s", line_truncated_message);
    }
  }

  if (line_length > 0U) {
    memcpy(ctx->pending_bbs_body + ctx->pending_bbs_body_length, line, line_length);
    ctx->pending_bbs_body_length += line_length;
  }

  ctx->pending_bbs_body[ctx->pending_bbs_body_length] = '\0';
  session_bbs_recalculate_line_count(ctx);
  ctx->pending_bbs_cursor_line = ctx->pending_bbs_line_count;
  ctx->pending_bbs_editing_line = false;
  return true;
}

static bool session_bbs_replace_line(session_ctx_t *ctx, size_t line_index, const char *line, char *status,
                                     size_t status_length) {
  if (ctx == NULL || line == NULL) {
    return false;
  }

  const bool ascii_mode = ctx->editor_mode == SESSION_EDITOR_MODE_ASCIIART;
  if (status != NULL && status_length > 0U) {
    status[0] = '\0';
  }

  session_bbs_recalculate_line_count(ctx);
  if (line_index >= ctx->pending_bbs_line_count) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Unable to locate the selected line.");
    }
    return false;
  }

  size_t start = 0U;
  size_t old_length = 0U;
  if (!session_bbs_get_line_range(ctx, line_index, &start, &old_length)) {
    if (status != NULL && status_length > 0U) {
      snprintf(status, status_length, "Unable to locate the selected line.");
    }
    return false;
  }

  size_t current_length = ctx->pending_bbs_body_length;
  size_t capacity = session_editor_body_capacity(ctx);
  if (capacity == 0U) {
    return false;
  }
  if (capacity > 0U) {
    --capacity;
  }
  size_t base_length = current_length - old_length;
  size_t max_allowed = (capacity > base_length) ? (capacity - base_length) : 0U;

  size_t new_length = strlen(line);
  if (new_length > max_allowed) {
    new_length = max_allowed;
    if (status != NULL && status_length > 0U) {
      const char *line_truncated_message =
          ascii_mode ? "Line truncated to fit within the ASCII art size limit."
                     : "Line truncated to fit within the post size limit.";
      snprintf(status, status_length, "%s", line_truncated_message);
    }
  }

  size_t tail_offset = start + old_length;
  size_t tail_bytes = current_length - tail_offset + 1U;

  if (new_length > old_length) {
    size_t shift = new_length - old_length;
    memmove(ctx->pending_bbs_body + tail_offset + shift, ctx->pending_bbs_body + tail_offset, tail_bytes);
  } else if (old_length > new_length) {
    size_t shift = old_length - new_length;
    memmove(ctx->pending_bbs_body + tail_offset - shift, ctx->pending_bbs_body + tail_offset, tail_bytes);
    tail_offset -= shift;
  }

  if (new_length > 0U) {
    memcpy(ctx->pending_bbs_body + start, line, new_length);
  }

  ctx->pending_bbs_body_length = base_length + new_length;
  ctx->pending_bbs_body[ctx->pending_bbs_body_length] = '\0';

  session_bbs_recalculate_line_count(ctx);
  size_t updated_count = ctx->pending_bbs_line_count;
  if (line_index + 1U <= updated_count) {
    ctx->pending_bbs_cursor_line = line_index + 1U;
  } else {
    ctx->pending_bbs_cursor_line = updated_count;
  }
  ctx->pending_bbs_editing_line = false;
  return true;
}

static void session_bbs_render_editor(session_ctx_t *ctx, const char *status) {
  if (ctx == NULL) {
    return;
  }

  const bool ascii_mode = ctx->editor_mode == SESSION_EDITOR_MODE_ASCIIART;
  const bool editing_post = ctx->editor_mode == SESSION_EDITOR_MODE_BBS_EDIT;

  ctx->bbs_view_active = false;
  ctx->bbs_view_post_id = 0U;
  ctx->bbs_rendering_editor = true;

  session_bbs_prepare_canvas(ctx);
  session_bbs_recalculate_line_count(ctx);
  size_t line_count = ctx->pending_bbs_line_count;

  if (ascii_mode) {
    const char *target_label =
        (ctx->asciiart_target == SESSION_ASCIIART_TARGET_PROFILE_PICTURE) ? "profile picture" : "chat";
    char title_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(title_line, sizeof(title_line), "ASCII art %s draft (%zu/%u lines)", target_label, line_count,
             (unsigned int)SSH_CHATTER_ASCIIART_MAX_LINES);
    session_send_system_line(ctx, title_line);
  } else {
    char title_line[SSH_CHATTER_MESSAGE_LIMIT];
    if (editing_post) {
      if (ctx->pending_bbs_edit_id != 0U) {
        snprintf(title_line, sizeof(title_line), "Editing post #%" PRIu64 " '%s'", ctx->pending_bbs_edit_id,
                 ctx->pending_bbs_title);
      } else {
        snprintf(title_line, sizeof(title_line), "Editing '%s'", ctx->pending_bbs_title);
      }
    } else {
      snprintf(title_line, sizeof(title_line), "Composing '%s'", ctx->pending_bbs_title);
    }
    session_send_system_line(ctx, title_line);

    char tag_buffer[SSH_CHATTER_BBS_MAX_TAGS * (SSH_CHATTER_BBS_TAG_LEN + 2U)];
    tag_buffer[0] = '\0';
    size_t offset = 0U;
    for (size_t idx = 0U; idx < ctx->pending_bbs_tag_count; ++idx) {
      size_t remaining = sizeof(tag_buffer) - offset;
      if (remaining == 0U) {
        break;
      }
      int written = snprintf(tag_buffer + offset, remaining, "%s%s", idx > 0U ? "," : "", ctx->pending_bbs_tags[idx]);
      if (written < 0) {
        break;
      }
      if ((size_t)written >= remaining) {
        offset = sizeof(tag_buffer) - 1U;
        break;
      }
      offset += (size_t)written;
    }

    char tags_line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(tags_line, sizeof(tags_line), "Tags: %s", tag_buffer[0] != '\0' ? tag_buffer : "(none)");
    session_send_system_line(ctx, tags_line);
  }

  session_send_system_line(ctx, SSH_CHATTER_BBS_EDITOR_BODY_DIVIDER);

  if (line_count == 0U) {
    const char *prefix = ctx->pending_bbs_editing_line ? "> " : "> ";
    session_send_line(ctx, prefix);
  } else {
    for (size_t idx = 0U; idx < line_count; ++idx) {
      char line_buffer[SSH_CHATTER_MESSAGE_LIMIT];
      session_bbs_copy_line(ctx, idx, line_buffer, sizeof(line_buffer));
      bool selected = ctx->pending_bbs_editing_line && ctx->pending_bbs_cursor_line == idx;
      const char *prefix = selected ? "> " : "  ";
      char display[SSH_CHATTER_MESSAGE_LIMIT];
      if (line_buffer[0] == '\0') {
        snprintf(display, sizeof(display), "%s", prefix);
      } else {
        snprintf(display, sizeof(display), "%s%s", prefix, line_buffer);
      }
      session_send_line(ctx, display);
    }
    if (!ctx->pending_bbs_editing_line) {
      session_send_line(ctx, "> ");
    }
  }

  session_send_system_line(ctx, SSH_CHATTER_BBS_EDITOR_END_DIVIDER);

  size_t capacity = session_editor_body_capacity(ctx);
  size_t remaining = 0U;
  if (capacity > ctx->pending_bbs_body_length) {
    remaining = capacity - ctx->pending_bbs_body_length - 1U;
  }
  char remaining_line[64];
  snprintf(remaining_line, sizeof(remaining_line), "Remaining bytes: %zu", remaining);
  session_send_system_line(ctx, remaining_line);

  const char *terminator = session_editor_terminator(ctx);
  char shortcut_hint[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(shortcut_hint, sizeof(shortcut_hint), "Ctrl+S(or Save) inserts %s. Ctrl+A(or Abort) cancels the draft.", terminator);
  session_send_system_line(ctx, shortcut_hint);
  session_send_system_line(ctx, "Use Up/Down arrows to revisit a saved line and press Enter to store changes.");
  char publish_hint[SSH_CHATTER_MESSAGE_LIMIT];
  if (ascii_mode) {
    snprintf(publish_hint, sizeof(publish_hint), "Typing %s on its own line will finish the artwork.", terminator);
  } else if (editing_post) {
    snprintf(publish_hint, sizeof(publish_hint), "Typing %s on its own line will update the post.", terminator);
  } else {
    snprintf(publish_hint, sizeof(publish_hint), "Typing %s on its own line will publish the post.", terminator);
  }
  session_send_system_line(ctx, publish_hint);

  if (ctx->bbs_breaking_count > 0U && !ascii_mode) {
    session_send_system_line(ctx, "");
    session_send_system_line(ctx, "Breaking updates:");
    for (size_t idx = 0U; idx < ctx->bbs_breaking_count; ++idx) {
      session_send_system_line(ctx, ctx->bbs_breaking_messages[idx]);
    }
  }

  if (status != NULL && status[0] != '\0') {
    char working[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(working, sizeof(working), "%s", status);
    char *cursor = working;
    while (cursor != NULL && *cursor != '\0') {
      char *newline = strchr(cursor, '\n');
      if (newline != NULL) {
        *newline = '\0';
      }
      if (*cursor != '\0') {
        session_send_system_line(ctx, cursor);
      }
      if (newline == NULL) {
        break;
      }
      cursor = newline + 1;
    }
  }

  session_render_prompt(ctx, false);
  ctx->bbs_rendering_editor = false;
}

static void session_bbs_move_cursor(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || direction == 0) {
    return;
  }

  session_bbs_recalculate_line_count(ctx);
  size_t line_count = ctx->pending_bbs_line_count;

  if (line_count == 0U) {
    ctx->pending_bbs_cursor_line = 0U;
    ctx->pending_bbs_editing_line = false;
    session_set_input_text(ctx, "");
    session_bbs_render_editor(ctx, NULL);
    return;
  }

  size_t target = ctx->pending_bbs_cursor_line;
  bool editing = ctx->pending_bbs_editing_line;
  if (target > line_count) {
    target = line_count;
  }

  if (direction < 0) {
    if (!editing) {
      target = line_count - 1U;
      editing = true;
    } else {
      if (target > 0U) {
        --target;
      }
    }
  } else {
    if (editing) {
      if (target + 1U < line_count) {
        ++target;
      } else {
        target = line_count;
        editing = false;
      }
    }
  }

  ctx->pending_bbs_cursor_line = target;
  ctx->pending_bbs_editing_line = editing;

  char status[64];
  status[0] = '\0';

  if (editing && target < line_count) {
    char line_buffer[SSH_CHATTER_MAX_INPUT_LEN];
    session_bbs_copy_line(ctx, target, line_buffer, sizeof(line_buffer));
    session_set_input_text(ctx, line_buffer);
    snprintf(status, sizeof(status), "Editing line %zu of %zu.", target + 1U, line_count);
  } else {
    session_set_input_text(ctx, "");
    snprintf(status, sizeof(status), "Editing new line %zu.", line_count + 1U);
  }

  session_bbs_render_editor(ctx, status);
}

static bool session_render_external_banner(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  static const char kExternalBannerPath[] = "/var/lib/ssh-chatter/banner";

  struct stat banner_info;
  if (stat(kExternalBannerPath, &banner_info) != 0 || !S_ISREG(banner_info.st_mode)) {
    return false;
  }

  FILE *banner_file = fopen(kExternalBannerPath, "r");
  if (banner_file == NULL) {
    return false;
  }

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  bool rendered = false;
  while (fgets(line, sizeof(line), banner_file) != NULL) {
    size_t length = strlen(line);
    while (length > 0U && (line[length - 1U] == '\n' || line[length - 1U] == '\r')) {
      line[--length] = '\0';
    }

    session_send_plain_line(ctx, line);
    rendered = true;
  }

  fclose(banner_file);
  return rendered;
}

static void session_render_banner_ascii(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  static const char *kBanner[] = {
      "\033[1;35m+===================================================================+\033[0m",
      "\033[1;36m|  ██████╗██╗  ██╗ █████╗ ████████╗████████╗███████╗██████╗         |\033[0m",
      "\033[1;36m| ██╔════╝██║  ██║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗        |\033[0m",
      "\033[1;34m| ██║     ███████║███████║   ██║      ██║   █████╗  ██████╔╝        |\033[0m",
      "\033[1;34m| ██║     ██╔══██║██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗        |\033[0m",
      "\033[1;32m| ╚██████╗██║  ██║██║  ██║   ██║      ██║   ███████╗██║  ██║        |\033[0m",
      "\033[1;32m|  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝        |\033[0m",
      "\033[1;35m+===================================================================+\033[0m",
      "\033[1;36m|        *** Welcome to CHATTER (2025) ***                          |\033[0m",
      "\033[1;35m|   Cute and tiny SSH chat written in C.                            |\033[0m",
      "\033[1;36m|   Type \033[1;33m/help\033[1;36m to see available commands.                           |\033[0m",
      "\033[1;36m|   Type \033[1;33m/mode\033[1;36m to switch input modes.                               |\033[0m",
      "\033[1;35m+===================================================================+\033[0m",
  };

  for (size_t idx = 0; idx < sizeof(kBanner) / sizeof(kBanner[0]); ++idx) {
    session_send_system_line(ctx, kBanner[idx]);
  }
}


static void session_render_prelogin_language_prompt(session_ctx_t *ctx) {
  if (ctx == NULL || session_client_geo_language(ctx) != SESSION_UI_LANGUAGE_KO) {
    return;
  }

  session_send_system_line(ctx, "기본 UI 언어는 한국어입니다. 로그인 전에 원하는 언어를 선택하세요.");
  session_send_system_line(ctx, "Default UI language is Korean. Choose one before logging in:");

  const char *prefix = session_command_prefix(ctx);
  static const struct {
    const char *code;
    const char *label;
  } kLanguagePrompts[] = {
      {"en", "English"},
      {"jp", "日本語 / Japanese"},
      {"zh", "中文 / Chinese"},
      {"ru", "Русский / Russian"},
  };

  for (size_t idx = 0; idx < sizeof(kLanguagePrompts) / sizeof(kLanguagePrompts[0]); ++idx) {
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "  %sset-ui-lang %s  → %s", prefix, kLanguagePrompts[idx].code,
             kLanguagePrompts[idx].label);
    session_send_system_line(ctx, line);
  }

  session_send_system_line(ctx, "명령을 입력하면 해당 언어로 전환되고, Enter를 누르면 한국어가 유지됩니다.");
  session_send_system_line(ctx, "Run one of the commands above to switch, or press Enter to keep Korean.");
}

static void session_render_prelogin_banner(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->prelogin_banner_rendered) {
    return;
  }

  session_apply_background_fill(ctx);

  bool has_external_banner = session_render_external_banner(ctx);
  if (!has_external_banner) {
    session_render_banner_ascii(ctx);
  }

  session_send_plain_line(ctx, "\033[37mConnection established.\033[0m");
  session_send_plain_line(ctx, "\033[37mAuthenticate or choose a nickname to continue.\033[0m");

  session_render_prelogin_language_prompt(ctx);

  ctx->prelogin_banner_rendered = true;
}

static void session_render_banner(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  session_apply_background_fill(ctx);

  bool show_graphics = !ctx->prelogin_banner_rendered;
  bool has_external_banner = false;
  if (show_graphics) {
    has_external_banner = session_render_external_banner(ctx);
    if (!has_external_banner) {
      session_render_banner_ascii(ctx);
    }
  }

  char welcome[SSH_CHATTER_MESSAGE_LIMIT];
  size_t name_len = 0;
  if (ctx->user.name[0] != '\0')
    name_len = strlen(ctx->user.name);
  int welcome_padding = 55 - (int)name_len;
  if (welcome_padding < 0) {
    welcome_padding = 0;
  }

  snprintf(welcome, sizeof(welcome), "\033[1;32m|  Welcome, %s!%*s|\033[0m", ctx->user.name, welcome_padding, "");
  session_send_system_line(ctx, welcome);

  char version_line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t version_len = strlen(ctx->owner->version);
  int version_padding = 65 - (int)version_len;
  if (version_padding < 0) {
    version_padding = 0;
  }
  snprintf(version_line, sizeof(version_line), "\033[1;32m|  %s%*s|\033[0m", ctx->owner->version, version_padding, "");
  session_send_system_line(ctx, version_line);

  if (show_graphics && !has_external_banner) {
    session_send_system_line(ctx, "\033[1;32m+===================================================================+\033[0m");
  }

  const session_ui_locale_t *locale = session_ui_get_locale(ctx);
  const char *prefix = session_command_prefix(ctx);

  if (locale->welcome_help_hint != NULL && locale->welcome_help_hint[0] != '\0') {
    const char *args[] = {prefix};
    char hint[SSH_CHATTER_MESSAGE_LIMIT];
    session_format_template(locale->welcome_help_hint, args, sizeof(args) / sizeof(args[0]), hint, sizeof(hint));
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(line, sizeof(line), "\033[37m%s\033[0m", hint);
    session_send_plain_line(ctx, line);
  }

  if (locale->welcome_motd_hint != NULL && locale->welcome_motd_hint[0] != '\0') {
    const char *args[] = {prefix};
    char hint[SSH_CHATTER_MESSAGE_LIMIT];
    session_format_template(locale->welcome_motd_hint, args, sizeof(args) / sizeof(args[0]), hint, sizeof(hint));
    char highlighted[SSH_CHATTER_MESSAGE_LIMIT];
    session_apply_motd_highlight(ctx, hint, highlighted, sizeof(highlighted));
    session_send_plain_line(ctx, highlighted);
  }
  session_render_separator(ctx, "Chatroom");
}

static void session_render_prompt(session_ctx_t *ctx, bool include_separator) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  bool locked = session_output_lock(ctx);
  if (include_separator) {
    session_render_separator(ctx, "Input");
  }

  session_apply_background_fill(ctx);

  const char *fg = ctx->system_fg_code != NULL ? ctx->system_fg_code : "";
  const char *hl = ctx->system_highlight_code != NULL ? ctx->system_highlight_code : "";
  const char *bold = ctx->system_is_bold ? ANSI_BOLD : "";
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  const char *mode_prompt = ctx->input_mode == SESSION_INPUT_MODE_COMMAND ? "│ cmd> " : "│ > ";

  char prompt[128];
  size_t offset = 0U;
  offset = session_append_fragment(prompt, sizeof(prompt), offset, hl);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, fg);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, bold);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, mode_prompt);
  offset = session_append_fragment(prompt, sizeof(prompt), offset, ANSI_RESET);
  if (bg[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, bg);
  }
  if (fg[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, fg);
  }
  if (bold[0] != '\0') {
    offset = session_append_fragment(prompt, sizeof(prompt), offset, bold);
  }

  session_channel_write(ctx, prompt, offset);
  if (ctx->input_length > 0U) {
    session_channel_write(ctx, ctx->input_buffer, ctx->input_length);
  }

  if (locked) {
    session_output_unlock(ctx);
  }
}

static void session_refresh_input_line(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  bool locked = session_output_lock(ctx);
  const char *bg = ctx->system_bg_code != NULL ? ctx->system_bg_code : "";
  if (bg[0] != '\0') {
    session_channel_write(ctx, bg, strlen(bg));
  }

  static const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);

  if (bg[0] != '\0') {
    session_channel_write(ctx, bg, strlen(bg));
  }

  session_render_prompt(ctx, false);

  if (locked) {
    session_output_unlock(ctx);
  }
}

static void session_set_input_text(session_ctx_t *ctx, const char *text) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));

  if (text != NULL && text[0] != '\0') {
    const size_t len = strnlen(text, sizeof(ctx->input_buffer) - 1U);
    memcpy(ctx->input_buffer, text, len);
    ctx->input_buffer[len] = '\0';
    ctx->input_length = len;
  }

  session_refresh_input_line(ctx);
}

static void session_local_echo_char(session_ctx_t *ctx, char ch) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return;
  }

  if (ch == '\r' || ch == '\n') {
    session_channel_write(ctx, "\r\n", 2U);
    return;
  }

  session_channel_write(ctx, &ch, 1U);
}

static size_t session_utf8_prev_char_len(const char *buffer, size_t length) {
  if (buffer == NULL || length == 0U) {
    return 0U;
  }

  size_t idx = length;
  while (idx > 0U) {
    --idx;
    const unsigned char byte = (unsigned char)buffer[idx];
    if ((byte & 0xC0U) != 0x80U) {
      const size_t seq_len = length - idx;
      size_t expected = 1U;
      if ((byte & 0x80U) == 0U) {
        expected = 1U;
      } else if ((byte & 0xE0U) == 0xC0U) {
        expected = 2U;
      } else if ((byte & 0xF0U) == 0xE0U) {
        expected = 3U;
      } else if ((byte & 0xF8U) == 0xF0U) {
        expected = 4U;
      } else {
        expected = 1U;
      }

      if (seq_len < expected) {
        return seq_len;
      }
      return expected;
    }
  }

  return 1U;
}

static int session_utf8_char_width(const char *bytes, size_t length) {
  if (bytes == NULL || length == 0U) {
    return 0;
  }

  mbstate_t state;
  memset(&state, 0, sizeof(state));

  wchar_t wc;
  const size_t result = mbrtowc(&wc, bytes, length, &state);
  if (result == (size_t)-1 || result == (size_t)-2) {
    return 1;
  }

  const int width = wcwidth(wc);
  if (width < 0) {
    return 1;
  }

  return width;
}

static void session_local_backspace(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx) || ctx->input_length == 0U) {
    return;
  }

  const size_t char_len = session_utf8_prev_char_len(ctx->input_buffer, ctx->input_length);
  if (char_len == 0U || char_len > ctx->input_length) {
    return;
  }

  const size_t char_start = ctx->input_length - char_len;
  const int display_width = session_utf8_char_width(&ctx->input_buffer[char_start], char_len);

  ctx->input_length = char_start;
  ctx->input_buffer[ctx->input_length] = '\0';

  const int width = display_width > 0 ? display_width : 1;
  const char sequence[] = "\b \b";
  for (int idx = 0; idx < width; ++idx) {
    session_channel_write(ctx, sequence, sizeof(sequence) - 1U);
  }
}

static void session_clear_input(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->input_length = 0U;
  memset(ctx->input_buffer, 0, sizeof(ctx->input_buffer));
  ctx->input_history_position = -1;
  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (!ctx->bracket_paste_active) {
    session_refresh_input_line(ctx);
  }
}

static bool session_try_command_completion(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->input_length == 0U) {
    return false;
  }

  size_t first_visible = 0U;
  while (first_visible < ctx->input_length && isspace((unsigned char)ctx->input_buffer[first_visible])) {
    ++first_visible;
  }
  if (first_visible >= ctx->input_length) {
    return false;
  }

  const bool has_slash = ctx->input_buffer[first_visible] == '/';
  if (!has_slash && ctx->input_mode != SESSION_INPUT_MODE_COMMAND) {
    return false;
  }

  size_t command_start = first_visible + (has_slash ? 1U : 0U);
  if (command_start > ctx->input_length) {
    command_start = ctx->input_length;
  }

  size_t command_end = command_start;
  while (command_end < ctx->input_length && !isspace((unsigned char)ctx->input_buffer[command_end])) {
    ++command_end;
  }

  const size_t token_len = command_end - command_start;
  char prefix[SSH_CHATTER_MAX_INPUT_LEN];
  size_t copy_len = token_len < sizeof(prefix) - 1U ? token_len : sizeof(prefix) - 1U;
  if (copy_len > 0U) {
    memcpy(prefix, &ctx->input_buffer[command_start], copy_len);
  }
  prefix[copy_len] = '\0';

  const size_t prefix_len = strlen(prefix);
  const char *matches[SSH_CHATTER_COMMAND_COUNT];
  size_t match_count = 0U;
  for (size_t idx = 0U; idx < SSH_CHATTER_COMMAND_COUNT; ++idx) {
    const char *candidate = kSessionCommandNames[idx];
    if (prefix_len == 0U || strncasecmp(candidate, prefix, prefix_len) == 0) {
      matches[match_count++] = candidate;
    }
  }

  session_command_collect_localized_matches(ctx, prefix, matches, &match_count,
                                            sizeof(matches) / sizeof(matches[0]));

  if (match_count == 0U) {
    if (session_transport_active(ctx)) {
      const char bell = '\a';
      session_channel_write(ctx, &bell, 1U);
    }
    session_refresh_input_line(ctx);
    return true;
  }

  char updated[SSH_CHATTER_MAX_INPUT_LEN];
  size_t updated_len = 0U;
  const size_t prefix_copy_len = command_start < sizeof(updated) ? command_start : sizeof(updated) - 1U;
  if (prefix_copy_len > 0U) {
    memcpy(updated, ctx->input_buffer, prefix_copy_len);
    updated_len = prefix_copy_len;
  }

  if (match_count == 1U) {
    const char *completion = matches[0];
    size_t completion_len = strlen(completion);
    if (updated_len + completion_len >= sizeof(updated)) {
      completion_len = sizeof(updated) - 1U - updated_len;
    }
    memcpy(&updated[updated_len], completion, completion_len);
    updated_len += completion_len;

    size_t suffix_len = ctx->input_length - command_end;
    if (suffix_len > 0U) {
      size_t copy_suffix = suffix_len;
      if (updated_len + copy_suffix >= sizeof(updated)) {
        copy_suffix = sizeof(updated) - 1U - updated_len;
      }
      memcpy(&updated[updated_len], &ctx->input_buffer[command_end], copy_suffix);
      updated_len += copy_suffix;
    } else if (updated_len + 1U < sizeof(updated)) {
      updated[updated_len++] = ' ';
    }

    updated[updated_len] = '\0';
    session_set_input_text(ctx, updated);
    ctx->input_history_position = -1;
    session_scrollback_reset_position(ctx);
    return true;
  }

  size_t common_len = strlen(matches[0]);
  for (size_t idx = 1U; idx < match_count && common_len > 0U; ++idx) {
    const char *candidate = matches[idx];
    size_t candidate_len = strlen(candidate);
    if (candidate_len < common_len) {
      common_len = candidate_len;
    }
    size_t compare_len = common_len;
    size_t match_prefix = 0U;
    for (; match_prefix < compare_len; ++match_prefix) {
      unsigned char lhs = (unsigned char)tolower((unsigned char)matches[0][match_prefix]);
      unsigned char rhs = (unsigned char)tolower((unsigned char)candidate[match_prefix]);
      if (lhs != rhs) {
        break;
      }
    }
    common_len = match_prefix;
  }

  if (common_len > prefix_len) {
    size_t completion_len = common_len;
    if (updated_len + completion_len >= sizeof(updated)) {
      completion_len = sizeof(updated) - 1U - updated_len;
    }
    memcpy(&updated[updated_len], matches[0], completion_len);
    updated_len += completion_len;

    size_t suffix_len = ctx->input_length - command_end;
    if (suffix_len > 0U) {
      size_t copy_suffix = suffix_len;
      if (updated_len + copy_suffix >= sizeof(updated)) {
        copy_suffix = sizeof(updated) - 1U - updated_len;
      }
      memcpy(&updated[updated_len], &ctx->input_buffer[command_end], copy_suffix);
      updated_len += copy_suffix;
    }

    updated[updated_len] = '\0';
    session_set_input_text(ctx, updated);
    ctx->input_history_position = -1;
    session_scrollback_reset_position(ctx);
    return true;
  }

  session_send_system_line(ctx, "Possible commands:");
  char line[SSH_CHATTER_MESSAGE_LIMIT];
  size_t offset = 0U;
  for (size_t idx = 0U; idx < match_count; ++idx) {
    char entry[64];
    snprintf(entry, sizeof(entry), "/%s", matches[idx]);
    size_t entry_len = strlen(entry);
    if (offset != 0U) {
      if (offset + 1U >= sizeof(line)) {
        line[offset] = '\0';
        session_send_system_line(ctx, line);
        offset = 0U;
      }
      line[offset++] = ' ';
    }
    if (entry_len >= sizeof(line)) {
      session_send_system_line(ctx, entry);
      offset = 0U;
      continue;
    }
    if (offset + entry_len >= sizeof(line)) {
      line[offset] = '\0';
      session_send_system_line(ctx, line);
      offset = 0U;
    }
    memcpy(&line[offset], entry, entry_len);
    offset += entry_len;
  }
  if (offset > 0U) {
    line[offset] = '\0';
    session_send_system_line(ctx, line);
  }
  session_refresh_input_line(ctx);
  return true;
}

static void session_scrollback_reset_position(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->history_scroll_position = 0U;
  ctx->history_latest_notified = false;
  ctx->history_oldest_notified = false;
}

static void session_history_record(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL) {
    return;
  }

  bool has_visible = false;
  for (const char *cursor = line; *cursor != '\0'; ++cursor) {
    if (!isspace((unsigned char)*cursor)) {
      has_visible = true;
      break;
    }
  }

  if (!has_visible) {
    ctx->input_history_position = -1;
    return;
  }

  const char *trimmed = line;
  while (*trimmed == ' ' || *trimmed == '\t') {
    ++trimmed;
  }

  bool is_command = false;
  if (*trimmed != '\0') {
    if (*trimmed == '/') {
      is_command = true;
    } else if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
      is_command = true;
    }
  }

  if (ctx->input_history_count > 0U) {
    const size_t last_index = ctx->input_history_count - 1U;
    if (strncmp(ctx->input_history[last_index], line, sizeof(ctx->input_history[last_index])) == 0) {
      ctx->input_history_position = -1;
      return;
    }
  }

  if (ctx->input_history_count < SSH_CHATTER_INPUT_HISTORY_LIMIT) {
    snprintf(ctx->input_history[ctx->input_history_count], sizeof(ctx->input_history[0]), "%s", line);
    ctx->input_history_is_command[ctx->input_history_count] = is_command;
    ++ctx->input_history_count;
  } else {
    memmove(ctx->input_history, ctx->input_history + 1,
            sizeof(ctx->input_history) - sizeof(ctx->input_history[0]));
    memmove(ctx->input_history_is_command, ctx->input_history_is_command + 1,
            (SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U) * sizeof(ctx->input_history_is_command[0]));
    snprintf(ctx->input_history[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U], sizeof(ctx->input_history[0]), "%s", line);
    ctx->input_history_is_command[SSH_CHATTER_INPUT_HISTORY_LIMIT - 1U] = is_command;
  }

  ctx->input_history_position = -1;
  session_scrollback_reset_position(ctx);
}

static void session_history_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || direction == 0) {
    return;
  }

  session_scrollback_reset_position(ctx);

  if (ctx->input_history_count == 0U) {
    ctx->input_history_position = (int)ctx->input_history_count;
    session_set_input_text(ctx, "");
    return;
  }

  int position = ctx->input_history_position;
  if (position < 0 || position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  position += direction;
  if (position < 0) {
    position = 0;
  }
  if (position > (int)ctx->input_history_count) {
    position = (int)ctx->input_history_count;
  }

  ctx->input_history_position = position;

  if (position == (int)ctx->input_history_count) {
    session_set_input_text(ctx, "");
  } else {
    session_set_input_text(ctx, ctx->input_history[position]);
  }
}

static void session_scrollback_navigate(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || ctx->owner == NULL || !session_transport_active(ctx) || direction == 0) {
    return;
  }

  size_t total = host_history_total(ctx->owner);
  if (total == 0U) {
    session_send_system_line(ctx, "No chat history available yet.");
    return;
  }

  bool suppress_translation = translator_should_skip_scrollback_translation();
  bool previous_translation_suppress = ctx->translation_suppress_output;
  if (suppress_translation) {
    ctx->translation_suppress_output = true;
  }

  const size_t step = SSH_CHATTER_SCROLLBACK_CHUNK > 0 ? SSH_CHATTER_SCROLLBACK_CHUNK : 1U;
  if (ctx->history_scroll_position >= total) {
    ctx->history_scroll_position = total > 0U ? total - 1U : 0U;
  }
  size_t position = ctx->history_scroll_position;
  size_t new_position = position;
  bool reached_oldest = false;

  const size_t max_position = total > 0U ? total - 1U : 0U;

  if (direction > 0) {
    size_t current_newest_visible = 0U;
    if (position < total) {
      current_newest_visible = total - 1U - position;
    }

    size_t current_chunk = step;
    if (current_chunk > current_newest_visible + 1U) {
      current_chunk = current_newest_visible + 1U;
    }
    if (current_chunk == 0U) {
      current_chunk = 1U;
    }

    const size_t current_oldest_visible =
        (current_newest_visible + 1U > current_chunk) ? (current_newest_visible + 1U - current_chunk) : 0U;

    if (current_oldest_visible == 0U) {
      reached_oldest = true;
    } else if (new_position < max_position) {
      size_t advance = step;
      if (advance > max_position - new_position) {
        advance = max_position - new_position;
      }
      if (advance == 0U) {
        reached_oldest = true;
      } else {
        new_position += advance;
      }
    } else {
      reached_oldest = true;
    }
  } else if (direction < 0) {
    if (new_position > 0U) {
      size_t retreat = step;
      if (retreat > new_position) {
        retreat = new_position;
      }
      new_position -= retreat;
    }
  }

  bool at_boundary = (new_position == position);
  ctx->history_scroll_position = new_position;

  bool at_latest = (ctx->history_scroll_position == 0U);
  bool at_oldest = (ctx->history_scroll_position == max_position && total > 0U);

  if (!at_latest) {
    ctx->history_latest_notified = false;
  }
  if (!at_oldest) {
    ctx->history_oldest_notified = false;
  }

  const char clear_sequence[] = "\r" ANSI_CLEAR_LINE;
  session_channel_write(ctx, clear_sequence, sizeof(clear_sequence) - 1U);
  session_channel_write(ctx, "\r\n", 2U);

  if (direction < 0 && at_boundary && new_position == 0U) {
    if (!ctx->history_latest_notified) {
      session_send_system_line(ctx, "Already at the latest messages.");
      ctx->history_latest_notified = true;
    }
    session_render_prompt(ctx, false);
    goto cleanup;
  }

  const size_t newest_visible = total - 1U - new_position;
  size_t chunk = step;
  if (chunk > newest_visible + 1U) {
    chunk = newest_visible + 1U;
  }
  if (chunk == 0U) {
    chunk = 1U;
  }

  const size_t oldest_visible = (newest_visible + 1U > chunk) ? (newest_visible + 1U - chunk) : 0U;

  if (direction > 0 && (reached_oldest || (at_boundary && new_position == max_position))) {
    if (!ctx->history_oldest_notified) {
      session_send_system_line(ctx, "Reached the oldest stored message.");
      ctx->history_oldest_notified = true;
    }
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Scrollback (%zu-%zu of %zu)", oldest_visible + 1U, newest_visible + 1U, total);
  session_send_system_line(ctx, header);

  chat_history_entry_t buffer[SSH_CHATTER_SCROLLBACK_CHUNK];
  size_t request = chunk;
  if (request > SSH_CHATTER_SCROLLBACK_CHUNK) {
    request = SSH_CHATTER_SCROLLBACK_CHUNK;
  }
  size_t copied = host_history_copy_range(ctx->owner, oldest_visible, buffer, request);
  if (copied == 0U) {
    session_send_system_line(ctx, "Unable to read chat history right now.");
    ctx->history_scroll_position = (total > 0U) ? max_position : 0U;
    ctx->history_latest_notified = false;
    ctx->history_oldest_notified = false;
    session_render_prompt(ctx, false);
    goto cleanup;
  }

  for (size_t idx = 0; idx < copied; ++idx) {
    session_send_history_entry(ctx, &buffer[idx]);
  }

  if (direction < 0 && new_position == 0U) {
    if (!ctx->history_latest_notified) {
      session_send_system_line(ctx, "End of scrollback.");
      ctx->history_latest_notified = true;
    }
  }

  session_render_prompt(ctx, false);

cleanup:
  if (suppress_translation) {
    ctx->translation_suppress_output = previous_translation_suppress;
  }
}

static bool session_consume_escape_sequence(session_ctx_t *ctx, char ch) {
  if (ctx == NULL) {
    return false;
  }

  if (!ctx->input_escape_active) {
    if (ch == 0x1b) {
      ctx->input_escape_active = true;
      ctx->input_escape_length = 0U;
      if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
        ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
      }
      return true;
    }
    return false;
  }

  if (ctx->input_escape_length < sizeof(ctx->input_escape_buffer)) {
    ctx->input_escape_buffer[ctx->input_escape_length++] = ch;
  }

  const char *sequence = ctx->input_escape_buffer;
  const size_t length = ctx->input_escape_length;

  if (length == 1U) {
    return true;
  }

  if (length == 2U) {
    if (sequence[1] == '[') {
      return true;
    }
    if (sequence[1] == 'k') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
      } else {
        if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
          ctx->input_escape_active = false;
          ctx->input_escape_length = 0U;
          return true;
        }
        session_history_navigate(ctx, -1);
      }
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[1] == 'j') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
      } else {
        if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
          ctx->input_escape_active = false;
          ctx->input_escape_length = 0U;
          return true;
        }
        session_history_navigate(ctx, 1);
      }
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if ((sequence[1] == 'l' || sequence[1] == 'L') && ctx->game.active && ctx->game.type == SESSION_GAME_ALPHA) {
      session_game_alpha_manual_lock(ctx);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == '[') {
    int dx = 0;
    int dy = 0;
    switch (sequence[2]) {
      case 'A':
        dy = -1;
        break;
      case 'B':
        dy = 1;
        break;
      case 'C':
        dx = 1;
        break;
      case 'D':
        dx = -1;
        break;
      default:
        break;
    }
    if ((dx != 0 || dy != 0) && session_game_alpha_handle_arrow(ctx, dx, dy)) {
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'A') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 3U && sequence[1] == 'O') {
    int dx = 0;
    int dy = 0;
    switch (sequence[2]) {
      case 'A':
        dy = -1;
        break;
      case 'B':
        dy = 1;
        break;
      case 'C':
        dx = 1;
        break;
      case 'D':
        dx = -1;
        break;
      default:
        break;
    }
    if ((dx != 0 || dy != 0) && session_game_alpha_handle_arrow(ctx, dx, dy)) {
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'A') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, -1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == 'B') {
      if (ctx->bbs_post_pending) {
        session_bbs_move_cursor(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 1U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->in_rss_mode && session_rss_move(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      if (ctx->input_mode == SESSION_INPUT_MODE_COMMAND) {
        session_history_navigate(ctx, 1);
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  if (length == 4U && sequence[1] == '[' && sequence[3] == '~') {
    if (sequence[2] == '5') {
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, 1, 0U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, 1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
    if (sequence[2] == '6') {
      if (ctx->bbs_view_active && session_bbs_scroll(ctx, -1, 0U)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
      session_scrollback_navigate(ctx, -1);
      ctx->input_escape_active = false;
      ctx->input_escape_length = 0U;
      return true;
    }
  }

  const bool bracket_sequence = (length >= 2U && sequence[1] == '[');
  if (bracket_sequence) {
    const char final = sequence[length - 1U];
    if (final != '~' && !(length == 3U && isalpha((unsigned char)sequence[2]))) {
      return true;
    }
    if (final == '~') {
      if (length >= 5U && strncmp(&sequence[2], "200", 3) == 0) {
        ctx->bracket_paste_active = true;
      } else if (length >= 5U && strncmp(&sequence[2], "201", 3) == 0) {
        ctx->bracket_paste_active = false;
        session_refresh_input_line(ctx);
      }
    }
  }

  ctx->input_escape_active = false;
  ctx->input_escape_length = 0U;
  if (bracket_sequence) {
    return true;
  }
  return ch == 0x1b;
}

static void session_send_private_message_line(session_ctx_t *ctx, const session_ctx_t *color_source, const char *label,
                                              const char *message) {
  if (ctx == NULL || !session_transport_active(ctx) || color_source == NULL || label == NULL || message == NULL) {
    return;
  }

  const char *highlight = color_source->user_highlight_code != NULL ? color_source->user_highlight_code : "";
  const char *color = color_source->user_color_code != NULL ? color_source->user_color_code : "";
  const char *bold = color_source->user_is_bold ? ANSI_BOLD : "";

  char line[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(line, sizeof(line), "%s%s%s[%s]%s %s", highlight, bold, color, label, ANSI_RESET, message);
  session_send_line(ctx, line);

  if (ctx != color_source && ctx->history_scroll_position == 0U) {
    session_refresh_input_line(ctx);
  }
}

static void session_send_history_entry(session_ctx_t *ctx, const chat_history_entry_t *entry) {
  if (ctx == NULL || !session_transport_active(ctx) || entry == NULL) {
    return;
  }

  if (session_should_hide_entry(ctx, entry)) {
    return;
  }

  if (entry->is_user_message) {
    bool previous_override = session_translation_push_scope_override(ctx);
    const char *highlight = entry->user_highlight_code != NULL ? entry->user_highlight_code : "";
    const char *color = entry->user_color_code != NULL ? entry->user_color_code : "";
    const char *bold = entry->user_is_bold ? ANSI_BOLD : "";

    const char *message_text = entry->message;
    char fallback[SSH_CHATTER_MESSAGE_LIMIT + 64];
    if ((message_text == NULL || message_text[0] == '\0') && entry->attachment_type != CHAT_ATTACHMENT_NONE) {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(fallback, sizeof(fallback), "shared a %s", label);
      message_text = fallback;
    } else if (message_text == NULL) {
      message_text = "";
    }

    bool multiline_message = strchr(message_text, '\n') != NULL;
    const char *header_body = message_text;
    if (multiline_message) {
      header_body = "shared ASCII art:";
    }

    char header[SSH_CHATTER_MESSAGE_LIMIT + 128];
    if (entry->message_id > 0U) {
      snprintf(header, sizeof(header), "[#%" PRIu64 "] %s%s%s[%s]%s %s", entry->message_id, highlight, bold, color,
               entry->username, ANSI_RESET, header_body);
    } else {
      snprintf(header, sizeof(header), "%s%s%s[%s]%s %s", highlight, bold, color, entry->username, ANSI_RESET,
               header_body);
    }
    session_send_plain_line(ctx, header);

    if (multiline_message) {
      const char *line_start = message_text;
      while (line_start != NULL) {
        const char *newline = strchr(line_start, '\n');
        size_t segment_length = newline != NULL ? (size_t)(newline - line_start) : strlen(line_start);
        char line[SSH_CHATTER_MESSAGE_LIMIT + 1U];
        if (segment_length >= sizeof(line)) {
          segment_length = sizeof(line) - 1U;
        }
        if (segment_length > 0U) {
          memcpy(line, line_start, segment_length);
        }
        line[segment_length] = '\0';
        session_send_plain_line(ctx, line);
        if (newline == NULL) {
          break;
        }
        line_start = newline + 1;
      }
    }

    char attachment_line[SSH_CHATTER_ATTACHMENT_TARGET_LEN + 64];
    if (entry->attachment_type != CHAT_ATTACHMENT_NONE && entry->attachment_target[0] != '\0') {
      const char *label = chat_attachment_type_label(entry->attachment_type);
      snprintf(attachment_line, sizeof(attachment_line), "    ↳ %s: %s", label, entry->attachment_target);
      session_send_plain_line(ctx, attachment_line);
    }

    char caption_line[SSH_CHATTER_ATTACHMENT_CAPTION_LEN + 32];
    if (entry->attachment_caption[0] != '\0') {
      snprintf(caption_line, sizeof(caption_line), "    ↳ note: %s", entry->attachment_caption);
      session_send_plain_line(ctx, caption_line);
    }

    char reactions_line[SSH_CHATTER_MESSAGE_LIMIT];
    if (chat_history_entry_build_reaction_summary(entry, reactions_line, sizeof(reactions_line))) {
      char summary_line[SSH_CHATTER_MESSAGE_LIMIT + 32];
      snprintf(summary_line, sizeof(summary_line), "    ↳ reactions: %s", reactions_line);
      session_send_plain_line(ctx, summary_line);
    }

    if (entry->attachment_type == CHAT_ATTACHMENT_IMAGE && entry->message_id > 0U) {
      char hint[SSH_CHATTER_MESSAGE_LIMIT];
      session_send_plain_line(ctx, hint);
    }

    if (entry->message_id > 0U) {
      session_send_reply_tree(ctx, entry->message_id, 0U, 1U);
    }

    session_translation_pop_scope_override(ctx, previous_override);
  } else {
    session_send_system_line(ctx, entry->message);
  }
}

// Present a summary of a poll, optionally showing the label used for named polls.
static void session_send_poll_summary_generic(session_ctx_t *ctx, const poll_state_t *poll, const char *label) {
  if (ctx == NULL || poll == NULL) {
    return;
  }

  if (!poll->active || poll->option_count == 0U) {
    if (label == NULL) {
      session_send_system_line(ctx, "No active poll right now.");
    } else {
      char message[128];
      snprintf(message, sizeof(message), "Poll '%s' is not active.", label);
      session_send_system_line(ctx, message);
    }
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT + 64];
  const char *mode_suffix = poll->allow_multiple ? " (multiple choice)" : "";
  if (label == NULL) {
    snprintf(header, sizeof(header), "Poll #%" PRIu64 ": %s%s", poll->id, poll->question, mode_suffix);
  } else {
    snprintf(header, sizeof(header), "Poll [%s] #%" PRIu64 ": %s%s", label, poll->id, poll->question, mode_suffix);
  }
  session_send_system_line(ctx, header);

  for (size_t idx = 0U; idx < poll->option_count; ++idx) {
    char option_line[SSH_CHATTER_MESSAGE_LIMIT + 64];
    uint32_t votes = poll->options[idx].votes;
    if (label == NULL) {
      snprintf(option_line, sizeof(option_line), "  /%zu - %s (%u vote%s)", idx + 1U, poll->options[idx].text, votes,
               votes == 1U ? "" : "s");
    } else {
      snprintf(option_line, sizeof(option_line), "  /%zu %s - %s (%u vote%s)", idx + 1U, label, poll->options[idx].text, votes,
               votes == 1U ? "" : "s");
    }
    session_send_system_line(ctx, option_line);
  }

  if (label == NULL) {
    if (poll->allow_multiple) {
      session_send_system_line(ctx, "Vote with /1 through /5 (multiple selections allowed).");
    } else {
      session_send_system_line(ctx, "Vote with /1 through /5.");
    }
  } else {
    char footer[192];
    if (poll->allow_multiple) {
      snprintf(footer, sizeof(footer), "Vote with /1 %s through /%zu %s (multiple selections allowed).", label,
               poll->option_count, label);
    } else {
      snprintf(footer, sizeof(footer), "Vote with /1 %s through /%zu %s.", label, poll->option_count, label);
    }
    session_send_system_line(ctx, footer);
  }
}

// Gather the main poll and any named polls and present summaries to the caller.
static void session_send_poll_summary(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  poll_state_t main_snapshot = {0};
  named_poll_state_t named_snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
  size_t named_count = 0U;

  pthread_mutex_lock(&host->lock);
  main_snapshot = host->poll;
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] == '\0') {
      continue;
    }
    named_snapshot[named_count++] = host->named_polls[idx];
    if (named_count >= SSH_CHATTER_MAX_NAMED_POLLS) {
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  session_send_poll_summary_generic(ctx, &main_snapshot, NULL);

  size_t active_named = 0U;
  for (size_t idx = 0U; idx < named_count; ++idx) {
    if (named_snapshot[idx].poll.active && named_snapshot[idx].poll.option_count > 0U) {
      if (active_named == 0U) {
        session_send_system_line(ctx, "Active named polls:");
      }
      session_send_poll_summary_generic(ctx, &named_snapshot[idx].poll, named_snapshot[idx].label);
      ++active_named;
    }
  }

  if (active_named == 0U) {
    session_send_system_line(ctx,
                             "No active named polls. Use /vote <label> <question>|<option1>|<option2> or /vote-single for a "
                             "single-choice poll.");
  }
}

// Provide a lightweight overview of every named poll regardless of status.
static void session_list_named_polls(session_ctx_t *ctx) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  host_t *host = ctx->owner;
  named_poll_state_t snapshot[SSH_CHATTER_MAX_NAMED_POLLS];
  size_t count = 0U;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_MAX_NAMED_POLLS; ++idx) {
    if (host->named_polls[idx].label[0] == '\0') {
      continue;
    }
    snapshot[count++] = host->named_polls[idx];
    if (count >= SSH_CHATTER_MAX_NAMED_POLLS) {
      break;
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (count == 0U) {
    session_send_system_line(ctx,
                             "No named polls exist. Start one with /vote <label> <question>|<option1>|<option2> or /vote-single "
                             "for single-choice voting.");
    return;
  }

  session_send_system_line(ctx, "Named polls overview:");
  for (size_t idx = 0U; idx < count; ++idx) {
    const named_poll_state_t *entry = &snapshot[idx];
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    const char *status = entry->poll.active ? "active" : "inactive";
    const char *mode = entry->poll.allow_multiple ? "multiple choice" : "single choice";
    snprintf(line, sizeof(line), "- [%s] %s (options: %zu, %s, %s)", entry->label, entry->poll.question,
             entry->poll.option_count, status, mode);
    session_send_system_line(ctx, line);
  }
}

static bool chat_history_entry_build_reaction_summary(const chat_history_entry_t *entry, char *buffer, size_t length) {
  if (entry == NULL || buffer == NULL || length == 0U) {
    return false;
  }

  buffer[0] = '\0';
  bool any = false;
  size_t offset = 0U;

  for (size_t idx = 0U; idx < SSH_CHATTER_REACTION_KIND_COUNT; ++idx) {
    uint32_t count = entry->reaction_counts[idx];
    if (count == 0U) {
      continue;
    }

    const reaction_descriptor_t *descriptor = &REACTION_DEFINITIONS[idx];
    char chunk[64];
    snprintf(chunk, sizeof(chunk), "%s x%u", descriptor->icon, count);

    size_t chunk_len = strlen(chunk);
    if (chunk_len + 1U >= length - offset) {
      break;
    }

    if (any) {
      buffer[offset++] = ' ';
    }
    memcpy(buffer + offset, chunk, chunk_len);
    offset += chunk_len;
    buffer[offset] = '\0';
    any = true;
  }

  return any;
}

static const char *chat_attachment_type_label(chat_attachment_type_t type) {
  switch (type) {
  case CHAT_ATTACHMENT_IMAGE:
    return "image";
  case CHAT_ATTACHMENT_VIDEO:
    return "video";
  case CHAT_ATTACHMENT_AUDIO:
    return "audio";
  case CHAT_ATTACHMENT_FILE:
    return "file";
  case CHAT_ATTACHMENT_NONE:
  default:
    return "attachment";
  }
}

static bool session_handle_service_request(ssh_message message) {
  if (message == NULL) {
    return false;
  }

  const char *service = ssh_message_service_service(message);
  if (service == NULL) {
    return false;
  }

  if (strcmp(service, "ssh-userauth") == 0 || strcmp(service, "ssh-connection") == 0) {
    ssh_message_service_reply_success(message);
    return true;
  }

  return false;
}

static int session_authenticate(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool authenticated = false;
  if (ctx != NULL) {
    ctx->lan_operator_credentials_valid = false;
  }

  while (!authenticated && (message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    switch (message_type) {
      case SSH_REQUEST_SERVICE:
        if (!session_handle_service_request(message)) {
          ssh_message_reply_default(message);
        }
        break;
      case SSH_REQUEST_AUTH:
        {
          const char *username = ssh_message_auth_user(message);
          if (username != NULL && username[0] != '\0') {
            snprintf(ctx->user.name, sizeof(ctx->user.name), "%.*s", SSH_CHATTER_USERNAME_LEN - 1, username);
          }

          bool reserved_name = false;
          lan_operator_credential_t *credential = NULL;
          if (ctx->owner != NULL) {
            credential = host_find_lan_operator_credential(ctx->owner, ctx->user.name);
            reserved_name = credential != NULL;
          }

          if (!reserved_name) {
            ssh_message_auth_reply_success(message, 0);
            authenticated = true;
            break;
          }

          if (!session_is_lan_client(ctx->client_ip)) {
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
            ssh_message_reply_default(message);
            break;
          }

          const int auth_method = ssh_message_subtype(message);
          if (auth_method != SSH_AUTH_METHOD_PASSWORD) {
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
            ssh_message_reply_default(message);
            break;
          }

          const char *password = ssh_message_auth_password(message);
          if (credential == NULL || password == NULL || credential->password[0] == '\0' || strcmp(credential->password, password) != 0) {
            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
            ssh_message_reply_default(message);
            break;
          }

          ctx->lan_operator_credentials_valid = true;
          snprintf(ctx->user.name, sizeof(ctx->user.name), "%s", credential->nickname);
          ssh_message_auth_reply_success(message, 0);
          authenticated = true;
        }
        break;
      default:
        ssh_message_reply_default(message);
        break;
    }
    ssh_message_free(message);
  }

  return authenticated ? 0 : -1;
}

static int session_accept_channel(session_ctx_t *ctx) {
  ssh_message message = NULL;

  while ((message = ssh_message_get(ctx->session)) != NULL) {
    const int message_type = ssh_message_type(message);
    if (message_type == SSH_REQUEST_SERVICE) {
      if (!session_handle_service_request(message)) {
        ssh_message_reply_default(message);
      }
      ssh_message_free(message);
      continue;
    }

    if (message_type == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
      ssh_channel channel = ssh_message_channel_request_open_reply_accept(message);
      if (channel == NULL) {
        accept_channel_fn_t accept_channel = resolve_accept_channel_fn();
        if (accept_channel != NULL) {
          channel = ssh_channel_new(ctx->session);
          if (channel != NULL) {
            if (accept_channel(message, channel) != SSH_OK) {
              ssh_channel_free(channel);
              channel = NULL;
            }
          }
        }
      }

      if (channel != NULL) {
        ctx->channel = channel;
        ssh_message_free(message);
        break;
      }

      ssh_message_reply_default(message);
      ssh_message_free(message);
      continue;
    }

    ssh_message_reply_default(message);
    ssh_message_free(message);
  }

  return session_transport_active(ctx) ? 0 : -1;
}

static int session_prepare_shell(session_ctx_t *ctx) {
  ssh_message message = NULL;
  bool shell_ready = false;

  while (!shell_ready && (message = ssh_message_get(ctx->session)) != NULL) {
    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
      const int subtype = ssh_message_subtype(message);
      if (subtype == SSH_CHANNEL_REQUEST_PTY || subtype == SSH_CHANNEL_REQUEST_SHELL) {
        ssh_message_channel_request_reply_success(message);
        if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
          shell_ready = true;
        }
      } else {
        ssh_message_reply_default(message);
      }
    } else {
      ssh_message_reply_default(message);
    }
    ssh_message_free(message);
  }

  return shell_ready ? 0 : -1;
}

static const char *session_captcha_question_for_language(const captcha_prompt_t *prompt, captcha_language_t language) {
  if (prompt == NULL) {
    return NULL;
  }

  switch (language) {
    case CAPTCHA_LANGUAGE_EN:
      return prompt->question_en;
    case CAPTCHA_LANGUAGE_ZH:
      return prompt->question_zh;
    case CAPTCHA_LANGUAGE_RU:
      return prompt->question_ru;
    case CAPTCHA_LANGUAGE_KO:
    default:
      return prompt->question_ko;
  }
}

static const char *session_captcha_label_for_language(captcha_language_t language) {
  switch (language) {
    case CAPTCHA_LANGUAGE_EN:
      return "Captcha: ";
    case CAPTCHA_LANGUAGE_ZH:
      return "驗證碼: ";
    case CAPTCHA_LANGUAGE_RU:
      return "Капча: ";
    case CAPTCHA_LANGUAGE_KO:
    default:
      return "캡챠: ";
  }
}

static captcha_language_t session_captcha_language_from_ui(session_ui_language_t language) {
  switch (language) {
    case SESSION_UI_LANGUAGE_EN:
      return CAPTCHA_LANGUAGE_EN;
    case SESSION_UI_LANGUAGE_ZH:
      return CAPTCHA_LANGUAGE_ZH;
    case SESSION_UI_LANGUAGE_RU:
      return CAPTCHA_LANGUAGE_RU;
    case SESSION_UI_LANGUAGE_JP:
      return CAPTCHA_LANGUAGE_EN;
    case SESSION_UI_LANGUAGE_KO:
    default:
      return CAPTCHA_LANGUAGE_KO;
  }
}

static captcha_language_t session_captcha_primary_language(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return CAPTCHA_LANGUAGE_KO;
  }

  session_ui_language_t preferred = session_ui_language_current(ctx);
  captcha_language_t preferred_language = session_captcha_language_from_ui(preferred);
  if (preferred != SESSION_UI_LANGUAGE_KO || preferred_language != CAPTCHA_LANGUAGE_KO) {
    return preferred_language;
  }

  session_ui_language_t geo_language = session_client_geo_language(ctx);
  if (geo_language != SESSION_UI_LANGUAGE_COUNT) {
      return session_captcha_language_from_ui(geo_language);
  }

  char label[64];
  if (session_detect_provider_ip(ctx->client_ip, label, sizeof(label))) {
    if (string_contains_case_insensitive(label, "Chinese")) {
      return CAPTCHA_LANGUAGE_ZH;
    }
    if (string_contains_case_insensitive(label, "Russian")) {
      return CAPTCHA_LANGUAGE_RU;
    }
    if (string_contains_case_insensitive(label, "Korean")) {
      return CAPTCHA_LANGUAGE_KO;
    }
  }

  return CAPTCHA_LANGUAGE_EN;
}

static bool session_captcha_add_language(captcha_language_t *order, size_t capacity, size_t *count, bool used[],
                                         captcha_language_t language) {
  if (order == NULL || count == NULL || used == NULL) {
    return false;
  }

  size_t index = (size_t)language;
  if (index >= CAPTCHA_LANGUAGE_COUNT) {
    return false;
  }

  if (used[index] || *count >= capacity) {
    return false;
  }

  order[*count] = language;
  used[index] = true;
  ++(*count);
  return true;
}

static size_t session_collect_captcha_languages(const session_ctx_t *ctx, captcha_language_t *order, size_t capacity) {
  if (order == NULL || capacity == 0U) {
    return 0U;
  }

  bool used[CAPTCHA_LANGUAGE_COUNT] = {false};
  size_t count = 0U;

  captcha_language_t primary = session_captcha_primary_language(ctx);
  session_captcha_add_language(order, capacity, &count, used, primary);

  if (ctx != NULL) {
    captcha_language_t user_pref = session_captcha_language_from_ui(session_ui_language_current(ctx));
    session_captcha_add_language(order, capacity, &count, used, user_pref);

    char label[64];
    if (session_detect_provider_ip(ctx->client_ip, label, sizeof(label))) {
      if (string_contains_case_insensitive(label, "Chinese")) {
        session_captcha_add_language(order, capacity, &count, used, CAPTCHA_LANGUAGE_ZH);
      }
      if (string_contains_case_insensitive(label, "Russian")) {
        session_captcha_add_language(order, capacity, &count, used, CAPTCHA_LANGUAGE_RU);
      }
      if (string_contains_case_insensitive(label, "Korean")) {
        session_captcha_add_language(order, capacity, &count, used, CAPTCHA_LANGUAGE_KO);
      }
    }
  }

  session_captcha_add_language(order, capacity, &count, used, CAPTCHA_LANGUAGE_EN);
  session_captcha_add_language(order, capacity, &count, used, CAPTCHA_LANGUAGE_KO);

  static const captcha_language_t kFallbackOrder[] = {
      CAPTCHA_LANGUAGE_ZH,
      CAPTCHA_LANGUAGE_RU,
      CAPTCHA_LANGUAGE_EN,
      CAPTCHA_LANGUAGE_KO,
  };

  for (size_t idx = 0U; idx < sizeof(kFallbackOrder) / sizeof(kFallbackOrder[0]); ++idx) {
    session_captcha_add_language(order, capacity, &count, used, kFallbackOrder[idx]);
  }

  return count;
}

static void session_send_captcha_prompt(session_ctx_t *ctx, const captcha_prompt_t *prompt,
                                        const captcha_language_t *order, size_t count) {
  if (ctx == NULL || prompt == NULL || order == NULL || count == 0U) {
    return;
  }

  for (size_t idx = 0U; idx < count; ++idx) {
    captcha_language_t language = order[idx];
    const char *label = session_captcha_label_for_language(language);
    const char *question = session_captcha_question_for_language(prompt, language);
    if (label == NULL || question == NULL || question[0] == '\0') {
      continue;
    }

    char line[sizeof(prompt->question_en) + 32];
    int written = snprintf(line, sizeof(line), "%s%s", label, question);
    if (written <= 0) {
      continue;
    }

    session_send_system_line(ctx, line);
  }
}

static void host_update_last_captcha_prompt(host_t *host, const captcha_prompt_t *prompt,
                                            const captcha_language_t *order, size_t count) {
  if (host == NULL || prompt == NULL) {
    return;
  }

  static const captcha_language_t kDefaultOrder[] = {
      CAPTCHA_LANGUAGE_KO,
      CAPTCHA_LANGUAGE_EN,
      CAPTCHA_LANGUAGE_ZH,
      CAPTCHA_LANGUAGE_RU,
  };

  const captcha_language_t *languages = order;
  size_t language_count = count;
  if (languages == NULL || language_count == 0U) {
    languages = kDefaultOrder;
    language_count = sizeof(kDefaultOrder) / sizeof(kDefaultOrder[0]);
  }

  char combined_question[sizeof(prompt->question_en) + sizeof(prompt->question_ko) + sizeof(prompt->question_ru) +
                         sizeof(prompt->question_zh) + 64];
  combined_question[0] = '\0';
  size_t combined_length = 0U;

  for (size_t idx = 0U; idx < language_count; ++idx) {
    const char *label = session_captcha_label_for_language(languages[idx]);
    const char *question = session_captcha_question_for_language(prompt, languages[idx]);
    if (label == NULL || question == NULL || question[0] == '\0') {
      continue;
    }

    char line[sizeof(prompt->question_en) + 32];
    int written = snprintf(line, sizeof(line), "%s%s", label, question);
    if (written <= 0) {
      continue;
    }

    size_t line_length = (size_t)written;
    if (combined_length > 0U && combined_length + 1U < sizeof(combined_question)) {
      combined_question[combined_length++] = '\n';
    }

    if (combined_length >= sizeof(combined_question)) {
      break;
    }

    size_t available = sizeof(combined_question) - combined_length;
    if (available == 0U) {
      break;
    }

    if (line_length >= available) {
      line_length = available - 1U;
    }

    memcpy(combined_question + combined_length, line, line_length);
    combined_length += line_length;
    combined_question[combined_length] = '\0';
  }

  pthread_mutex_lock(&host->lock);
  snprintf(host->last_captcha_question, sizeof(host->last_captcha_question), "%s", combined_question);
  snprintf(host->last_captcha_answer, sizeof(host->last_captcha_answer), "%s", prompt->answer);
  host->has_last_captcha = host->last_captcha_question[0] != '\0' && host->last_captcha_answer[0] != '\0';
  if (host->has_last_captcha) {
    if (clock_gettime(CLOCK_REALTIME, &host->last_captcha_generated) != 0) {
      host->last_captcha_generated.tv_sec = time(NULL);
      host->last_captcha_generated.tv_nsec = 0L;
    }
  } else {
    host->last_captcha_generated.tv_sec = 0;
    host->last_captcha_generated.tv_nsec = 0L;
  }
  pthread_mutex_unlock(&host->lock);
}

static bool session_run_captcha(session_ctx_t *ctx) {
  if (ctx == NULL || !session_transport_active(ctx)) {
    return false;
  }

  captcha_prompt_t prompt;
  session_build_captcha_prompt(ctx, &prompt);
  captcha_language_t languages[CAPTCHA_LANGUAGE_COUNT];
  size_t language_count = session_collect_captcha_languages(ctx, languages,
                                                            sizeof(languages) / sizeof(languages[0]));
  if (language_count == 0U) {
    languages[0] = CAPTCHA_LANGUAGE_KO;
    language_count = 1U;
  }

  host_update_last_captcha_prompt(ctx->owner, &prompt, languages, language_count);

  bool include_chinese = false;
  for (size_t idx = 0U; idx < language_count; ++idx) {
    if (languages[idx] == CAPTCHA_LANGUAGE_ZH) {
      include_chinese = true;
      break;
    }
  }

  session_send_system_line(ctx, "For Windows users: CHANGE TERMINAL ENCODING TO UTF-8");
  if (include_chinese) {
    session_send_system_line(ctx,
                             "INFO: Chinese question is in Traditional one to cover regions those are NOT Mainland China.");
  }
  session_send_system_line(ctx, "Before entering the room, solve this small puzzle.");
  session_send_captcha_prompt(ctx, &prompt, languages, language_count);
  session_send_system_line(ctx, "Type your answer and press Enter:");

  char answer[sizeof(prompt.answer)];
  size_t length = 0U;
  while (length + 1U < sizeof(answer)) {
    char ch = '\0';
    const int read_result = session_transport_read(ctx, &ch, 1, -1);
    if (read_result <= 0) {
      return false;
    }

    if (ch == '\r' || ch == '\n') {
      session_local_echo_char(ctx, '\n');
      break;
    }

    if (ch == '\b' || (unsigned char)ch == 0x7fU) {
      if (length > 0U) {
        --length;
        session_send_raw_text(ctx, "\b \b");
      }
      continue;
    }

    if ((unsigned char)ch < 0x20U) {
      continue;
    }

    answer[length++] = ch;
    session_local_echo_char(ctx, ch);
  }
  answer[length] = '\0';
  trim_whitespace_inplace(answer);

  if (answer[0] == '\0') {
    session_send_system_line(ctx, "Captcha answer missing. Disconnecting.");
    return false;
  }

  if (strcasecmp(prompt.answer, "dog") == 0 && strcmp(answer, "개") == 0) {
    snprintf(answer, sizeof(answer), "%s", "dog");
  }

  if (strcasecmp(answer, prompt.answer) == 0) {
    session_send_system_line(ctx, "Captcha solved. Welcome aboard!");
    return true;
  }

  session_send_system_line(ctx, "Captcha failed. Disconnecting.");
  return false;
}

static bool session_is_captcha_exempt(const session_ctx_t *ctx) {
  if (ctx == NULL) {
    return false;
  }

  if (ctx->user.name[0] == '\0') {
    return false;
  }

  char lowered[sizeof(ctx->user.name)];
  size_t idx = 0U;
  for (; idx + 1U < sizeof(lowered) && ctx->user.name[idx] != '\0'; ++idx) {
    lowered[idx] = (char)tolower((unsigned char)ctx->user.name[idx]);
  }
  if (idx < sizeof(lowered)) {
    lowered[idx] = '\0';
  } else {
    lowered[sizeof(lowered) - 1U] = '\0';
  }

  return strcmp(lowered, "gpt") == 0;
}

static void session_print_help(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  const session_ui_locale_t *locale = session_ui_get_locale(ctx);
  const char *prefix = session_command_prefix(ctx);

  if (locale->help_title != NULL && locale->help_title[0] != '\0') {
    session_send_system_line(ctx, locale->help_title);
  }

  session_help_send_entries(ctx, kSessionHelpEssential,
                            sizeof(kSessionHelpEssential) / sizeof(kSessionHelpEssential[0]));

  session_send_system_line(ctx, "");

  if (locale->help_hint_extra != NULL && locale->help_hint_extra[0] != '\0') {
    const char *args[] = {prefix};
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    session_format_template(locale->help_hint_extra, args, sizeof(args) / sizeof(args[0]), line, sizeof(line));
    session_send_system_line(ctx, line);
  }

  if (locale->help_scroll_hint != NULL && locale->help_scroll_hint[0] != '\0') {
    session_send_system_line(ctx, locale->help_scroll_hint);
  }

  if (locale->help_regular_hint != NULL && locale->help_regular_hint[0] != '\0') {
    session_send_system_line(ctx, locale->help_regular_hint);
  }
}

static void session_print_help_extra(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  const session_ui_locale_t *locale = session_ui_get_locale(ctx);
  const char *prefix = session_command_prefix(ctx);

  if (locale->help_extra_title != NULL && locale->help_extra_title[0] != '\0') {
    session_send_system_line(ctx, locale->help_extra_title);
  }

  session_help_send_entries(ctx, kSessionHelpExtended,
                            sizeof(kSessionHelpExtended) / sizeof(kSessionHelpExtended[0]));

  session_send_system_line(ctx, "");

  if (locale->help_extra_hint != NULL && locale->help_extra_hint[0] != '\0') {
    const char *args[] = {prefix};
    char line[SSH_CHATTER_MESSAGE_LIMIT];
    session_format_template(locale->help_extra_hint, args, sizeof(args) / sizeof(args[0]), line, sizeof(line));
    session_send_system_line(ctx, line);
  }

  if (ctx->user.is_operator || ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "");
    if (locale->help_operator_title != NULL && locale->help_operator_title[0] != '\0') {
      session_send_system_line(ctx, locale->help_operator_title);
    }
    session_help_send_entries(ctx, kSessionHelpOperator,
                              sizeof(kSessionHelpOperator) / sizeof(kSessionHelpOperator[0]));
  }
}

static bool session_line_is_exit_command(const char *line) {
  if (line == NULL) {
    return false;
  }

  if (strncmp(line, "/exit", 5) != 0) {
    return false;
  }

  const char trailing = line[5];
  if (trailing == '\0') {
    return true;
  }

  if (!isspace((unsigned char)trailing)) {
    return false;
  }

  for (size_t idx = 6U; line[idx] != '\0'; ++idx) {
    if (!isspace((unsigned char)line[idx])) {
      return false;
    }
  }

  return true;
}

static void session_handle_username_conflict_input(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL) {
    return;
  }

  if (session_line_is_exit_command(line)) {
    ctx->ops->handle_exit(ctx);
    return;
  }

  char reminder[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(reminder, sizeof(reminder), "The username '%s' is already in use.", ctx->user.name);
  session_send_system_line(ctx, reminder);
  session_send_system_line(ctx,
                           "Reconnect with a different username by running: ssh newname@<server> (or ssh -l newname <server>)");
  session_send_system_line(ctx, "Type /exit to quit.");
}

static void session_process_line(session_ctx_t *ctx, const char *line) {
  if (ctx == NULL || line == NULL) {
    return;
  }

  char normalized[SSH_CHATTER_MAX_INPUT_LEN];
  snprintf(normalized, sizeof(normalized), "%s", line);
  session_normalize_newlines(normalized);

  if (ctx->bbs_post_pending) {
    session_bbs_capture_body_text(ctx, normalized);
    return;
  }

  if (ctx->asciiart_pending) {
    session_asciiart_capture_text(ctx, normalized);
    return;
  }

  if (normalized[0] == '\0') {
    return;
  }

  if (ctx->game.active) {
    if (strcmp(normalized, "/suspend!") == 0) {
      session_game_suspend(ctx, "Game suspended.");
      return;
    }

    if (normalized[0] == '/') {
      session_send_system_line(ctx, "Finish the current game with /suspend! first.");
      return;
    }

    if (ctx->game.type == SESSION_GAME_TETRIS) {
      session_game_tetris_handle_line(ctx, normalized);
    } else if (ctx->game.type == SESSION_GAME_LIARGAME) {
      session_game_liar_handle_line(ctx, normalized);
    } else if (ctx->game.type == SESSION_GAME_ALPHA) {
      session_game_alpha_handle_line(ctx, normalized);
    }
    return;
  }

  if (ctx->in_rss_mode) {
    if (strcmp(normalized, "/exit") == 0) {
      session_rss_exit(ctx, NULL);
    } else {
      const char *rss_args = NULL;
      if (session_parse_command(normalized, "/rss", &rss_args)) {
        session_rss_exit(ctx, NULL);
        session_handle_rss(ctx, rss_args);
      } else {
        session_send_system_line(ctx, "RSS reader active. Use /rss exit Ctrl+Z, or Terminate to return to chat.");
      }
    }
    return;
  }

  bool translation_bypass = false;
  char bypass_buffer[SSH_CHATTER_MAX_INPUT_LEN];
  if (translation_strip_no_translate_prefix(normalized, bypass_buffer, sizeof(bypass_buffer))) {
    translation_bypass = true;
    snprintf(normalized, sizeof(normalized), "%s", bypass_buffer);
  }

  if (normalized[0] == '\0') {
    return;
  }

  printf("[%s] %s\n", ctx->user.name, normalized);

  const struct timespec tiny_delay = {.tv_sec = 0, .tv_nsec = 5000000L};
  host_sleep_uninterruptible(&tiny_delay);

  if (ctx->username_conflict) {
    session_handle_username_conflict_input(ctx, normalized);
    return;
  }

  if (!translation_bypass && normalized[0] == '/') {
    if (session_try_localized_command_forward(ctx, normalized)) {
      return;
    }
    ctx->ops->dispatch_command(ctx, normalized);
    return;
  }

  const char *trimmed = normalized;
  while (*trimmed == ' ' || *trimmed == '\t') {
    ++trimmed;
  }

  if (!translation_bypass && ctx->input_mode == SESSION_INPUT_MODE_COMMAND && *trimmed != '\0') {
    const char *command_text = trimmed;
    char command_buffer[SSH_CHATTER_MAX_INPUT_LEN];
    if (command_text[0] != '/') {
      command_buffer[0] = '/';
      size_t command_len = strnlen(command_text, sizeof(command_buffer) - 2U);
      memcpy(&command_buffer[1], command_text, command_len);
      command_buffer[command_len + 1U] = '\0';
      command_text = command_buffer;
    }
    ctx->ops->dispatch_command(ctx, command_text);
    return;
  }

  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    now.tv_sec = time(NULL);
    now.tv_nsec = 0L;
  }

  const bool asciiart_active = ctx->asciiart_pending;
  bool ascii_profile_command = asciiart_active;
  if (!ascii_profile_command && normalized[0] == '/') {
    const char *command_args = NULL;
    if (session_parse_command(normalized, "/asciiart", &command_args) ||
        session_parse_command(normalized, "/profilepic", &command_args)) {
      ascii_profile_command = true;
    }
  }

  const bool translation_throttle =
      ctx->translation_enabled && ctx->input_translation_enabled && ctx->input_translation_language[0] != '\0';
  const bool chat_throttle = ctx->input_mode == SESSION_INPUT_MODE_CHAT;
  if ((translation_throttle || chat_throttle) && ctx->has_last_message_time) {
    time_t sec_delta = now.tv_sec - ctx->last_message_time.tv_sec;
    long nsec_delta = now.tv_nsec - ctx->last_message_time.tv_nsec;
    if (nsec_delta < 0L) {
      --sec_delta;
      nsec_delta += 1000000000L;
    }
    if (translation_throttle && (sec_delta < 0 || (sec_delta == 0 && nsec_delta < 1000000000L))) {
      session_send_system_line(ctx, "Please wait at least one second before sending another message.");
      return;
    }
    if (!translation_throttle && chat_throttle && !ascii_profile_command && !ctx->bracket_paste_active &&
        (sec_delta < 0 || (sec_delta == 0 && nsec_delta < 300000000L))) {
      session_send_system_line(ctx, "Please wait at least 300 milliseconds before sending another chat message.");
      return;
    }
  }

  ctx->last_message_time = now;
  ctx->has_last_message_time = true;

  if (!translation_bypass && ctx->translation_enabled && ctx->input_translation_enabled &&
      ctx->input_translation_language[0] != '\0') {
    if (session_translation_queue_input(ctx, normalized)) {
      return;
    }
    session_send_system_line(ctx, "Translation unavailable; sending your original message.");
  }

  session_deliver_outgoing_message(ctx, normalized, true);
}

static void session_handle_kick(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to kick users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /kick <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /kick <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", target_name);
    session_send_system_line(ctx, message);
    return;
  }

  if (target == ctx) {
    session_send_system_line(ctx, "You cannot kick yourself.");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [%s] has been kicked by [%s]", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);

  const bool target_active = session_transport_active(target);
  if (!target_active || (target->transport_kind == SESSION_TRANSPORT_SSH && target->session == NULL)) {
    target->should_exit = true;
    target->has_joined_room = false;
    chat_room_remove(&ctx->owner->room, target);
    session_send_system_line(ctx, "User removed from the chat.");
  } else {
    session_send_system_line(target, "You have been kicked by an operator.");
    target->should_exit = true;
    session_transport_request_close(target);
    target->has_joined_room = false;
    chat_room_remove(&ctx->owner->room, target);
    session_send_system_line(ctx, "User removed from the chat.");
  }

  printf("[kick] %s kicked %s\n", ctx->user.name, target->user.name);
}

static void session_handle_ban_name(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to ban nicknames.");
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Host unavailable.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /banname <nickname>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /banname <nickname>");
    return;
  }

  for (size_t idx = 0U; target_name[idx] != '\0'; ++idx) {
    const unsigned char ch = (unsigned char)target_name[idx];
    if (ch <= 0x1FU || ch == 0x7FU || ch == ' ' || ch == '\t') {
      session_send_system_line(ctx, "Nicknames may not include control characters or whitespace.");
      return;
    }
  }

  if (host_is_username_banned(ctx->owner, target_name)) {
    session_send_system_line(ctx, "That nickname is already blocked for bot detection.");
    return;
  }

  if (!host_add_ban_entry(ctx->owner, target_name, "")) {
    session_send_system_line(ctx, "Unable to add ban entry (list full?).");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* Nickname '%s' blocked for bot detection by [%s]", target_name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
  session_send_system_line(ctx, "Nickname ban applied.");
  printf("[banname] %s banned nickname %s\n", ctx->user.name, target_name);

  session_ctx_t *active = chat_room_find_user(&ctx->owner->room, target_name);
  if (active != NULL) {
    session_send_system_line(active,
                             "Your nickname is now blocked for bot detection. Use /nick <name> to change immediately.");
  }
}

static void session_handle_ban(session_ctx_t *ctx, const char *arguments) {
  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to ban users.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /ban <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  if (target == NULL) {
    bool valid_ip = false;
    unsigned char inet_buffer[sizeof(struct in6_addr)];
    if (inet_pton(AF_INET, target_name, inet_buffer) == 1 ||
        inet_pton(AF_INET6, target_name, inet_buffer) == 1) {
      valid_ip = true;
    }

    bool valid_cidr = false;
    if (!valid_ip && strchr(target_name, '/') != NULL) {
      uint32_t ipv4_network = 0U;
      uint32_t ipv4_mask = 0U;
      struct in6_addr ipv6_network;
      struct in6_addr ipv6_mask;
      memset(&ipv6_network, 0, sizeof(ipv6_network));
      memset(&ipv6_mask, 0, sizeof(ipv6_mask));
      valid_cidr =
          host_parse_ipv4_cidr(target_name, &ipv4_network, &ipv4_mask) ||
          host_parse_ipv6_cidr(target_name, &ipv6_network, &ipv6_mask);
    }

    if (valid_ip || valid_cidr) {
      if (host_add_ban_entry(ctx->owner, "", target_name)) {
        char notice[SSH_CHATTER_MESSAGE_LIMIT];
        const char *label = valid_cidr ? "CIDR" : "IP";
        snprintf(notice, sizeof(notice), "%s '%s' has been banned.", label, target_name);
        session_send_system_line(ctx, notice);
      } else {
        session_send_system_line(ctx, "Unable to add ban entry (list full?).");
      }
    } else {
      char not_found[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
      session_send_system_line(ctx, not_found);
    }
    return;
  }

  if (target->user.is_lan_operator) {
    session_send_system_line(ctx, "LAN operators cannot be banned.");
    return;
  }

  const char *target_ip = target->client_ip[0] != '\0' ? target->client_ip : "";
  if (!host_add_ban_entry(ctx->owner, target->user.name, target_ip)) {
    session_send_system_line(ctx, "Unable to add ban entry (list full?).");
    return;
  }

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "* [%s] has been banned by [%s]", target->user.name, ctx->user.name);
  host_history_record_system(ctx->owner, notice);
  chat_room_broadcast(&ctx->owner->room, notice, NULL);
  session_send_system_line(ctx, "Ban applied.");
  printf("[ban] %s banned %s (%s)\n", ctx->user.name, target->user.name, target_ip[0] != '\0' ? target_ip : "unknown");

  if (session_transport_active(target)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "You have been banned by [%s].", ctx->user.name);
    session_send_system_line(target, message);
    target->should_exit = true;
    session_transport_request_close(target);
  }
}

static void session_handle_ban_list(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->user.is_operator) {
    session_send_system_line(ctx, "You are not allowed to view the ban list.");
    return;
  }

  if (arguments != NULL) {
    while (*arguments != '\0' && isspace((unsigned char)*arguments)) {
      ++arguments;
    }
    if (*arguments != '\0') {
      session_send_system_line(ctx, "Usage: /banlist");
      return;
    }
  }

  host_t *host = ctx->owner;
  if (host == NULL) {
    session_send_system_line(ctx, "Host unavailable.");
    return;
  }

  typedef struct ban_snapshot {
    char username[SSH_CHATTER_USERNAME_LEN];
    char ip[SSH_CHATTER_IP_LEN];
  } ban_snapshot_t;

  ban_snapshot_t entries[SSH_CHATTER_MAX_BANS];
  size_t entry_count = 0U;

  pthread_mutex_lock(&host->lock);
  entry_count = host->ban_count;
  if (entry_count > SSH_CHATTER_MAX_BANS) {
    entry_count = SSH_CHATTER_MAX_BANS;
  }
  for (size_t idx = 0U; idx < entry_count; ++idx) {
    snprintf(entries[idx].username, sizeof(entries[idx].username), "%s", host->bans[idx].username);
    snprintf(entries[idx].ip, sizeof(entries[idx].ip), "%s", host->bans[idx].ip);
  }
  pthread_mutex_unlock(&host->lock);

  if (entry_count == 0U) {
    session_send_system_line(ctx, "No active bans.");
    return;
  }

  session_send_system_line(ctx, "Active bans:");
  for (size_t idx = 0U; idx < entry_count; ++idx) {
    const char *username = entries[idx].username;
    const char *ip = entries[idx].ip;
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    if (username[0] != '\0' && ip[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. user: %s, ip: %s", idx + 1U, username, ip);
    } else if (username[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. user: %s", idx + 1U, username);
    } else if (ip[0] != '\0') {
      snprintf(message, sizeof(message), "%zu. ip: %s", idx + 1U, ip);
    } else {
      snprintf(message, sizeof(message), "%zu. <empty>", idx + 1U);
    }
    session_send_system_line(ctx, message);
  }
}

static void session_handle_getaddr(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (!ctx->user.is_operator && !ctx->user.is_lan_operator) {
    session_send_system_line(ctx, "You are not allowed to run that command.");
    return;
  }

  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /getaddr <username>");
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%s", arguments);
  trim_whitespace_inplace(target_name);

  if (target_name[0] == '\0') {
    session_send_system_line(ctx, "Usage: /getaddr <username>");
    return;
  }

  host_t *host = ctx->owner;
  if (host == NULL) {
    session_send_system_line(ctx, "Host unavailable.");
    return;
  }

  char ip[SSH_CHATTER_IP_LEN];
  if (!host_lookup_last_ip(host, target_name, ip, sizeof(ip)) || ip[0] == '\0') {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No recorded address for '%s'.", target_name);
    session_send_system_line(ctx, message);
    return;
  }

  char message[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(message, sizeof(message), "Last known address for '%s': %s", target_name, ip);
  session_send_system_line(ctx, message);
}

static void session_handle_poke(session_ctx_t *ctx, const char *arguments) {
  if (arguments == NULL || *arguments == '\0') {
    session_send_system_line(ctx, "Usage: /poke <username>");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, arguments);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%s' is not connected.", arguments);
    session_send_system_line(ctx, message);
    return;
  }

  printf("[poke] %s pokes %s\n", ctx->user.name, target->user.name);
  session_channel_write(target, "\a", 1U);
  session_send_system_line(ctx, "Poke sent.");
}

static void session_handle_block(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /block <username|ip|list|confirm <username> <only|ip>>";

  char usage[SSH_CHATTER_MESSAGE_LIMIT];
  session_command_format_usage(ctx, "/block", kUsage, usage, sizeof(usage));

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  if (strcasecmp(working, "list") == 0) {
    session_blocklist_show(ctx);
    return;
  }

  if (strncasecmp(working, "confirm", 7) == 0 &&
      (working[7] == '\0' || isspace((unsigned char)working[7]))) {
    char *cursor = working + 7;
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
      ++cursor;
    }

    if (*cursor == '\0') {
      session_send_system_line(ctx, usage);
      return;
    }

    char username[SSH_CHATTER_USERNAME_LEN];
    size_t name_len = 0U;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor) && name_len + 1U < sizeof(username)) {
      username[name_len++] = *cursor++;
    }
    username[name_len] = '\0';

    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
      ++cursor;
    }

    if (*cursor == '\0') {
      session_send_system_line(ctx, usage);
      return;
    }

    char mode[16];
    size_t mode_len = 0U;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor) && mode_len + 1U < sizeof(mode)) {
      mode[mode_len++] = *cursor++;
    }
    mode[mode_len] = '\0';

    if (!ctx->block_pending.active) {
      session_send_system_line(ctx, "No provider block is awaiting confirmation.");
      return;
    }

    if (strncmp(ctx->block_pending.username, username, SSH_CHATTER_USERNAME_LEN) != 0) {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Pending block is for [%s], not [%s].", ctx->block_pending.username, username);
      session_send_system_line(ctx, message);
      return;
    }

    bool block_ip = false;
    if (strcasecmp(mode, "ip") == 0 || strcasecmp(mode, "all") == 0 || strcasecmp(mode, "full") == 0) {
      block_ip = true;
    } else if (strcasecmp(mode, "only") == 0 || strcasecmp(mode, "user") == 0 || strcasecmp(mode, "name") == 0) {
      block_ip = false;
    } else {
      session_send_system_line(ctx, usage);
      return;
    }

    bool already_present = false;
    if (!session_blocklist_add(ctx, ctx->block_pending.ip, ctx->block_pending.username, block_ip, &already_present)) {
      if (already_present) {
        session_send_system_line(ctx, "That target is already blocked.");
      } else {
        session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
      }
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      if (block_ip) {
        snprintf(message, sizeof(message), "Blocking all users from %.63s.", ctx->block_pending.ip);
      } else {
        snprintf(message, sizeof(message), "Blocking [%.23s] only (IP %.63s).", ctx->block_pending.username,
                 ctx->block_pending.ip);
      }
      session_send_system_line(ctx, message);
    }

    ctx->block_pending.active = false;
    ctx->block_pending.username[0] = '\0';
    ctx->block_pending.ip[0] = '\0';
    ctx->block_pending.provider_label[0] = '\0';
    return;
  }

  unsigned char inet_buffer[sizeof(struct in6_addr)];
  if (inet_pton(AF_INET, working, inet_buffer) == 1 || inet_pton(AF_INET6, working, inet_buffer) == 1) {
    bool already_present = false;
    char label[64];
    bool provider = session_detect_provider_ip(working, label, sizeof(label));
    if (provider && label[0] != '\0') {
      char warning[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(warning, sizeof(warning),
               "Error: You cannot ban a country."
               "%.256s is flagged as %.63s; other people may also be hidden.", working, label);
      session_send_system_line(ctx, warning);
      return;
    }
    if (!session_blocklist_add(ctx, working, "", true, &already_present)) {
      if (already_present) {
        session_send_system_line(ctx, "That IP is already blocked.");
      } else {
        session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
      }
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Blocking all users from %.256s.", working);
      session_send_system_line(ctx, message);
    }
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Block list unavailable right now.");
    return;
  }

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, working);
  if (target == NULL) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "User '%.256s' is not connected.", working);
    session_send_system_line(ctx, message);
    return;
  }

  if (target == ctx) {
    session_send_system_line(ctx, "You do not need to block yourself.");
    return;
  }

  if (target->client_ip[0] == '\0') {
    session_send_system_line(ctx, "Unable to identify that user's IP address right now.");
    return;
  }

  char label[64];
  if (session_detect_provider_ip(target->client_ip, label, sizeof(label))) {
    memset(&ctx->block_pending, 0, sizeof(ctx->block_pending));
    ctx->block_pending.active = true;
    snprintf(ctx->block_pending.username, sizeof(ctx->block_pending.username), "%s", target->user.name);
    snprintf(ctx->block_pending.ip, sizeof(ctx->block_pending.ip), "%s", target->client_ip);
    snprintf(ctx->block_pending.provider_label, sizeof(ctx->block_pending.provider_label), "%.31s", label);

    char warning[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(warning, sizeof(warning), "%.63s appears to belong to %.63s.", target->client_ip, label);
    session_send_system_line(ctx, warning);

    char prompt[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(prompt, sizeof(prompt),
             "Use /block confirm %.23s only to hide just [%.23s] or /block confirm %.23s ip to hide everyone from that IP.",
             target->user.name, target->user.name, target->user.name);
    session_send_system_line(ctx, prompt);
    return;
  }

  bool already_present = false;
  if (!session_blocklist_add(ctx, target->client_ip, target->user.name, true, &already_present)) {
    if (already_present) {
      session_send_system_line(ctx, "That address is already blocked.");
    } else {
      session_send_system_line(ctx, "Unable to add block entry (limit reached?).");
    }
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Blocking all users from %.63s (triggered by [%.23s]).", target->client_ip,
             target->user.name);
    session_send_system_line(ctx, message);
  }
}

static void session_handle_unblock(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /unblock <username|ip|all>";

  char usage[SSH_CHATTER_MESSAGE_LIMIT];
  session_command_format_usage(ctx, "/unblock", kUsage, usage, sizeof(usage));

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  if (strcasecmp(working, "all") == 0) {
    size_t removed = 0U;
    for (size_t idx = 0U; idx < SSH_CHATTER_MAX_BLOCKED; ++idx) {
      if (ctx->block_entries[idx].in_use) {
        memset(&ctx->block_entries[idx], 0, sizeof(ctx->block_entries[idx]));
        ++removed;
      }
    }
    ctx->block_entry_count = 0U;
    ctx->block_pending.active = false;
    ctx->block_pending.username[0] = '\0';
    ctx->block_pending.ip[0] = '\0';
    ctx->block_pending.provider_label[0] = '\0';

    if (removed == 0U) {
      session_send_system_line(ctx, "No blocked entries to remove.");
    } else {
      char message[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(message, sizeof(message), "Removed %zu blocked entr%s.", removed, removed == 1U ? "y" : "ies");
      session_send_system_line(ctx, message);
    }
    return;
  }

  if (session_blocklist_remove(ctx, working)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Removed block for %.256s.", working);
    session_send_system_line(ctx, message);
  } else {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "No block entry matched '%.256s'.", working);
    session_send_system_line(ctx, message);
  }
}

static void session_handle_pm(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  static const char *kUsage = "Usage: /pm <username> <message>";

  char usage[SSH_CHATTER_MESSAGE_LIMIT];
  session_command_format_usage(ctx, "/pm", kUsage, usage, sizeof(usage));

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Private messages are unavailable right now.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *cursor = working;
  while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
    ++cursor;
  }

  if (*cursor == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  *cursor = '\0';
  char *message = cursor + 1;
  while (*message != '\0' && isspace((unsigned char)*message)) {
    ++message;
  }

  if (*message == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char target_name[SSH_CHATTER_USERNAME_LEN];
  snprintf(target_name, sizeof(target_name), "%.*s", (int)sizeof(target_name) - 1, working);

  session_ctx_t *target = chat_room_find_user(&ctx->owner->room, target_name);
  const bool target_is_eliza = strcasecmp(target_name, "eliza") == 0;
  const bool eliza_active = target_is_eliza && atomic_load(&ctx->owner->eliza_enabled);

  if (target == NULL) {
    if (target_is_eliza) {
      if (!eliza_active) {
        session_send_system_line(ctx, "eliza isn't around right now.");
        return;
      }
      session_send_system_line(ctx, "Connecting you with eliza...");
    } else {
      char not_found[SSH_CHATTER_MESSAGE_LIMIT];
      snprintf(not_found, sizeof(not_found), "User '%s' is not connected.", target_name);
      session_send_system_line(ctx, not_found);
      return;
    }
  }

  char prepared[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(prepared, sizeof(prepared), "%s", message);

  char stripped[SSH_CHATTER_MESSAGE_LIMIT];
  bool translation_bypass = translation_strip_no_translate_prefix(prepared, stripped, sizeof(stripped));
  const char *deliver_body = translation_bypass ? stripped : prepared;

  const char *target_display = target != NULL ? target->user.name : target_name;
  printf("[pm] %s -> %s: %s\n", ctx->user.name, target_display, deliver_body);

  char to_target_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_target_label, sizeof(to_target_label), "%s -> you", ctx->user.name);

  char to_sender_label[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(to_sender_label, sizeof(to_sender_label), "you -> %s", target_display);

  bool attempt_translation = (target != NULL) && !translation_bypass && ctx->translation_enabled &&
                             ctx->input_translation_enabled && ctx->input_translation_language[0] != '\0';

  if (attempt_translation) {
    if (session_translation_queue_private_message(ctx, target, deliver_body)) {
      return;
    }
    session_send_system_line(ctx, "Translation unavailable; sending your original message.");
  }

  if (target != NULL) {
    session_send_private_message_line(target, ctx, to_target_label, deliver_body);
    session_send_private_message_line(ctx, ctx, to_sender_label, deliver_body);
    return;
  }

  session_send_private_message_line(ctx, ctx, to_sender_label, deliver_body);
  host_eliza_handle_private_message(ctx, deliver_body);
}

static bool username_contains(const char *username, const char *needle) {
  if (username == NULL || needle == NULL) {
    return false;
  }

  const size_t needle_len = strlen(needle);
  if (needle_len == 0U) {
    return false;
  }

  const size_t name_len = strlen(username);
  if (needle_len > name_len) {
    return false;
  }

  for (size_t offset = 0U; offset + needle_len <= name_len; ++offset) {
    bool match = true;
    for (size_t idx = 0U; idx < needle_len; ++idx) {
      const unsigned char user_ch = (unsigned char)username[offset + idx];
      const unsigned char needle_ch = (unsigned char)needle[idx];
      if (tolower(user_ch) != tolower(needle_ch)) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }

  return false;
}

static void session_handle_search(session_ctx_t *ctx, const char *arguments) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->owner == NULL) {
    session_send_system_line(ctx, "Search is unavailable at the moment.");
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char query[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(query, sizeof(query), "%s", arguments);
  trim_whitespace_inplace(query);

  if (query[0] == '\0') {
    session_send_system_line(ctx, "Usage: /search <text>");
    return;
  }

  char listing[SSH_CHATTER_MESSAGE_LIMIT];
  listing[0] = '\0';
  size_t match_count = 0U;

  pthread_mutex_lock(&ctx->owner->room.lock);
  for (size_t idx = 0U; idx < ctx->owner->room.member_count; ++idx) {
    session_ctx_t *member = ctx->owner->room.members[idx];
    if (member == NULL) {
      continue;
    }
    if (!username_contains(member->user.name, query)) {
      continue;
    }

    char name[SSH_CHATTER_USERNAME_LEN];
    snprintf(name, sizeof(name), "%s", member->user.name);
    size_t current_len = strnlen(listing, sizeof(listing));
    size_t name_len = strnlen(name, sizeof(name));
    size_t prefix_len = (match_count == 0U) ? 0U : 2U;

    if (current_len + prefix_len + name_len >= sizeof(listing)) {
      continue;
    }

    if (match_count > 0U) {
      listing[current_len++] = ',';
      listing[current_len++] = ' ';
    }
    memcpy(listing + current_len, name, name_len);
    listing[current_len + name_len] = '\0';
    ++match_count;
  }
  pthread_mutex_unlock(&ctx->owner->room.lock);

  if (match_count == 0U) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    char display_query[64];
    size_t copy_len = strnlen(query, sizeof(display_query) - 1U);
    memcpy(display_query, query, copy_len);
    display_query[copy_len] = '\0';
    snprintf(message, sizeof(message), "No users matching '%s'.", display_query);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Matching users (%zu):", match_count);
  session_send_system_line(ctx, header);
  session_send_system_line(ctx, listing);
}

static void session_handle_chat_lookup(session_ctx_t *ctx, const char *arguments) {
  static const char *kUsage = "Usage: /chat <message-id>";

  char usage[SSH_CHATTER_MESSAGE_LIMIT];
  session_command_format_usage(ctx, "/chat", kUsage, usage, sizeof(usage));

  if (ctx == NULL || ctx->owner == NULL) {
    return;
  }

  if (arguments == NULL) {
    session_send_system_line(ctx, usage);
    return;
  }

  char working[64];
  snprintf(working, sizeof(working), "%s", arguments);
  trim_whitespace_inplace(working);

  if (working[0] == '\0') {
    session_send_system_line(ctx, usage);
    return;
  }

  char *endptr = NULL;
  unsigned long long parsed = strtoull(working, &endptr, 10);
  if (parsed == 0ULL || (endptr != NULL && *endptr != '\0')) {
    session_send_system_line(ctx, usage);
    return;
  }

  uint64_t message_id = (uint64_t)parsed;
  chat_history_entry_t entry = {0};
  if (!host_history_find_entry_by_id(ctx->owner, message_id, &entry)) {
    char message[SSH_CHATTER_MESSAGE_LIMIT];
    snprintf(message, sizeof(message), "Message #%" PRIu64 " was not found.", message_id);
    session_send_system_line(ctx, message);
    return;
  }

  char header[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(header, sizeof(header), "Message #%" PRIu64 ":", message_id);
  session_send_system_line(ctx, header);
  session_send_history_entry(ctx, &entry);
  session_send_reply_tree(ctx, entry.message_id, 0U, 1U);
}
