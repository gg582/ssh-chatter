  const char *welcome_history_hint;
        .welcome_history_hint = "Previous messages are hidden. Use Up/Down arrows to browse older chat.",
        .welcome_history_hint = "이전 메시지는 숨겨져 있습니다. 위/아래 화살표로 지난 채팅을 살펴보세요.",
        .welcome_history_hint = "以前のメッセージは非表示です。上下の矢印で過去のチャットを確認できます。",
        .welcome_history_hint = "之前的消息已隐藏。使用上下方向键查看较早的聊天。",
        .welcome_history_hint = "Предыдущие сообщения скрыты. Используйте стрелки вверх/вниз, чтобы просмотреть старый чат.",
static void session_scrollback_reset_position(session_ctx_t *ctx);
  bool locked = false;
  if (ctx->channel_mutex_initialized) {
    int lock_result = pthread_mutex_lock(&ctx->channel_mutex);
    if (lock_result == 0) {
      locked = true;
    } else {
      humanized_log_error("session", "failed to lock channel mutex", lock_result);
    }
  }

  if (locked) {
    int unlock_result = pthread_mutex_unlock(&ctx->channel_mutex);
    if (unlock_result != 0) {
      humanized_log_error("session", "failed to unlock channel mutex", unlock_result);
    }
  }

    session_scrollback_reset_position(ctx);
    session_scrollback_reset_position(ctx);
static void session_scrollback_reset_position(session_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }

  ctx->history_scroll_position = 0U;
  ctx->history_latest_notified = false;
  ctx->history_oldest_notified = false;
}

  session_scrollback_reset_position(ctx);
  session_scrollback_reset_position(ctx);
  bool at_latest = (ctx->history_scroll_position == 0U);
  bool at_oldest = (ctx->history_scroll_position == max_position && total > 0U);

  if (!at_latest) {
    ctx->history_latest_notified = false;
  }
  if (!at_oldest) {
    ctx->history_oldest_notified = false;
  }

    if (!ctx->history_latest_notified) {
      ctx->history_latest_notified = true;
    if (!ctx->history_oldest_notified) {
      session_send_system_line(ctx, "Reached the oldest stored message.");
      ctx->history_oldest_notified = true;
    }
    ctx->history_scroll_position = (total > 0U) ? max_position : 0U;
    ctx->history_latest_notified = false;
    ctx->history_oldest_notified = false;
    if (!ctx->history_latest_notified) {
      session_send_system_line(ctx, "End of scrollback.");
      ctx->history_latest_notified = true;
    }
  session_scrollback_reset_position(ctx);
    if (pthread_mutex_init(&ctx->channel_mutex, NULL) == 0) {
      ctx->channel_mutex_initialized = true;
    } else {
      humanized_log_error("session", "failed to initialize channel mutex", errno != 0 ? errno : ENOMEM);
    }
  if (ctx->channel_mutex_initialized) {
    pthread_mutex_destroy(&ctx->channel_mutex);
    ctx->channel_mutex_initialized = false;
  }
    if (locale->welcome_history_hint != NULL && locale->welcome_history_hint[0] != '\0') {
      session_send_system_line(ctx, locale->welcome_history_hint);
    } else {
      session_send_system_line(ctx, "Use the Up/Down arrow keys to browse stored chat history.");
    }
    session_scrollback_reset_position(ctx);

        session_scrollback_reset_position(ctx);
          session_scrollback_reset_position(ctx);
        session_scrollback_reset_position(ctx);
      if (pthread_mutex_init(&ctx->channel_mutex, NULL) == 0) {
        ctx->channel_mutex_initialized = true;
      } else {
        humanized_log_error("session", "failed to initialize channel mutex", errno != 0 ? errno : ENOMEM);
      }
