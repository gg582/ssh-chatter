  const char *welcome_history_hint;
        .welcome_history_hint = "Previous messages are hidden. Use Up/Down arrows to browse older chat.",
        .welcome_history_hint = "이전 메시지는 숨겨져 있습니다. 위/아래 화살표로 지난 채팅을 살펴보세요.",
        .welcome_history_hint = "以前のメッセージは非表示です。上下の矢印で過去のチャットを確認できます。",
        .welcome_history_hint = "之前的消息已隐藏。使用上下方向键查看较早的聊天。",
        .welcome_history_hint = "Предыдущие сообщения скрыты. Используйте стрелки вверх/вниз, чтобы просмотреть старый чат.",
    if (locale->welcome_history_hint != NULL && locale->welcome_history_hint[0] != '\0') {
      session_send_system_line(ctx, locale->welcome_history_hint);
    } else {
      session_send_system_line(ctx, "Use the Up/Down arrow keys to browse stored chat history.");
    }
    ctx->history_scroll_position = 0U;

