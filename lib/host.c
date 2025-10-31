  if (strcasecmp(token, "off") == 0 || strcasecmp(token, "none") == 0 || strcasecmp(token, "disable") == 0 ||
      strcasecmp(token, "stop") == 0) {
    return true;
  }

  return strcmp(token, "끄기") == 0 || strcmp(token, "オフ") == 0 || strcmp(token, "关") == 0 || strcmp(token, "выкл") == 0;
  else if (session_parse_command_any(ctx, "/reply", effective_line, &args)) {
  else if (strncmp(effective_line, "/getaddr", 8) == 0) {
    const char *arguments = effective_line + 8;
  else if (strncmp(effective_line, "/birthday", 9) == 0) {
    const char *arguments = effective_line + 9;
  else if (strcasecmp(effective_line, session_command_alias_preferred_by_canonical(ctx, "/soulmate")) == 0) {
    const char *arguments = effective_line + 9;
  else if (strncmp(effective_line, "/grant", 6) == 0) {
    const char *arguments = effective_line + 6;
  else if (strncmp(effective_line, "/revoke", 7) == 0) {
    const char *arguments = effective_line + 7;
  else if (strncmp(effective_line, "/pair", 5) == 0) {
    const char *arguments = effective_line + 5;
  else if (strncmp(effective_line, "/connected", 10) == 0) {
    const char *arguments = effective_line + 10;
  else if (session_parse_command(effective_line, "/alpha-centauri-landers", &args)) {
  else if (strcasecmp(effective_line, session_command_alias_preferred_by_canonical(ctx, "/poll")) == 0) {
    const char *arguments = effective_line + 5;
  else if (strncmp(effective_line, "/vote-single", 12) == 0) {
    const char *arguments = effective_line + 12;
  else if (strncmp(effective_line, "/vote", 5) == 0) {
    const char *arguments = effective_line + 5;
  else if (strncmp(effective_line, "/elect", 6) == 0) {
    const char *arguments = effective_line + 6;
  else if (session_parse_command(effective_line, "/rss", &args)) {
  else if (session_parse_command_any(ctx, "/bbs", effective_line, &args)) {
  else if (session_parse_command(effective_line, "/kick", &args)) {
  else if (effective_line[0] == '/') {
    if (isdigit((unsigned char)effective_line[1])) {
      unsigned long vote_index = strtoul(effective_line + 1, &endptr, 10);
      if (!session_parse_command_any(ctx, canonical, effective_line, &arguments)) {
      strcasecmp(token, "bold") == 0 || strcmp(token, "켜기") == 0 || strcmp(token, "オン") == 0 ||
      strcmp(token, "开") == 0 || strcmp(token, "вкл") == 0) {
      strcasecmp(token, "normal") == 0 || strcmp(token, "끄기") == 0 || strcmp(token, "オフ") == 0 ||
      strcmp(token, "关") == 0 || strcmp(token, "выкл") == 0) {
