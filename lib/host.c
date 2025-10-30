static bool session_bbs_navigate_adjacent(session_ctx_t *ctx, int direction);
    if (sequence[2] == 'C') {
      if (ctx->bbs_view_active && session_bbs_navigate_adjacent(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
    }
    if (sequence[2] == 'D') {
      if (ctx->bbs_view_active && session_bbs_navigate_adjacent(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
    }
    if (sequence[2] == 'C') {
      if (ctx->bbs_view_active && session_bbs_navigate_adjacent(ctx, 1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
    }
    if (sequence[2] == 'D') {
      if (ctx->bbs_view_active && session_bbs_navigate_adjacent(ctx, -1)) {
        ctx->input_escape_active = false;
        ctx->input_escape_length = 0U;
        return true;
      }
    }
  session_bbs_emit_line_if_visible(ctx,
                                   "Use Up/Down arrows or PgUp/PgDn to scroll this post. Use Left/Right arrows to switch"
                                   " posts.",
                                   false, offset, window, emit, &line_index);
static bool session_bbs_navigate_adjacent(session_ctx_t *ctx, int direction) {
  if (ctx == NULL || ctx->owner == NULL || !ctx->bbs_view_active || ctx->bbs_view_post_id == 0U || direction == 0) {
    return false;
  }

  host_t *host = ctx->owner;

  bbs_post_t snapshot[SSH_CHATTER_BBS_MAX_POSTS];
  size_t snapshot_count = 0U;

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0U; idx < SSH_CHATTER_BBS_MAX_POSTS; ++idx) {
    const bbs_post_t *post = &host->bbs_posts[idx];
    if (!post->in_use) {
      continue;
    }
    if (snapshot_count < SSH_CHATTER_BBS_MAX_POSTS) {
      snapshot[snapshot_count++] = *post;
    }
  }
  pthread_mutex_unlock(&host->lock);

  if (snapshot_count == 0U) {
    return false;
  }

  for (size_t idx = 0U; idx + 1U < snapshot_count; ++idx) {
    size_t best = idx;
    time_t best_time = snapshot[idx].bumped_at != 0 ? snapshot[idx].bumped_at : snapshot[idx].created_at;
    for (size_t scan = idx + 1U; scan < snapshot_count; ++scan) {
      time_t candidate = snapshot[scan].bumped_at != 0 ? snapshot[scan].bumped_at : snapshot[scan].created_at;
      if (candidate > best_time) {
        best = scan;
        best_time = candidate;
      }
    }
    if (best != idx) {
      bbs_post_t temp = snapshot[idx];
      snapshot[idx] = snapshot[best];
      snapshot[best] = temp;
    }
  }

  size_t current_index = SIZE_MAX;
  for (size_t idx = 0U; idx < snapshot_count; ++idx) {
    if (snapshot[idx].id == ctx->bbs_view_post_id) {
      current_index = idx;
      break;
    }
  }

  if (current_index == SIZE_MAX) {
    session_send_system_line(ctx, "Unable to locate the current post.");
    return false;
  }

  size_t target_index = current_index;
  if (direction < 0) {
    if (current_index == 0U) {
      session_send_system_line(ctx, "Already viewing the newest post.");
      return true;
    }
    target_index = current_index - 1U;
  } else {
    if (current_index + 1U >= snapshot_count) {
      session_send_system_line(ctx, "Already viewing the oldest post.");
      return true;
    }
    target_index = current_index + 1U;
  }

  bbs_post_t target = snapshot[target_index];

  char notice[SSH_CHATTER_MESSAGE_LIMIT];
  snprintf(notice, sizeof(notice), "Showing post #%" PRIu64 ".", target.id);
  session_bbs_render_post(ctx, &target, notice, true, false);
  return true;
}

