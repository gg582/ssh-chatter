#ifndef CONTEXT_SESSION_H
#define CONTEXT_SESSION_H

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "host.h"

  game_ctx_t game;
  char chosen_camouflage_language[32];
  bool is_camouflaged;
  tetris_game_t saved_tetris_state;
  liar_game_t saved_liar_state;
  alpha_game_t saved_alpha_state;
  // Add other session-related fields here


#endif
