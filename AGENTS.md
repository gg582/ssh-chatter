# Codebase Analysis: SSH-Chatter Integration

## Current Integration
The project, named `ssh-chatter`, is a C reimplementation of the Go `ssh-chat` server. Evidence for this integration is abundant throughout the codebase:
- The `README.md` explicitly states: "SSH-Chatter has started from a C reimplementation of the Go [`ssh-chat`](https://github.com/gosuda/ssh-chat) server."
- File paths and service configurations (e.g., `example.ssh-chat-server.service`, `install_chatbot.sh`) refer to `ssh-chat-server`.
- Source code files (e.g., `lib/host_parts/host_core.c`, `lib/host_parts/host_runtime.c`) contain strings like "ssh-chatter", "ssh-chat-server", and "Welcome to ssh-chat!".
- There is no indication or mention of `synchronet` integration within the scanned files.

## Telnet Support
The `README.md` indicates that the `ssh-chatter` server is designed to listen for both SSH and TELNET connections. The usage instructions show a `-T` flag for configuring a telnet port:
`Usage: ./ssh-chatter [-a address] [-p port] [-m motd_file] [-k host_key_dir] [-T telnet_port|off]`
This suggests that basic telnet functionality is already present and designed into the application.

# Revised Plan: Synchronet Integration and Tetris Flickering Fix

The goal is to integrate `ssh-chatter` with Synchronet and resolve a screen flickering issue in the Tetris game, while maintaining existing SSH and Telnet functionality.

## Phase 1: Analyze Synchronet Integration and Tetris Flickering

1.  **Synchronet Integration Analysis:**
    *   Search the codebase for any existing mentions or partial implementations related to "Synchronet" or common Synchronet protocols/libraries (e.g., "BBS", "Zmodem", "ANSI", "telnetd" in a Synchronet context).
    *   Investigate how `ssh-chatter` currently handles terminal output and input, especially in `lib/host_parts/host_transport.c` and `lib/client.c`, to understand how it might be adapted for Synchronet's expectations (e.g., ANSI escape codes, specific terminal types).
    *   Research Synchronet's external program/door interface to understand how `ssh-chatter` would interact with it.
2.  **Tetris Flickering Analysis:**
    *   Identified the code responsible for rendering Tetris in `lib/host_parts/host_bbs_and_games.inc` (specifically `session_game_tetris_render`).
    *   Determined that flickering was caused by full screen redraws and lack of precise cursor positioning.

## Phase 2: Implement Synchronet Integration (Pending)

1.  **Design Synchronet Interface:**
    *   Based on the analysis, design a clear interface or module for `ssh-chatter` to interact with Synchronet. This might involve adapting existing Telnet handling or creating a new transport layer.
    *   Consider how user authentication, chat messages, and game interactions would be passed between `ssh-chatter` and Synchronet.
2.  **Implement Synchronet Communication:**
    *   Write code to establish and maintain a connection with Synchronet (if it's an external process) or integrate `ssh-chatter` as a Synchronet door.
    *   Implement necessary protocol handling for data exchange.
3.  **Update `AGENTS.md`:** Document the Synchronet integration details.

## Phase 3: Fix Tetris Flickering (Completed)

1.  **Identified Root Cause:** Full screen redraws and lack of precise cursor positioning in `session_game_tetris_render`.
2.  **Implemented Fix:**
    *   Added `session_send_ansi_text` function in `lib/host_parts/host_session_output.inc` for sending raw ANSI escape codes.
    *   Modified `session_game_tetris_render` in `lib/host_parts/host_bbs_and_games.inc` to:
        *   Clear the screen once per frame using `session_clear_screen`.
        *   Use ANSI escape codes (`\033[<ROW>;<COL>H`) with `session_send_ansi_text` for precise cursor positioning before drawing each element of the Tetris game (header, borders, game board, controls).
    *   Defined `TETRIS_START_ROW`, `TETRIS_START_COL`, `TETRIS_HEADER_ROW`, `TETRIS_HEADER_COL`, `TETRIS_CONTROLS_ROW`, `TETRIS_CONTROLS_COL` constants for layout management.
3.  **Tested Tetris:** (Manual testing required by user to verify smooth play).

## Phase 4: Verification and Documentation

1.  **Build and Test:** Project successfully built after changes.
2.  **Integration Testing:** Test Synchronet integration (if possible in this environment) and verify chat functionality.
3.  **Update Documentation:** Update `README.md` and any other relevant documentation to reflect Synchronet integration and the Tetris fix.
