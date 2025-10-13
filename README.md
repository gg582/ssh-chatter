## SSH-Chatter should be 100% compatible with Go SSH-Chat.

The C implementation mirrors the behaviour of the Go `ssh-chat` reference while
focusing on clear separation of concerns and modern C conventions. The codebase
is organised around the following building blocks:

* **`host.c` / `host.h`** – the main server entry point. It exposes
  `host_init`, `host_set_motd`, and `host_serve`, which mirror the lifecycle of
  the Go implementation.
* **Chat room primitives** – encapsulated inside `host.c` for now, providing a
  thread-safe member registry prepared for future session attachments.
* **Session context (`session_ctx_t`)** – carries SSH state, user metadata, and
  authorisation flags so that the per-connection thread can implement commands
  such as `/ban` and `/poke` while remaining compatible with the reference.

## Additional Functions should be kept if possible
- Poke
- Ban
- Etc
