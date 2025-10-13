## SSH-Chatter : ssh-chat written in C, 100% compatible with Go SSH-Chat.

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

## Build

Use the provided `Makefile` to build the server:

```sh
make
```

Run the resulting binary with:

```sh
make run
```

By default the server looks for `ssh_host_rsa_key` in the current working
directory. Supply `-k <directory>` to point the server at a folder containing
the RSA host key if you keep certificates elsewhere.

## Feature status

### Implemented endpoints
* SSH listener that accepts connections on the configured address and port, performing key exchange and spawning a thread per session.
* Message of the day (MOTD) configuration via the `-m` flag and automatic delivery to new sessions.
* `/help` command that lists the available chat commands to the connected client.
* Logging for chat activity such as joins, parts, and command invocations for `/ban` and `/poke`.

### Not yet implemented
* Broadcasting chat messages to other connected clients – messages are only printed to the server log today.
* Enforcement of moderation commands (`/ban`, `/poke`) beyond server-side logging.
* Authentication and authorization integration beyond blindly accepting every connection.
* Session attachments that would allow `chat_room_broadcast` to deliver payloads to active channels.

