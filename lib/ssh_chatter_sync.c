#define LIBSSH_STATIC
#include "ssh_chatter_sync.h"
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h> // For sleep

static ssh_session session = NULL;
static ssh_channel channel = NULL;
static pthread_t read_thread;
static bool sync_running = false;
static message_received_callback_t msg_callback = NULL;
static pthread_t retry_thread; // For managing reconnection retries
static bool retry_pending = false;

#define MAX_CHAT_HISTORY_SIZE 50
#define RETRY_INTERVAL_SECONDS 3600 // 1 hour

// Global chat history variables
static chat_message_t *chat_history_head = NULL;
static int chat_history_size = 0;
static pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global synchronization settings
static sync_settings_t current_settings = {
  .sync_in_enabled = true,
  .sync_out_enabled = true,
  .last_sync_attempt = { 0, 0 } // Initialize timespec
};

// Forward declarations
static void *read_channel_thread (void *arg);
static int authenticate_ssh_session (ssh_session sess);

static double
timespec_elapsed_seconds (const struct timespec *start,
                          const struct timespec *end)
{
  if (start == NULL || end == NULL) {
    return 0.0;
  }

  time_t sec = end->tv_sec - start->tv_sec;
  long nsec = end->tv_nsec - start->tv_nsec;
  if (nsec < 0L) {
    --sec;
    nsec += 1000000000L;
  }
  if (sec < 0) {
    sec = 0;
    nsec = 0L;
  }

  return (double)sec + (double)nsec / 1000000000.0;
}

static void *
retry_connection_thread (void *arg)
{
  (void)arg; // Suppress unused parameter warning
  fprintf (stderr, "[SSH_SYNC] Retry thread started.\n\n");

  while (sync_running) {
    if (retry_pending) {
      struct timespec now;
      clock_gettime (CLOCK_MONOTONIC, &now);
      double elapsed = timespec_elapsed_seconds (
          &current_settings.last_sync_attempt, &now);

      if (elapsed >= RETRY_INTERVAL_SECONDS) {
        fprintf (stderr, "[SSH_SYNC] Attempting to retry connection...\n\n");
        ssh_chatter_sync_start (); // This will attempt to connect and reset retry_pending if successful
      }
    }
    sleep (300); // Check every 5 minutes
  }
  fprintf (stderr, "[SSH_SYNC] Retry thread stopped.\n\n");
  return NULL;
}

void
ssh_chatter_sync_add_message_to_history (const chat_message_t *new_msg)
{
  pthread_mutex_lock (&history_mutex);

  // Simple deduplication: Check if the last message is identical
  if (chat_history_head != NULL
      && strcmp (chat_history_head->message_body, new_msg->message_body) == 0
      && strcmp (chat_history_head->username, new_msg->username) == 0) {
    fprintf (stderr, "[SSH_SYNC] Duplicate message received, skipping.\n\n");
    pthread_mutex_unlock (&history_mutex);
    return;
  }

  chat_message_t *node = (chat_message_t *)malloc (sizeof (chat_message_t));
  if (node == NULL) {
    fprintf (stderr, "[SSH_SYNC] Failed to allocate memory for chat message "
                     "history node.\n\n");
    pthread_mutex_unlock (&history_mutex);
    return;
  }

  node->username = strdup (new_msg->username);
  node->message_body = strdup (new_msg->message_body);
  node->timestamp = new_msg->timestamp;
  node->next = chat_history_head;
  chat_history_head = node;

  chat_history_size++;

  // Trim history if it exceeds max size
  if (chat_history_size > MAX_CHAT_HISTORY_SIZE) {
    chat_message_t *current = chat_history_head;
    chat_message_t *prev = NULL;
    for (int i = 0; i < MAX_CHAT_HISTORY_SIZE - 1; i++) {
      if (current == NULL)
        break;
      prev = current;
      current = current->next;
    }
    if (prev != NULL && current != NULL) {
      free (current->username);
      free (current->message_body);
      free (current);
      prev->next = NULL;
      chat_history_size--;
    }
  }

  pthread_mutex_unlock (&history_mutex);
}

void
ssh_chatter_sync_free_history ()
{
  pthread_mutex_lock (&history_mutex);
  chat_message_t *current = chat_history_head;
  while (current != NULL) {
    chat_message_t *next = current->next;
    free (current->username);
    free (current->message_body);
    free (current);
    current = next;
  }
  chat_history_head = NULL;
  chat_history_size = 0;
  pthread_mutex_unlock (&history_mutex);
  pthread_mutex_destroy (&history_mutex);
}

// Placeholder for getting last N messages from history (to be implemented later if needed)
chat_message_t *
ssh_chatter_sync_get_last_messages (int count)
{
  (void)count; // Mark arg as used to suppress unused parameter warning
  // This will return an allocated array of messages, caller must free
  return NULL;
}

void
ssh_chatter_sync_init ()
{
  // Initialize libssh (not strictly necessary, but good practice)
  // ssh_init(); // This function is deprecated, no explicit init needed for newer libssh
  fprintf (stderr, "[SSH_SYNC] Initialized SSH Chatter Sync module.\n");
  pthread_mutex_init (&history_mutex, NULL); // Initialize history mutex
  // Load settings on init
  ssh_chatter_sync_load_settings ();
  // Start retry thread initially to handle potential immediate connection failures
  if (pthread_create (&retry_thread, NULL, retry_connection_thread, NULL)
      != 0) {
    fprintf (stderr, "[SSH_SYNC] Failed to create initial retry thread.\n\n");
  }
}

void
ssh_chatter_sync_start ()
{
  if (sync_running) {
    fprintf (stderr, "[SSH_SYNC] Synchronization already running.\n");
    return;
  }

  fprintf (stderr, "[SSH_SYNC] Starting synchronization...\n");

  session = ssh_new ();
  if (session == NULL) {
    fprintf (stderr, "[SSH_SYNC] Failed to create SSH session.\n\n");
    return;
  }

  ssh_options_set (session, SSH_OPTIONS_HOST, current_settings.go_chat_host);
  ssh_options_set (session, SSH_OPTIONS_PORT, &current_settings.go_chat_port);
  ssh_options_set (session, SSH_OPTIONS_USER,
                   current_settings.go_chat_username);

  int rc = ssh_connect (session);
  if (rc != SSH_OK) {
    fprintf (stderr, "[SSH_SYNC] Error connecting to %s:%d: %s\n\n",
             current_settings.go_chat_host, current_settings.go_chat_port,
             ssh_get_error (session));
    ssh_free (session);
    session = NULL;
    // Schedule retry after 1 hour
    clock_gettime (CLOCK_MONOTONIC, &current_settings.last_sync_attempt);
    retry_pending = true;
    ssh_chatter_sync_save_settings ();
    fprintf (stderr, "[SSH_SYNC] Connection failed. Retrying in 1 hour.\n\n");
    // Start retry thread if not already running
    if (pthread_create (&retry_thread, NULL, retry_connection_thread, NULL)
        != 0) {
      fprintf (stderr, "[SSH_SYNC] Failed to create retry thread.\n\n");
    }
    return;
  }

  fprintf (stderr, "[SSH_SYNC] Connected to %s:%d.\n\n",
           current_settings.go_chat_host, current_settings.go_chat_port);

  if (authenticate_ssh_session (session) != SSH_OK) {
    fprintf (stderr, "[SSH_SYNC] Authentication failed: %s\n\n",
             ssh_get_error (session));
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
    clock_gettime (CLOCK_MONOTONIC, &current_settings.last_sync_attempt);
    retry_pending = true;
    ssh_chatter_sync_save_settings ();
    fprintf (stderr,
             "[SSH_SYNC] Authentication failed. Retrying in 1 hour.\n\n");
    // Start retry thread if not already running
    if (pthread_create (&retry_thread, NULL, retry_connection_thread, NULL)
        != 0) {
      fprintf (stderr, "[SSH_SYNC] Failed to create retry thread.\n\n");
    }
    return;
  }

  fprintf (stderr, "[SSH_SYNC] Authenticated.\n\n");

  channel = ssh_channel_new (session);
  if (channel == NULL) {
    fprintf (stderr, "[SSH_SYNC] Failed to create SSH channel.\n\n");
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
    return;
  }

  rc = ssh_channel_open_session (channel);
  if (rc != SSH_OK) {
    fprintf (stderr, "[SSH_SYNC] Failed to open SSH channel session: %s\n\n",
             ssh_get_error (session));
    ssh_channel_free (channel);
    channel = NULL;
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
    return;
  }

  rc = ssh_channel_request_pty (channel);
  if (rc != SSH_OK) {
    fprintf (stderr, "[SSH_SYNC] Failed to request PTY: %s\n\n",
             ssh_get_error (session));
    ssh_channel_close (channel);
    ssh_channel_free (channel);
    channel = NULL;
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
    return;
  }

  rc = ssh_channel_request_shell (channel);
  if (rc != SSH_OK) {
    fprintf (stderr, "[SSH_SYNC] Failed to request shell: %s\n\n",
             ssh_get_error (session));
    ssh_channel_close (channel);
    ssh_channel_free (channel);
    channel = NULL;
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
    return;
  }

  sync_running = true;
  clock_gettime (CLOCK_MONOTONIC,
                 &current_settings.last_sync_attempt); // Use monotonic clock
  ssh_chatter_sync_save_settings ();

  // Start reading thread
  if (pthread_create (&read_thread, NULL, read_channel_thread, NULL) != 0) {
    fprintf (stderr, "[SSH_SYNC] Failed to create read thread.\n\n");
    ssh_chatter_sync_stop ();
    return;
  }
  fprintf (stderr, "[SSH_SYNC] Synchronization started successfully.\n\n");
}

void
ssh_chatter_sync_stop ()
{
  if (!sync_running) {
    fprintf (stderr, "[SSH_SYNC] Synchronization not running.\n\n");
    return;
  }

  fprintf (stderr, "[SSH_SYNC] Stopping synchronization...\n\n");
  sync_running = false;
  retry_pending = false; // Stop retry attempts

  if (read_thread) {
    pthread_join (read_thread, NULL); // Wait for the read thread to finish
  }
  if (retry_thread) {
    pthread_join (retry_thread, NULL); // Wait for the retry thread to finish
  }

  if (channel) {
    ssh_channel_close (channel);
    ssh_channel_free (channel);
    channel = NULL;
  }
  if (session) {
    ssh_disconnect (session);
    ssh_free (session);
    session = NULL;
  }
  ssh_chatter_sync_free_history (); // Free chat history
  fprintf (stderr, "[SSH_SYNC] Synchronization stopped.\n\n");
}

void
ssh_chatter_sync_manual_trigger ()
{
  fprintf (stderr, "[SSH_SYNC] Manual synchronization trigger requested.\n\n");
  if (sync_running) {
    ssh_chatter_sync_stop ();
  }
  ssh_chatter_sync_start ();
}

void
ssh_chatter_sync_set_in_enabled (bool enabled)
{
  current_settings.sync_in_enabled = enabled;
  ssh_chatter_sync_save_settings ();
  fprintf (stderr, "[SSH_SYNC] Incoming sync %s.\n\n",
           enabled ? "enabled" : "disabled");
}

void
ssh_chatter_sync_set_out_enabled (bool enabled)
{
  current_settings.sync_out_enabled = enabled;
  ssh_chatter_sync_save_settings ();
  fprintf (stderr, "[SSH_SYNC] Outgoing sync %s.\n\n",
           enabled ? "enabled" : "disabled");
}

sync_settings_t
ssh_chatter_sync_get_settings ()
{
  return current_settings;
}

void
ssh_chatter_sync_save_settings ()
{
  FILE *fp = fopen ("ssh_chatter_sync.dat", "wb");
  if (fp) {
    // Only save tv_sec for last_sync_attempt
    sync_settings_t settings_to_save = current_settings;
    settings_to_save.last_sync_attempt.tv_nsec = 0; // Don't save nanoseconds

    fwrite (&settings_to_save, sizeof (sync_settings_t), 1, fp);
    fclose (fp);
    fprintf (stderr, "[SSH_SYNC] Settings saved.\n\n");
  } else {
    fprintf (stderr, "[SSH_SYNC] Failed to save settings.\n\n");
  }
}

void
ssh_chatter_sync_load_settings ()
{
  FILE *fp = fopen ("ssh_chatter_sync.dat", "rb");
  if (fp) {
    size_t read_bytes
        = fread (&current_settings, sizeof (sync_settings_t), 1, fp);
    if (read_bytes != 1) {
      fprintf (
          stderr,
          "[SSH_SYNC] Error reading settings from file, using defaults.\n\n");
      // Reset to defaults if read failed
      current_settings.sync_in_enabled = true;
      current_settings.sync_out_enabled = true;
      current_settings.last_sync_attempt.tv_sec = 0;  // Initialize tv_sec
      current_settings.last_sync_attempt.tv_nsec = 0; // Initialize tv_nsec
      memset (current_settings.go_chat_host, 0,
              sizeof (current_settings.go_chat_host));
      memset (current_settings.go_chat_username, 0,
              sizeof (current_settings.go_chat_username));
      memset (current_settings.go_chat_password, 0,
              sizeof (current_settings.go_chat_password));
      current_settings.go_chat_port = 2022; // Default port
    }
    fclose (fp);
    fprintf (stderr, "[SSH_SYNC] Settings loaded.\n\n");
  } else {
    fprintf (stderr, "[SSH_SYNC] No settings file found, using defaults.\n\n");
    // Initialize with defaults if file not found
    current_settings.sync_in_enabled = true;
    current_settings.sync_out_enabled = true;
    current_settings.last_sync_attempt.tv_sec = 0;  // Initialize tv_sec
    current_settings.last_sync_attempt.tv_nsec = 0; // Initialize tv_nsec
    strncpy (current_settings.go_chat_host, "127.0.0.1",
             sizeof (current_settings.go_chat_host) - 1);
    current_settings.go_chat_host[sizeof (current_settings.go_chat_host) - 1]
        = '\0';
    current_settings.go_chat_port = 2022;
    strncpy (current_settings.go_chat_username, "chatter_sync",
             sizeof (current_settings.go_chat_username) - 1);
    current_settings
        .go_chat_username[sizeof (current_settings.go_chat_username) - 1]
        = '\0';
    strncpy (current_settings.go_chat_password, "password",
             sizeof (current_settings.go_chat_password) - 1);
    current_settings
        .go_chat_password[sizeof (current_settings.go_chat_password) - 1]
        = '\0';
  }
}

void
ssh_chatter_sync_send_message (const char *message)
{
  if (!sync_running || !channel || !current_settings.sync_out_enabled) {
    fprintf (stderr, "[SSH_SYNC] Cannot send message: Sync not running, "
                     "channel not open, or outgoing sync disabled.\n\n");
    return;
  }

  // Append newline to simulate pressing Enter
  char *msg_with_newline = (char *)malloc (strlen (message) + 2);
  if (msg_with_newline == NULL) {
    fprintf (stderr, "[SSH_SYNC] Failed to allocate memory for message.\n\n");
    return;
  }
  strcpy (msg_with_newline, message);
  strcat (msg_with_newline, "\n");

  int rc = ssh_channel_write (channel, msg_with_newline,
                              (uint32_t)strlen (msg_with_newline));
  free (msg_with_newline);

  if (rc == SSH_ERROR) {
    fprintf (stderr, "[SSH_SYNC] Error sending message: %s\n\n",
             ssh_get_error (session));
  } else {
    fprintf (stderr, "[SSH_SYNC] Sent message: %s\n\n", message);
  }
}

void
ssh_chatter_sync_set_message_received_callback (
    message_received_callback_t callback)
{
  msg_callback = callback;
}

static void *
read_channel_thread (void *arg)
{
  (void)arg; // Mark arg as used to suppress unused parameter warning
  char buffer[256];
  int nbytes;

  fprintf (stderr, "[SSH_SYNC] Read thread started.\n\n");

  while (sync_running && channel) {
    // Read from stdout
    nbytes = ssh_channel_read_nonblocking (channel, buffer, sizeof (buffer), 0);
    if (nbytes < 0) {
      fprintf (stderr, "[SSH_SYNC] Error reading from channel: %s\n\n",
               ssh_get_error (session));
      sync_running = false; // Stop sync on read error
      break;
    }
    if (nbytes > 0) {
      // Null-terminate the buffer for string manipulation
      buffer[nbytes] = '\0';
      // Process the received buffer line by line
      char *line = buffer;
      char *next_line;
      while ((next_line = strchr (line, '\n')) != NULL) {
        *next_line = '\0'; // Null-terminate the current line
        // Trim leading/trailing whitespace
        char *trimmed_line = line;
        while (*trimmed_line == ' ' || *trimmed_line == '\t'
               || *trimmed_line == '\r') {
          trimmed_line++;
        }
        char *end = trimmed_line + strlen (trimmed_line) - 1;
        while (end > trimmed_line
               && (*end == ' ' || *end == '\t' || *end == '\r')) {
          *end = '\0';
          end--;
        }

        if (strlen (trimmed_line) > 0) {
          fprintf (stderr, "\033[G[SSH_SYNC] Received line: %s\n\n",
                   trimmed_line);

          // Attempt to parse as a chat message "username: message_body"
          char *colon_pos = strstr (trimmed_line, ": ");
          if (colon_pos != NULL) {
            *colon_pos = '\0'; // Null-terminate username
            char *username = trimmed_line;
            char *message_body = colon_pos + 2; // Skip ": "

            if (current_settings.sync_in_enabled && msg_callback) {
              chat_message_t new_chat_msg;
              new_chat_msg.username = username;
              new_chat_msg.message_body = message_body;
              new_chat_msg.timestamp = time (NULL);
              ssh_chatter_sync_add_message_to_history (&new_chat_msg);
              msg_callback (&new_chat_msg);
            }
          } else {
            // Not a standard chat message, could be a system message or join/leave
            // For now, just log it and don't add to history as a chat message
            fprintf (stderr, "\033[G[SSH_SYNC] Non-chat message: %s\n\n",
                     trimmed_line);
          }
        }
        line = next_line + 1; // Move to the next line
      }
      // Handle any remaining part of the buffer that doesn't end with a newline
      if (strlen (line) > 0) {
        fprintf (stderr, "\033[G[SSH_SYNC] Received partial line: %s\n\n",
                 line);
        // This partial line will be prepended to the next buffer read
        // For now, we'll just ignore it for parsing purposes
      }
    }

    // Read from stderr (optional, for debugging server errors)
    nbytes = ssh_channel_read_nonblocking (channel, buffer, sizeof (buffer), 1);
    if (nbytes < 0) {
      fprintf (stderr, "[SSH_SYNC] Error reading from channel stderr: %s\n\n",
               ssh_get_error (session));
      // Don't stop sync for stderr read error, but log it
    }
    if (nbytes > 0) {
      buffer[nbytes] = '\0';
      fprintf (stderr, "[SSH_SYNC] Received (stderr): %s\n\n", buffer);
    }

    usleep (100000); // Sleep for 100ms to prevent busy-waiting
  }

  fprintf (stderr, "[SSH_SYNC] Read thread stopped.\n\n");
  return NULL;
}

static int
authenticate_ssh_session (ssh_session sess)
{
  // As per user's instruction, Go chat does not require password authentication.
  // We will simply return SSH_OK to bypass authentication.
  (void)sess; // Suppress unused parameter warning
  return SSH_OK;
}

void
ssh_chatter_sync_set_connection_details (const char *host, int port,
                                         const char *username,
                                         const char *password)
{
  if (host) {
    strncpy (current_settings.go_chat_host, host,
             sizeof (current_settings.go_chat_host) - 1);
    current_settings.go_chat_host[sizeof (current_settings.go_chat_host) - 1]
        = '\0';
  }
  current_settings.go_chat_port = port;
  if (username) {
    strncpy (current_settings.go_chat_username, username,
             sizeof (current_settings.go_chat_username) - 1);
    current_settings
        .go_chat_username[sizeof (current_settings.go_chat_username) - 1]
        = '\0';
  }
  if (password) {
    strncpy (current_settings.go_chat_password, password,
             sizeof (current_settings.go_chat_password) - 1);
    current_settings
        .go_chat_password[sizeof (current_settings.go_chat_password) - 1]
        = '\0';
  }
  ssh_chatter_sync_save_settings ();
  fprintf (stderr, "[SSH_SYNC] Connection details updated and saved.\n\n");
}
