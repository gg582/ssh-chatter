static bool host_address_is_wildcard(const char *address) {
  if (address == NULL) {
    return true;
  }

  if (address[0] == '\0') {
    return true;
  }

  if (strcmp(address, "*") == 0 || strcmp(address, "0.0.0.0") == 0 || strcmp(address, "::") == 0 ||
      strcmp(address, "::0") == 0) {
    return true;
  }

  bool all_zero = true;
  for (const char *cursor = address; *cursor != '\0'; ++cursor) {
    if (*cursor == ':' || *cursor == '.') {
      continue;
    }
    if (*cursor != '0') {
      all_zero = false;
      break;
    }
  }

  return all_zero;
}

static bool host_is_protected_ip_unlocked(const host_t *host, const char *ip) {
  if (host == NULL || ip == NULL || ip[0] == '\0') {
    return false;
  }

  for (size_t idx = 0; idx < host->protected_ip_count && idx < SSH_CHATTER_MAX_PROTECTED_IPS; ++idx) {
    if (strncmp(host->protected_ips[idx], ip, SSH_CHATTER_IP_LEN) == 0) {
      return true;
    }
  }

  return false;
}

static bool host_protected_ip_add_unlocked(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL) {
    return false;
  }

  char normalized[SSH_CHATTER_IP_LEN];
  size_t length = strnlen(ip, sizeof(normalized));
  size_t start = 0U;
  while (start < length && isspace((unsigned char)ip[start]) != 0) {
    ++start;
  }
  size_t end = length;
  while (end > start && isspace((unsigned char)ip[end - 1U]) != 0) {
    --end;
  }

  if (end <= start) {
    return false;
  }

  size_t normalized_length = end - start;
  if (normalized_length >= sizeof(normalized)) {
    normalized_length = sizeof(normalized) - 1U;
  }
  memcpy(normalized, ip + start, normalized_length);
  normalized[normalized_length] = '\0';

  if (host_address_is_wildcard(normalized)) {
    return false;
  }

  if (host_is_protected_ip_unlocked(host, normalized)) {
    return true;
  }

  if (host->protected_ip_count >= SSH_CHATTER_MAX_PROTECTED_IPS) {
    return false;
  }

  snprintf(host->protected_ips[host->protected_ip_count], SSH_CHATTER_IP_LEN, "%s", normalized);
  ++host->protected_ip_count;
  return true;
}

static bool host_protected_ip_add(host_t *host, const char *ip) {
  if (host == NULL || ip == NULL) {
    return false;
  }

  bool added = false;
  pthread_mutex_lock(&host->lock);
  added = host_protected_ip_add_unlocked(host, ip);
  pthread_mutex_unlock(&host->lock);
  return added;
}

static void host_protected_ips_load_from_env(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *env = getenv("CHATTER_PROTECTED_IPS");
  if (env == NULL || env[0] == '\0') {
    return;
  }

  size_t env_length = strlen(env);
  char *copy = (char *)malloc(env_length + 1U);
  if (copy == NULL) {
    humanized_log_error("host", "failed to allocate protected ip buffer", errno != 0 ? errno : ENOMEM);
    return;
  }
  memcpy(copy, env, env_length + 1U);

  char *save_ptr = NULL;
  for (char *token = strtok_r(copy, ",", &save_ptr); token != NULL; token = strtok_r(NULL, ",", &save_ptr)) {
    char working[SSH_CHATTER_IP_LEN];
    size_t token_length = strnlen(token, sizeof(working));
    if (token_length >= sizeof(working)) {
      token_length = sizeof(working) - 1U;
    }
    memcpy(working, token, token_length);
    working[token_length] = '\0';

    // Trim leading and trailing whitespace inside the buffer before adding it.
    size_t local_length = strnlen(working, sizeof(working));
    size_t local_start = 0U;
    while (local_start < local_length && isspace((unsigned char)working[local_start]) != 0) {
      ++local_start;
    }
    size_t local_end = local_length;
    while (local_end > local_start && isspace((unsigned char)working[local_end - 1U]) != 0) {
      --local_end;
    }
    if (local_end <= local_start) {
      continue;
    }
    size_t trimmed_length = local_end - local_start;
    if (trimmed_length >= sizeof(working)) {
      trimmed_length = sizeof(working) - 1U;
    }
    memmove(working, working + local_start, trimmed_length);
    working[trimmed_length] = '\0';

    if (working[0] == '\0') {
      continue;
    }

    (void)host_protected_ip_add(host, working);
  }

  free(copy);
}

static void host_protected_ips_bootstrap(host_t *host) {
  if (host == NULL) {
    return;
  }

  const char *defaults[] = {"127.0.0.1", "::1", "192.168.0.1"};

  pthread_mutex_lock(&host->lock);
  for (size_t idx = 0; idx < sizeof(defaults) / sizeof(defaults[0]); ++idx) {
    (void)host_protected_ip_add_unlocked(host, defaults[idx]);
  }
  pthread_mutex_unlock(&host->lock);

  host_protected_ips_load_from_env(host);
}

static void host_register_protected_bind_address(host_t *host, const char *address) {
  if (host == NULL || address == NULL || address[0] == '\0') {
    return;
  }

  if (host_address_is_wildcard(address)) {
    return;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  struct addrinfo *result = NULL;
  int rc = getaddrinfo(address, NULL, &hints, &result);
  if (rc != 0 || result == NULL) {
    (void)host_protected_ip_add(host, address);
    if (result != NULL) {
      freeaddrinfo(result);
    }
    return;
  }

  for (struct addrinfo *entry = result; entry != NULL; entry = entry->ai_next) {
    char ip_buffer[SSH_CHATTER_IP_LEN];
    void *addr_ptr = NULL;
    int family = entry->ai_family;
    if (family == AF_INET) {
      struct sockaddr_in *in4 = (struct sockaddr_in *)entry->ai_addr;
      addr_ptr = &in4->sin_addr;
    } else if (family == AF_INET6) {
      struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)entry->ai_addr;
      addr_ptr = &in6->sin6_addr;
    } else {
      continue;
    }

    if (inet_ntop(family, addr_ptr, ip_buffer, sizeof(ip_buffer)) == NULL) {
      continue;
    }

    (void)host_protected_ip_add(host, ip_buffer);
  }

  freeaddrinfo(result);
}

    if (entries[idx].ip[0] != '\0' && host_is_protected_ip_unlocked(host, entries[idx].ip)) {
      continue;
    }
    if (entries[idx].ip[0] != '\0' && strchr(entries[idx].ip, '/') != NULL) {
      bool intersects_protected = false;
      for (size_t protected_idx = 0; protected_idx < host->protected_ip_count &&
                                   protected_idx < SSH_CHATTER_MAX_PROTECTED_IPS; ++protected_idx) {
        if (host_cidr_contains_ip(entries[idx].ip, host->protected_ips[protected_idx])) {
          intersects_protected = true;
          break;
        }
      }
      if (intersects_protected) {
        continue;
      }
    }
  if (host_is_protected_ip_unlocked(host, ip)) {
    pthread_mutex_unlock(&host->lock);
    return false;
  }
    if (host_is_protected_ip_unlocked(host, ban_ip)) {
  if (ip != NULL && ip[0] != '\0' && host_is_protected_ip_unlocked(host, ip)) {
    pthread_mutex_unlock(&host->lock);
    return true;
  }
  if (ip != NULL && ip[0] != '\0' && strchr(ip, '/') != NULL) {
    for (size_t idx = 0; idx < host->protected_ip_count && idx < SSH_CHATTER_MAX_PROTECTED_IPS; ++idx) {
      if (host_cidr_contains_ip(ip, host->protected_ips[idx])) {
        pthread_mutex_unlock(&host->lock);
        return true;
      }
    }
  }

  memset(host->protected_ips, 0, sizeof(host->protected_ips));
  host->protected_ip_count = 0U;
  host_protected_ips_bootstrap(host);
  host_register_protected_bind_address(host, address);
  host_register_protected_bind_address(host, telnet_bind);
