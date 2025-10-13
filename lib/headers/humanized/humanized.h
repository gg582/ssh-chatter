#ifndef HUMANIZED_H
#define HUMANIZED_H
#define AND &&
#define OR ||
#define NOT !
#define none NULL

#define exitWithError(errcode, section, msg, exitcode) {                       \
    fprintf(stderr, "<%s>: %s, code: (%d)", section, msg, errcode); \
  return exitcode; \
}
#endif
