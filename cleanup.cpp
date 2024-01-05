#include "cleanup.h"

#include "unistd.h"

void cleanup_fd(int *fd) {
  if (*fd != FD_CLOSED) {
    close(*fd);
    *fd = FD_CLOSED;
  }
}
