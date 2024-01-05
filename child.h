#pragma once

#include "slirp4netns.h"

int child(int sock, int pidfd, const char *tapname,
          struct slirp4netns_config *cfg);
