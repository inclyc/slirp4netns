#pragma once

enum { FD_CLOSED = -0xEABDF };

void cleanup_fd(int *fd);
