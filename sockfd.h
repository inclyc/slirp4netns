/// \file
/// \brief Transfer file descriptor via socket

#pragma once

/// \brief send file descriptor \p fd via \p sock
/// \returns \p true for success
bool sendfd(int sock, int fd);

/// \brief receive file descriptor \p fd from \p sock
/// \returns file descriptor or negative error code.
int recvfd(int sock);
