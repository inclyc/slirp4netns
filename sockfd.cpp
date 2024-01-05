/// \file
/// \brief Transfer file descriptor via socket

#include "sockfd.h"

#include <cstdio>
#include <cstring>

#include <sys/socket.h>

bool sendfd(int sock, int fd) {
  cmsghdr *cmsg;
  char cmsgbuf[CMSG_SPACE(sizeof(fd))];
  char dummy = '\0';
  iovec iov{
      .iov_base = &dummy,
      .iov_len = 1,
  };
  msghdr msg{.msg_iov = &iov,
             .msg_iovlen = 1,
             .msg_control = cmsgbuf,
             .msg_controllen = sizeof(cmsgbuf)};

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
  msg.msg_controllen = cmsg->cmsg_len;
  if (ssize_t err = sendmsg(sock, &msg, 0); err < 0) {
    perror("sendmsg");
    return false;
  }
  return true;
}

int recvfd(int sock) {
  int fd;
  char dummy = '\0';
  iovec iov{
      .iov_base = &dummy,
      .iov_len = 1,
  };
  char cmsgbuf[CMSG_SPACE(sizeof(fd))];
  msghdr msg{.msg_iov = &iov,
             .msg_iovlen = 1,
             .msg_control = cmsgbuf,
             .msg_controllen = sizeof(cmsgbuf)};
  ssize_t rc;
  if (rc = recvmsg(sock, &msg, 0); rc < 0) {
    perror("recvmsg");
    return (int)rc;
  }
  if (rc == 0) {
    fprintf(stderr, "the message is empty\n");
    return -1;
  }
  cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
    fprintf(stderr, "the message does not contain fd\n");
    return -1;
  }
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  return fd;
}
