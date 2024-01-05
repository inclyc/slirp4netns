#include "syscall.h"

#include <linux/sched.h> /* Definition of struct clone_args */
#include <sys/syscall.h>

#include <unistd.h>

int pidfd_open(pid_t pid, unsigned int flags) {
  return static_cast<int>(syscall(SYS_pidfd_open, pid, flags));
}

pid_t clone3(struct clone_args *cl_args) {
  return static_cast<pid_t>(syscall(SYS_clone3, cl_args, sizeof(clone_args)));
}
