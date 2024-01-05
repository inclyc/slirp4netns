#include <sys/types.h>

int pidfd_open(pid_t pid, unsigned int flags);

pid_t clone3(struct clone_args *cl_args);
