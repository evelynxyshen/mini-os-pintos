#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "process.h"
#include <list.h>

void syscall_init (void);
void thread_close_all_file(void);

#endif /* userprog/syscall.h */
