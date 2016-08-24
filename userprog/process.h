#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* When a process is successfully created and loaded, added an entry in the 
 * exit_status list, and acquire the lock. This lock will be released after
 * this process's exit status is written*/
void process_add_exit_status(void);

/* When a process exit, either normal or terminated by kernel, record its 
 * exit status, release the lock, so parent process could read its exit
 * status */
void process_edit_exit_status(int status);

/* Parent process get the exit status of a child's process, if child process
 * does not exit yet, this process will wait till child process written its
 * exit status */
int process_get_exit_status(tid_t child_t);

void process_remove_exit_status(tid_t tid);
/* When a process exit, if children process already exit, free their entry in 
 * the exit_status_list */
void process_clear_children_exit_status(void);

/* When a parent process already exit, clear the entry in the exit_status, 
 * because no other process are allowed to read this process's exit status */
void process_clear_self_exit_status(void);

/* Add child_tid as current process's child process*/
void process_add_child(tid_t child_tid);

/* Is tid_ a child process of current process */
bool process_is_child(tid_t tid_);

struct synch_page 
  {
    struct lock load_lock;
    struct condition load_cond;
    void ** next_page;
  } ;

#endif /* userprog/process.h */
