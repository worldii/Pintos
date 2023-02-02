#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/page.h"
#include "filesys/off_t.h"

#define STACK_MAX_LIMIT 32
#define EIGHT_MEGA (1<<23)

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool handle_mm_fault(struct virtual_memory_page *virtual_memory_page);
bool expand_stack(void* addr);
bool check_expand_stack(void *sp, void ** esp);
#endif /* userprog/process.h */
