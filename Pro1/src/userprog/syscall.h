#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

void syscall_init (void);
void halt(void);
void exit (int status);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
int create (const char *file, unsigned initial_size);
int remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);
#endif /* userprog/syscall.h */
