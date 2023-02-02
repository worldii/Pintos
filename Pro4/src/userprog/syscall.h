#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/user/syscall.h"
#include "threads/thread.h"

void syscall_init (void);
void halt(void);
void exit (int status);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

// PROJECT 4 -> mmap 일부 구현 -> test/vm/page-merge-mm
int mmap(int fd, void *addr) ;
void munmap(mapid_t mapid);
void munmap_all();
#endif /* userprog/syscall.h */