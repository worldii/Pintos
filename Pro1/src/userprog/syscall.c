#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (!(is_user_vaddr(f->esp)))
        exit(-1);
  switch(*(uint32_t*) f->esp)
  {
	 case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if (!(is_user_vaddr(f->esp + 4)))
        exit(-1);
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      if (!(is_user_vaddr(f->esp + 4)))
        exit(-1);
      f->eax = exec ((const char* )*(uint32_t *)(f->esp + 4) );
      break;
    case SYS_WAIT:
      if (!(is_user_vaddr(f->esp + 4)))
        exit(-1);
      f->eax = wait((tid_t)*(uint32_t *)(f->esp + 4));
       break;
    case SYS_CREATE:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8)))
        exit(-1);
      break;
    case SYS_REMOVE:
      if (!(is_user_vaddr(f->esp + 4)))
       exit(-1);
      break;
    case SYS_OPEN:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      break;
    case SYS_FILESIZE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      break;
    case SYS_READ:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12)))  exit(-1);
      f->eax =read(*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12)))
	    		exit(-1);
       f->eax =write(*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_SEEK:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8)))
        exit(-1);
      break;
    case SYS_TELL:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      break;
    case SYS_CLOSE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      break;
    case SYS_FIBONACCI:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f->eax = fibonacci (*(uint32_t *)(f->esp+4));
      break; 
    case SYS_MAX_OF_FOUR_INT:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12) && is_user_vaddr(f->esp + 16)))
	    		exit(-1);
      f->eax = max_of_four_int(*(uint32_t *)(f->esp+4),*(uint32_t *)(f->esp+8),*(uint32_t *)(f->esp+12),*(uint32_t *)(f->esp+16));
      break; 
    default :
       break;
 
  }
}

void halt(void)
{
  shutdown_power_off();
}
void exit (int status)
{ 
  // print cmd name , status 
  printf("%s: exit(%d)\n",thread_current()->name,  status);
  // update status;
  thread_current()-> exit_status = status;
	thread_exit();	
}

tid_t exec (const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait (tid_t pid)
{
  return process_wait((tid_t)pid);
}

int read (int fd, void *buffer, unsigned size)
{
  if (fd ==0){
    int i;
    for (i =  0 ; i< size ; i++){
      if (input_getc() =='\0') break;
    } 
    return i;
  }
  return -1;
}

int write (int fd, const void *buffer, unsigned size)
{
  if ( fd == 1)
  {
    putbuf(buffer,size);
    return size;
  }
  return -1; 
}

int fibonacci(int n)
{
  int n1 = 0;
  int n2 = 1; 
  int sum;
  if (n < 0 )return -1;
  else if ( n<=1 ) return n;
  for (int i = 0 ; i< n-1 ; i++)
  {
    sum =n1+n2 ;
    n1= n2 ;
    n2= sum;
  } 
  return sum ;
}

int max_of_four_int(int a, int b, int c, int d)
{
  int maxnum = a;
  if (maxnum < b ) maxnum =b;
  if (maxnum < c) maxnum = c;
  if  (maxnum <d) maxnum = d;
  return maxnum;
}

int create (const char *file, unsigned initial_size);
int remove (const char *file);
int open (const char *file);
int filesize (int fd);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
