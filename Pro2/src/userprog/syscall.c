#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
struct lock file_load_lock;

void
syscall_init (void) 
{
  lock_init(&file_load_lock);
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
      f-> eax = create((const char *) *(uint32_t *)(f->esp + 4),  *(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      if (!(is_user_vaddr(f->esp + 4)))
       exit(-1);
      f-> eax = remove((const char * )*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f-> eax = open((const char * )*(uint32_t *)(f->esp + 4) );
      break;
    case SYS_FILESIZE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f-> eax = filesize(*(uint32_t *)(f->esp+4));
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
      seek( *(uint32_t *)(f->esp+4), *(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f-> eax = tell( *(uint32_t *)(f->esp+4));
      break;
    case SYS_CLOSE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      close (  *(uint32_t *)(f->esp+4));
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
  for (int i = 3; i< 128; i++)
  {
    if (thread_current()->fdlist[i]) close(i);
  }
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
  if (!is_user_vaddr(buffer))
    exit(-1);
  lock_acquire(&file_load_lock);
  if (fd == 1 || fd == 2 ) {
    lock_release(&file_load_lock);
    return -1;
  }
  else if (fd ==0)
  {
    int i=0;
    while((char) ((char*)buffer)[i++] != '\0');
    lock_release(&file_load_lock);
    return i;
  }
  else {
    struct file* temp_fd = thread_current()-> fdlist[fd];
    if( temp_fd == NULL ) 
    {   
    lock_release(&file_load_lock);
      exit(-1);
    }    
    int readbyte = file_read(temp_fd, buffer, size);
    lock_release(&file_load_lock);
    return readbyte;
  }
  return -1;
}

int write (int fd, const void *buffer, unsigned size)
{
  lock_acquire(&file_load_lock);
  if ( fd == 1)
  {
    putbuf(buffer,size);
    lock_release(&file_load_lock);
    return size;
  }
  else if (fd>=3)
  {
    struct file* temp_fd = thread_current()-> fdlist[fd];
    if( temp_fd == NULL)
    {    
      lock_release(&file_load_lock);
      exit(-1);
    }   
    int writebyte = file_write(temp_fd, buffer, size);
    lock_release(&file_load_lock);
    return writebyte;
  }
    lock_release(&file_load_lock);
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

bool create (const char *file, unsigned initial_size)
{
  if (file== NULL) exit(-1);
  return filesys_create(file, initial_size);
}
bool remove (const char *file)
{
  if (file == NULL) exit(-1);
  return filesys_remove(file);
}
int open (const char *file)
{
  if(file == NULL) exit(-1);
  lock_acquire(&file_load_lock);
  struct file* temp_fd = filesys_open(file);
  lock_release(&file_load_lock);
  if(temp_fd == NULL){ return -1;}
  int find_flag = 0;
  for (int i = 3 ; i<128 ; i++)
  {
    if (thread_current()->fdlist[i] == NULL)
    {
      thread_current()->cur_fd_num = i;
      find_flag = 1;
      break;
    }
  } 
  if(!find_flag) {return -1;}
  if (!strcmp(file, thread_current()->name)) file_deny_write(temp_fd);
  int cur_fd = thread_current()->cur_fd_num;
  thread_current()->fdlist[cur_fd] = temp_fd;
  return cur_fd;
}

int filesize (int fd)
{
  struct file* temp_fd = thread_current()->fdlist[fd];
  if (temp_fd == NULL) exit(-1);
  return file_length(temp_fd);
}

void seek (int fd, unsigned position){
  struct file* temp_fd = thread_current()->fdlist[fd];
  if ( temp_fd == NULL) exit(-1);
  file_seek(temp_fd,position);
}

unsigned tell (int fd){
  struct file* temp_fd = thread_current()->fdlist[fd];
  if ( temp_fd == NULL) exit(-1);
  return file_tell(temp_fd);
}

void close (int fd)
{
  struct file* temp_fd = thread_current()->fdlist[fd];
  if ( temp_fd == NULL) exit(-1);
  file_close(temp_fd);
  thread_current()->fdlist[fd] =NULL;
}
