#include "lib/user/syscall.h"
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
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include <string.h>
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "filesys/inode.h"

struct lock file_load_lock;

static void syscall_handler (struct intr_frame *);
static struct file_descriptor* search_file_descriptor(int fd_num, int flag);

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  switch ((int)*(uint32_t *)(f->esp)) {
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
      f-> eax = tell(*(uint32_t *)(f->esp+4));
      break;
    case SYS_CLOSE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      close (*(uint32_t *)(f->esp+4));
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
    case SYS_CHDIR:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f->eax = chdir((const char *)*(uint32_t *)(f->esp + 4));
      break; 
    case SYS_MKDIR:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f->eax = mkdir((const char *)*(uint32_t *)(f->esp + 4));
      break;                 
    case SYS_READDIR:
  if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12) && is_user_vaddr(f->esp + 16)))
	    		exit(-1);
      f->eax = readdir((int)*(uint32_t *)(f->esp + 4), (char *)*(uint32_t *)(f->esp + 8));
      break;             
    case SYS_ISDIR:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f->eax = isdir((int)*(uint32_t *)(f->esp + 4));
      break;                 
    case SYS_INUMBER:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      f->eax = inumber((int)*(uint32_t *)(f->esp + 4));
      break;                 
  }
}


void
syscall_init (void) 
{
  lock_init(&file_load_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


void halt()
{
  shutdown_power_off();
}

tid_t exec (const char *cmd_line)
{
  lock_acquire(&file_load_lock);
  pid_t result = process_execute(cmd_line);
  lock_release(&file_load_lock);
  return result;
}

void 
exit (int status) 
{
  // print cmd name , status 
  printf("%s: exit(%d)\n",thread_current()->name,  status);
  // update status;
  thread_current()-> exit_status = status;
  
  struct list *fd = &thread_current()->fd_list;
  if (!list_empty(fd))
  {
    struct list_elem *start = list_begin(fd);
    struct list_elem *end = list_end(fd);
    while(!list_empty(fd))
    {
      struct list_elem *e = list_pop_front (fd);
      struct file_descriptor *temp_fd = list_entry(e, struct file_descriptor, elem);
      file_close(temp_fd->file);
      palloc_free_page(temp_fd);
    }
  }

	thread_exit();	
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
    struct file_descriptor* temp_fd = search_file_descriptor( fd, FILE_TYPE);
    if( temp_fd == NULL || temp_fd->file == NULL ) 
    {   
    lock_release(&file_load_lock);
      exit(-1);
    }    
    int readbyte = file_read(temp_fd->file, buffer, size);
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
    struct file_descriptor* temp_fd = search_file_descriptor( fd, FILE_TYPE);
    if( temp_fd == NULL || temp_fd->file == NULL)
    {    
      lock_release(&file_load_lock);
      exit(-1);
    }   
    int writebyte = file_write( temp_fd->file, buffer, size);
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
  if ( maxnum <d) maxnum = d;
  return maxnum;
}

// FIX. CREATE HAS TO BE ADDED LOCK 
bool create (const char *file, unsigned initial_size)
{ 
  // fixed 
  if (file== NULL) exit(-1);
  lock_acquire(&file_load_lock);
  bool is_created=  filesys_create(file, initial_size,false);
  lock_release(&file_load_lock);
  return is_created;
}

bool remove (const char *file)
{
  if (file == NULL) exit(-1);
  lock_acquire(&file_load_lock);
  bool is_removed = filesys_remove(file);
  lock_release(&file_load_lock);
  return is_removed;
}


int open (const char *file) 
{
   struct file* fp;
   struct file_descriptor* fd;
  if(file == NULL)
    exit(-1);

  lock_acquire(&file_load_lock);
  
  fp = filesys_open(file);
  if (fp == NULL) {
      lock_release(&file_load_lock);
      return -1; 
  } 

  fd = palloc_get_page(0);
  fd->file = fp;
  fd->dir = NULL;
  struct inode *temp_inode = file_get_inode(fd->file);

  if(temp_inode != NULL && temp_inode->data.is_dir)
  {  fd->dir = dir_open(inode_reopen(temp_inode));}
  
  struct list* fd_list = &thread_current()->fd_list;

  if (list_empty(fd_list)) fd->id = 3;  
  else 
  {
    int nextid = list_entry(list_back(fd_list), struct file_descriptor, elem)->id ;
    fd->id = nextid + 1; 
  }
  
  list_push_back(fd_list, &(fd->elem));
  if(!strcmp(thread_current()->name, file))
    file_deny_write(fp);

  lock_release (&file_load_lock);
  return fd->id;
}

int filesize (int fd) 
{
  struct file_descriptor* temp_fd = search_file_descriptor(fd, FILE_TYPE);
  if (temp_fd == NULL) exit(-1);
  return file_length(temp_fd->file);
}

void seek (int fd, unsigned position)
{
  struct file_descriptor* temp_fd = search_file_descriptor(fd, FILE_TYPE);
  if(temp_fd && temp_fd->file) file_seek(temp_fd->file, position);
}

unsigned tell (int fd) 
{
  struct file_descriptor* temp_fd = search_file_descriptor(fd, FILE_TYPE);
  if (temp_fd == NULL) exit(-1);
  if (temp_fd && temp_fd->file) return file_tell(temp_fd->file);
  return -1;
}

void close (int fd) 
{
  struct file_descriptor* temp_fd = search_file_descriptor( fd, FILE_TYPE | DIR_TYPE);
  if ( temp_fd == NULL) exit(-1);
  if (temp_fd && temp_fd->file) {
    if(temp_fd->dir) dir_close(temp_fd->dir);
    if(temp_fd->file) file_close(temp_fd->file);
    list_remove(&(temp_fd->elem));
    palloc_free_page(temp_fd);
  }
}


///// PROJECT 5 ////

bool chdir(const char *dir)
{
  return filesys_chdir(dir);
}

bool mkdir(const char *dir){
  return filesys_create(dir,0,true);
}

bool readdir(int fd, char *name){

  struct file_descriptor* temp_fd = search_file_descriptor( fd, DIR_TYPE);
  if (temp_fd == NULL){return false;}

  struct inode *inode = file_get_inode(temp_fd->file);

  if(inode == NULL || inode->data.is_dir == false) { return false;}  
  return dir_readdir (temp_fd->dir, name);
}

bool isdir(int fd)
{
  struct file_descriptor* temp_fd = search_file_descriptor( fd, FILE_TYPE | DIR_TYPE);
  if (temp_fd == NULL){ return false;}
  return file_get_inode(temp_fd->file)->data.is_dir;
}

int inumber(int fd)
{
  struct file_descriptor* temp_fd = search_file_descriptor( fd, FILE_TYPE | DIR_TYPE);
  if (temp_fd == NULL) { return false;}
  return (int)inode_get_inumber (file_get_inode(temp_fd->file));
}

static struct file_descriptor* search_file_descriptor(int fd, int flag)
{
  struct thread* t= thread_current();
  struct list_elem *start = list_begin(&t->fd_list);
  struct list_elem *end = list_end(&t->fd_list);
  struct file_descriptor *temp_fd ;

  if (list_empty(&t->fd_list)) return NULL;

  while (start != end) {
       temp_fd = list_entry(start, struct file_descriptor, elem);
        if(temp_fd->id == fd) {
          if (temp_fd->dir != NULL && (flag & DIR_TYPE))
            return temp_fd;
          else if (temp_fd->dir == NULL && (flag & FILE_TYPE)) 
            return temp_fd;
        }
      start = list_next(start);
  }
  return NULL; 
}

