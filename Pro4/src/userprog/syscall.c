#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "vm/page.h"
#include "vm/frame.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "filesys/off_t.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
struct lock file_load_lock;

/* PROJECT 4 
- READ, WRITE : check if the buffer is valid (check_valid_buffer)
- ANY SYSTEM CALL include String : check if string is valid (check_valid_string)
*/ 
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
      check_valid_string(f->esp+4);
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
      check_valid_string(f->esp+4);
      f-> eax = create((const char *) *(uint32_t *)(f->esp + 4),  *(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      if (!(is_user_vaddr(f->esp + 4)))
       exit(-1);
      check_valid_string(f->esp+4);
      f-> eax = remove((const char * )*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      check_valid_string(f->esp+4);
      f-> eax = open((const char * )*(uint32_t *)(f->esp + 4) );
      break;
    case SYS_FILESIZE:
      if (!(is_user_vaddr(f->esp + 4))) exit(-1);
      check_valid_string(f->esp+4);
      f-> eax = filesize(*(uint32_t *)(f->esp+4));
      break;
    case SYS_READ:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12)))  exit(-1);
      check_valid_buffer((void *)*(uint32_t *)(f->esp + 8),(unsigned)*((uint32_t *)(f->esp + 12)),false );
      f->eax =read(*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8) && is_user_vaddr(f->esp + 12)))
	    		exit(-1);
      check_valid_buffer((void *)*(uint32_t *)(f->esp + 8),(unsigned)*((uint32_t *)(f->esp + 12)),true);
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
    case SYS_MMAP :
      if (!(is_user_vaddr(f->esp + 4) && is_user_vaddr(f->esp + 8)))
        exit(-1);
      check_valid_string(f->esp+8);
      f->eax = mmap(*(uint32_t *)(f->esp+4),*(uint32_t *)(f->esp+8));
      break;
    case SYS_MUNMAP :
      if (!(is_user_vaddr(f->esp + 4)))
        exit(-1);
      munmap(*(uint32_t *)(f->esp+4));
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
  lock_acquire(&file_load_lock);
  if (fd == 1 || fd == 2 ) {
  lock_release(&file_load_lock);
    return fd;
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
  if ( maxnum <d) maxnum = d;
  return maxnum;
}

// FIX. CREATE HAS TO BE ADDED LOCK 
bool create (const char *file, unsigned initial_size)
{ 
  // fixed 
  if (file== NULL) exit(-1);
  lock_acquire(&file_load_lock);
  bool is_created=  filesys_create(file, initial_size);
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
  // FIXED 
  if(file == NULL)
    exit(-1);

  lock_acquire(&file_load_lock);
  struct file* temp_fd = filesys_open(file);
  lock_release(&file_load_lock);

  if (temp_fd == NULL){ 
    return -1;
  }

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

  if(!find_flag){
    return -1;

  }
  if (!strcmp(file, thread_current()->name)) 
    file_deny_write(temp_fd);
  
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
  thread_current()->fdlist[fd] =NULL;
  file_close(temp_fd);

}

// PROJECT 4 
// mmap 일부 구현 -> test/vm/page-merge-mm
int mmap(int fd, void *addr){
  // addr 에 대해서 valid string 검사를 해주어야 함 
  
  // fd 가 0 또는 1이면 안됨
  if (fd == 0 || fd == 1)
    return -1;
  if (!addr) // add mmap-null test 
    return -1;
  // file 의 주소가 pgsize alignment 에 맞아야 한다.
  if (pg_ofs(addr) % PGSIZE != 0)
    return -1;
  if (thread_current()->fdlist[fd]== NULL)
    return -1;
  
  struct mmap_file * temp_mmap_file = malloc(sizeof (struct mmap_file));
  if (!temp_mmap_file)
    return -1;
  
  temp_mmap_file->file = file_reopen(thread_current()->fdlist[fd]);

  temp_mmap_file->mapid = thread_current()->cur_map_id;
  thread_current()->cur_map_id++;

  list_init (&temp_mmap_file->virtual_memory_page_list);
  list_push_back (&thread_current ()->mmap_list, &temp_mmap_file->elem);

  size_t read_bytes = file_length(temp_mmap_file->file);

  // 파일 길이가 0 보다 작으면 없는거임. add mmap-zero test
  if (read_bytes <= 0)
    return -1;

  size_t zero_bytes = PGSIZE - read_bytes % PGSIZE; // 마지막 페이지에 들어갈 자투리 바이트
  off_t ofs = 0;

  while (read_bytes > 0 || zero_bytes > 0)
  {
    // 이미 존재하는 페이지 일 때를 계속 계산해 줌. 만약 중복 되면 에러임.
    if (search_virtual_memory_page (addr))
      return -1;

    struct virtual_memory_page *temp_vm_page = malloc(sizeof(struct virtual_memory_page));
    if (!temp_vm_page)
      return -1;

    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    // SET 
    set_virtual_memory_page(temp_vm_page, temp_mmap_file->file, ofs, addr, read_bytes, zero_bytes, true, false,VM_FILE);
    // VM_ENTRY 를 supple table virtual_memory_page_table 에 삽입. 
    insert_virtual_memory_page (&thread_current()->virtual_memory_page_table, temp_vm_page);
    // virtual_memory_page_LIST 에서도 넣음 
    list_push_back (&temp_mmap_file->virtual_memory_page_list, &temp_vm_page->mmap_elem);

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    addr += PGSIZE;
    ofs += page_read_bytes;
  }

  return temp_mmap_file->mapid;
}


void munmap(mapid_t mapid){
  struct list_elem* start_element = list_begin(&thread_current()->mmap_list);
  struct list_elem* end_element = list_end(&thread_current()-> mmap_list);

  while (start_element!= end_element){
    // mmap 파일 가져옴.
    struct mmap_file * temp_mmap_file = list_entry(start_element, struct mmap_file , elem);
    if (!temp_mmap_file) break;
    if (temp_mmap_file->mapid == mapid){
      // 일치하는 것들 지워줌.
      struct list_elem * map_start = list_begin(&temp_mmap_file->virtual_memory_page_list);
      struct list_elem * map_end = list_end(&temp_mmap_file->virtual_memory_page_list);
      
      while (map_start != map_end){
        // mmap_file 삭제
        struct virtual_memory_page * temp_vm_page = list_entry(map_start, struct virtual_memory_page, mmap_elem);
        if (temp_vm_page != NULL)
        {
          if (temp_vm_page->is_loaded){
            void *physical_address  = pagedir_get_page(thread_current()->pagedir, temp_vm_page->virtual_address);
           // MMU는 특정 주소에 접근시 Dirty bit / Access bit에 FLAG 표시를 해주는데
           // dirty bit가 check 되어있으면 swap-out할 때 syscall로 파일 변경점에 대하여 update를 해줘야 한다. 
		        if (pagedir_is_dirty(thread_current()->pagedir, temp_vm_page->virtual_address)){
              lock_acquire(&file_load_lock);
              file_write_at(temp_vm_page->file, temp_vm_page->virtual_address, temp_vm_page->read_bytes, temp_vm_page->offset);
              lock_release(&file_load_lock);
            }
            free_page(physical_address);
          }
        }
      map_start =  list_remove(&temp_vm_page->mmap_elem);
      }
      if(temp_mmap_file->file) file_close(temp_mmap_file->file);
      start_element = list_remove(&temp_mmap_file->elem);
      free(temp_mmap_file);
    }
    else 
      start_element = list_next(start_element);
  }
}



void munmap_all(){
  struct list_elem* start_element = list_begin(&thread_current()->mmap_list);
  struct list_elem* end_element = list_end(&thread_current()-> mmap_list);

  while (start_element!= end_element){
    // mmap 파일 가져옴.
    struct mmap_file * temp_mmap_file = list_entry(start_element, struct mmap_file , elem);
      // 일치하는 것들 지워줌.
      struct list_elem * map_start = list_begin(&temp_mmap_file->virtual_memory_page_list);
      struct list_elem * map_end = list_end(&temp_mmap_file->virtual_memory_page_list);
      while (map_start != map_end){
        // mmap_file 삭제
        struct virtual_memory_page * temp_vm_page = list_entry(map_start, struct virtual_memory_page, mmap_elem);
        if (temp_vm_page != NULL)
        {
          if (temp_vm_page->is_loaded){
            void *physical_address  = pagedir_get_page(thread_current()->pagedir, temp_vm_page->virtual_address);
           // MMU는 특정 주소에 접근시 Dirty bit / Access bit에 FLAG 표시를 해주는데
           // dirty bit가 check 되어있으면 swap-out할 때 syscall로 파일 변경점에 대하여 update를 해줘야 한다. 
		        if (pagedir_is_dirty(thread_current()->pagedir, temp_vm_page->virtual_address)){
              lock_acquire(&file_load_lock);
              file_write_at(temp_vm_page->file, temp_vm_page->virtual_address, temp_vm_page->read_bytes, temp_vm_page->offset);
              lock_release(&file_load_lock);
            }
            free_page(physical_address);
          }
        }
       map_start =  list_remove(&temp_vm_page->mmap_elem);
      }
    if (temp_mmap_file->file) file_close(temp_mmap_file->file);
    start_element = list_remove(&temp_mmap_file->elem);
    free(temp_mmap_file);
  }
}