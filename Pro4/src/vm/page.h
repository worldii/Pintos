#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "lib/kernel/list.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct mmap_file 
{ 
  int mapid;
  struct file* file; 
  struct list_elem elem; 
  struct list virtual_memory_page_list;
};

struct virtual_memory_page
{
    uint8_t type; 
    void *virtual_address; 
    bool writable; 
    bool is_loaded; 

    struct file* file; 
    struct list_elem mmap_elem; 
    
    size_t offset; 
    size_t read_bytes; 
    size_t zero_bytes; 

    size_t swap_slot; 
    struct hash_elem elem; 

};


struct page {
    void *physical_address;
    struct virtual_memory_page *virtual_memory_page;
    struct thread *thread;
    struct list_elem lru;
    int clock;
};

void virtual_memory_page_init (struct hash *virtual_memory_page_table);
unsigned virtual_memory_page_hash_func (const struct hash_elem *e,void *aux);
bool virtual_memory_page_less_func (const struct hash_elem *a, const struct hash_elem *b, void * aux UNUSED);

bool insert_virtual_memory_page (struct hash *virtual_memory_page_table, struct virtual_memory_page *virtual_memory_page);
bool delete_virtual_memory_page (struct hash *virtual_memory_page_table, struct virtual_memory_page *virtual_memory_page);
struct virtual_memory_page *search_virtual_memory_page (void *virtual_address);

void virtual_memory_page_destroy (struct hash_elem *e, void *aux);
void virtual_memory_page_table_destroy (struct hash *virtual_memory_page_table);

void check_valid_buffer (void *buffer, unsigned size,  bool to_write);
void check_valid_string (const void *str);
bool load_file (void* physical_address, struct virtual_memory_page *virtual_memory_page);

void set_virtual_memory_page(struct virtual_memory_page *temp_vm_page, struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,bool writable,bool is_loaded, uint8_t type);
void set_stack_virtual_memory_page (struct virtual_memory_page *temp_vm_page, uint8_t * address, bool is_loaded , bool writable, uint8_t type);

#endif