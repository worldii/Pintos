#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <string.h>
#include "lib/kernel/list.h"

// hash table initialize for virtual memory page
void virtual_memory_page_init (struct hash *virtual_memory_page_table){
    hash_init(virtual_memory_page_table, virtual_memory_page_hash_func, virtual_memory_page_less_func,NULL);
}

// search virtual memory page for element 
unsigned virtual_memory_page_hash_func (const struct hash_elem *e,void *aux){
    struct virtual_memory_page * virtual_memory_page_one = hash_entry(e, struct virtual_memory_page, elem);
    return hash_int((int)virtual_memory_page_one->virtual_address);    
}

// sort by page entry address
bool virtual_memory_page_less_func (const struct hash_elem *a, const struct hash_elem *b, void * aux UNUSED){
    struct virtual_memory_page * virtual_memory_page_one = hash_entry(a, struct virtual_memory_page, elem);
    struct virtual_memory_page * virtual_memory_page_two = hash_entry(b, struct virtual_memory_page, elem);
    
    if (virtual_memory_page_two->virtual_address > virtual_memory_page_one->virtual_address)
        return true;
    return false;
}


bool insert_virtual_memory_page (struct hash *virtual_memory_page_table, struct virtual_memory_page *virtual_memory_page){
    bool is_success = true;
    struct hash_elem * virtual_memory_page_element = &virtual_memory_page->elem;
    
    if (hash_insert(virtual_memory_page_table, virtual_memory_page_element) != NULL)
        is_success = false;

    return is_success;
}


bool delete_virtual_memory_page (struct hash *virtual_memory_page_table, struct virtual_memory_page *virtual_memory_page){
   struct hash_elem *virtual_memory_page_element = &virtual_memory_page->elem;
   bool is_deleted = false;

   if (hash_delete(virtual_memory_page_table, virtual_memory_page_element) != NULL){
       is_deleted = true;
       free(virtual_memory_page);
   }
   return is_deleted;
}


// search virtual_memory_page_entry by virtual address
// by pg_round_down90 -> get the page number of virtual_adress
struct virtual_memory_page *search_virtual_memory_page (void *virtual_address) {
    struct virtual_memory_page virtual_memory_page_one;
    struct hash_elem * virtual_memory_page_element;

    virtual_memory_page_one.virtual_address =pg_round_down(virtual_address);
    virtual_memory_page_element = hash_find(&thread_current()->virtual_memory_page_table, &virtual_memory_page_one.elem);
    if (virtual_memory_page_element == NULL)
        return NULL;
    return hash_entry(virtual_memory_page_element, struct virtual_memory_page, elem);
}



// delete virtual memory page entry and hash table bucket 
void virtual_memory_page_table_destroy (struct hash *virtual_memory_page_table){
   hash_destroy(virtual_memory_page_table,virtual_memory_page_destroy);
}

void virtual_memory_page_destroy (struct hash_elem *e, void *aux){
    struct virtual_memory_page * virtual_memory_page_one = hash_entry(e, struct virtual_memory_page, elem);

	if (virtual_memory_page_one->is_loaded == true){
		void *physical_address  = pagedir_get_page(thread_current()->pagedir, virtual_memory_page_one->virtual_address);
		free_page(physical_address);
	}

    free(virtual_memory_page_one);
}


// check if the address is valid between buffer and buffer + size
// check if virtual memory page exists and virtual_memory_page_entry->writable is true
void check_valid_buffer (void *buffer, unsigned size, bool to_write)
{
    struct virtual_memory_page *temp_virtual_memory_page ;
    for (int i = 0 ; i< size ; i++) {
        if (!is_user_vaddr(buffer+i))
            exit(-1);
        temp_virtual_memory_page = search_virtual_memory_page(buffer+i);
        if (temp_virtual_memory_page == NULL)
            exit(-1);
        if (to_write == true && temp_virtual_memory_page->writable!= true)
            exit(-1);
    }
}


// check if the address is valid between string and string + string length
void check_valid_string (const void *str)
{
    struct virtual_memory_page *temp_virtual_memory_page;
    int len = strlen(str);
    for (int i = 0 ; i< len ; i++) {
        if (!is_user_vaddr(str+i))
            exit(-1);
         temp_virtual_memory_page = search_virtual_memory_page(str+i);
        if (temp_virtual_memory_page == NULL)
            exit(-1);
    }
}
void check_vme(void * addr) {
    struct virtual_memory_page *temp_virtual_memory_page;
    temp_virtual_memory_page = search_virtual_memory_page(addr);
    if (temp_virtual_memory_page == NULL)
                exit(-1);
}

// initialize field of virtual memory page 
void set_virtual_memory_page(struct virtual_memory_page *temp_virtual_memory_page, struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,bool writable,bool is_loaded, uint8_t type){
    temp_virtual_memory_page->file = file;
    temp_virtual_memory_page->offset = ofs;
    temp_virtual_memory_page->virtual_address = pg_round_down(upage);
    temp_virtual_memory_page->read_bytes = read_bytes;
    temp_virtual_memory_page->zero_bytes = zero_bytes;
    temp_virtual_memory_page->writable = writable;
    temp_virtual_memory_page->is_loaded = is_loaded;
    temp_virtual_memory_page->type = type;
}

// initialize field of stack virtual memory page 
void set_stack_virtual_memory_page (struct virtual_memory_page *temp_virtual_memory_page, uint8_t * address, bool is_loaded , bool writable, uint8_t type ){
  temp_virtual_memory_page->virtual_address     = pg_round_down(address);
  temp_virtual_memory_page->type      = type;
  temp_virtual_memory_page->is_loaded = is_loaded;
  temp_virtual_memory_page->writable  = writable;
}



// Disk -> memory data load
bool load_file(void *physical_address, struct virtual_memory_page *virtual_memory_page){
	if ((int)virtual_memory_page->read_bytes != file_read_at(virtual_memory_page->file, physical_address, virtual_memory_page->read_bytes, virtual_memory_page->offset)){
		return false;
	} 
    memset(physical_address + virtual_memory_page->read_bytes, 0, virtual_memory_page->zero_bytes);
	return true;
}


