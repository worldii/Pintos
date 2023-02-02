#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

extern struct lock file_load_lock;

// New PAGE initialization
struct page * page_initialization(void * addr){
    struct page*  new_page = malloc(sizeof (struct page));
    if (new_page == NULL){ 
        exit(-1);
    }

    new_page->physical_address = addr;
    new_page->thread = thread_current();
    new_page-> virtual_memory_page = NULL;
    insert_page_to_page_victim_list(new_page);

    return new_page;
}


// Lock has to be needed.
void insert_page_to_page_victim_list(struct page *page)
{
    if (page == NULL) return ;

    lock_acquire(&page_victim_lock);
    list_push_back(&page_victim_list, &page->lru);
    lock_release(&page_victim_lock);
}


void delete_page_from_page_victim_list(struct page* page)
{
    if (page == NULL)
        return;
    list_remove(&page->lru);
}


// if physical memory is lacked, use LRU algorithm and swap it.
// correspoding to type, it varies out how to deal with it 
// and Swap out.
void get_victim_page(){
	struct page *victim_page = NULL;
    struct list_elem * page_prev = NULL;

	while(1)
	{
        lock_acquire(&page_victim_lock);
        // SELECT NEXT PAGE
        if (list_empty(&page_victim_list)){
            page_clock = NULL;
        }
        else if (page_clock == NULL) page_clock = list_begin(&page_victim_list);
        else if (page_prev)
        {
            if (list_end(&page_victim_list) == list_begin(&page_victim_list))
                page_clock = NULL; 
            else if (list_end(&page_victim_list) == page_clock){
                page_clock = list_begin(&page_victim_list);
            }
        }

		if (page_clock == NULL)
			return ;

		victim_page = list_entry(page_clock, struct page, lru);
        lock_release(&page_victim_lock);

        // CLOCK ALGORITHM
        // if access bit is 1 , set 0 
        // else acecess bit is 0 , then evict
		if(pagedir_is_accessed(victim_page->thread->pagedir,victim_page->virtual_memory_page->virtual_address))
            pagedir_set_accessed(victim_page->thread->pagedir, victim_page->virtual_memory_page->virtual_address, false);
        else if (!pagedir_is_accessed(victim_page->thread->pagedir,victim_page->virtual_memory_page->virtual_address))
            break;

        lock_acquire(&page_victim_lock);
        page_prev = page_clock;
        page_clock = list_next(page_clock);
        lock_release(&page_victim_lock);

    }

    // EVICT the page which has most counter
    switch (victim_page->virtual_memory_page->type){
        case VM_ANON :
            // this must be swapped
            victim_page->virtual_memory_page->swap_slot = swap_out(victim_page->physical_address);
            break;
        case VM_BIN :
            // if dirty bit is 1, write to swap partition and free page
            // change type to VM_ANON for demand paging.
            if (pagedir_is_dirty(victim_page->thread->pagedir, victim_page->virtual_memory_page->virtual_address)){
                victim_page->virtual_memory_page->type = VM_ANON;
                victim_page->virtual_memory_page->swap_slot = swap_out(victim_page->physical_address);
            }
            break;
        case VM_FILE :
            // if dirty bit is 1, store change content to file and free page 
            // if dirty bit is 0, free page
            if (pagedir_is_dirty(victim_page->thread->pagedir, victim_page->virtual_memory_page->virtual_address)){
                lock_acquire(&file_load_lock);
                file_write_at(victim_page->virtual_memory_page->file, victim_page->physical_address ,victim_page->virtual_memory_page->read_bytes, victim_page->virtual_memory_page->offset);
                lock_release(&file_load_lock);
            }
            break;
        default :
            exit(-1);
            break;
    }
    victim_page->virtual_memory_page->is_loaded= false;
	free_page(victim_page->physical_address);
}


// page allocation from palloc_get_page(), page initialization
// insert page to page_victim_list 
struct page* allocate_page(enum palloc_flags flags)
{
    void * addr = palloc_get_page(flags);
    struct page * new_page;

    if (addr == NULL)
    {
        while (addr == NULL) {
            get_victim_page(flags);
            addr = palloc_get_page(flags);
        }
    }
    new_page = page_initialization(addr);
    return new_page;    
}



// search page that matched physical address from page_victim_list 
// if matched, call free_memory_space_page. 
// delete page from page victim list 
// free memory space allocate to Page structure
void free_page(void *physical_address){

    struct page *temp_page;

	lock_acquire(&page_victim_lock);

    struct list_elem * start_element = list_begin(&page_victim_list);
    struct list_elem * end_element = list_end(&page_victim_list);

	while (start_element != end_element){
        temp_page = list_entry(start_element, struct page, lru);

        if (physical_address == temp_page->physical_address){
            pagedir_clear_page(temp_page->thread->pagedir, temp_page->virtual_memory_page->virtual_address);
            palloc_free_page(temp_page->physical_address);
            delete_page_from_page_victim_list(temp_page);
            free(temp_page);
            lock_release(&page_victim_lock);
            return ;
        }
        start_element = list_next(start_element);
    }
    lock_release(&page_victim_lock);
}

