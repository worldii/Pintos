#ifndef FRAME_H
#define FRAME_H
#include "vm/page.h"
#include "threads/palloc.h"
#include <list.h>
#include "threads/synch.h"

// PAGE LIST
struct list page_victim_list;
struct lock page_victim_lock;
struct list_elem * page_clock;

// LRU Algorithm
void get_victim_page();
void insert_page_to_page_victim_list(struct page* page);
void delete_page_from_page_victim_list(struct page* page);

// PAGE ALLOCATE AND FREE
struct page * page_initialization(void * addr);
struct page* allocate_page(enum palloc_flags flags);
void free_page(void *physical_address);

#endif