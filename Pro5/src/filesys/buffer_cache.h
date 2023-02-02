

#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include <stdbool.h>

#define NUM_CACHE 64

struct buffer_cache_entry
{	bool valid_bit;
	bool reference_bit;
    bool dirty_bit;
    block_sector_t disk_sector;	
    uint8_t buffer[BLOCK_SECTOR_SIZE]; 
};


struct buffer_cache_entry cache[NUM_CACHE]; 
struct lock buffer_cache_lock;

void buffer_cache_init ();
void buffer_cache_terminate ();
void buffer_cache_read (block_sector_t,void*);
void buffer_cache_write (block_sector_t,void *);
struct buffer_cache_entry *buffer_cache_lookup (block_sector_t);
struct buffer_cache_entry *buffer_cache_select_victim ();
void buffer_cache_flush_entry(struct buffer_cache_entry*);
void buffer_cache_flush_all();
void buffer_cache_evict_set_up(struct buffer_cache_entry* temp_buffer_cache_entry,block_sector_t sector_idx);
#endif