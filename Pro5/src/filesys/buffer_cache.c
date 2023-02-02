#include "threads/synch.h"
#include  <debug.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/buffer_cache.h"

void buffer_cache_init()
{    
    lock_init(&buffer_cache_lock);
    for (int i = 0 ; i< NUM_CACHE ; i++) {
        cache[i].valid_bit = false;
        cache[i].reference_bit = false;
        cache[i].dirty_bit = false;
    }
}

void buffer_cache_terminate (){
    buffer_cache_flush_all();
}

void buffer_cache_read (block_sector_t sector_idx,void* user_buffer){
    lock_acquire(&buffer_cache_lock);  
    struct buffer_cache_entry *temp_buffer_cache_entry = buffer_cache_lookup(sector_idx);
   
    if (temp_buffer_cache_entry == NULL)
     {
        while (temp_buffer_cache_entry == NULL)
            temp_buffer_cache_entry = buffer_cache_select_victim();
        buffer_cache_evict_set_up(temp_buffer_cache_entry,sector_idx);
    }

    temp_buffer_cache_entry->reference_bit = true;
    memcpy(user_buffer,temp_buffer_cache_entry->buffer,BLOCK_SECTOR_SIZE);
    lock_release(&buffer_cache_lock);
}

void buffer_cache_write (block_sector_t sector_idx,void * buffer){
    lock_acquire(&buffer_cache_lock);    

    struct buffer_cache_entry * temp_buffer_cache_entry =buffer_cache_lookup(sector_idx);
    if (temp_buffer_cache_entry == NULL ) 
    {
        while (temp_buffer_cache_entry == NULL ) 
        {
            temp_buffer_cache_entry = buffer_cache_select_victim();
        }
        buffer_cache_evict_set_up(temp_buffer_cache_entry,sector_idx);
    }
    temp_buffer_cache_entry->dirty_bit = true;
    temp_buffer_cache_entry->reference_bit = true;
    memcpy(temp_buffer_cache_entry->buffer,buffer,BLOCK_SECTOR_SIZE);
    
    lock_release(&buffer_cache_lock);
}

struct buffer_cache_entry *buffer_cache_lookup (block_sector_t target){
    for (int i = 0 ; i< NUM_CACHE ; i++) {
        if (cache[i].disk_sector == target && cache[i].valid_bit == true) {
            return &cache[i];
        }
    }
    return NULL;
}


struct buffer_cache_entry *buffer_cache_select_victim (){
    int clock =0 ;

    while (1) {
        if (cache[clock].valid_bit == false)
	        return &(cache[clock]);

        if (!cache[clock].reference_bit) break;
        cache[clock].reference_bit = false;	
        clock = (clock + 1)% NUM_CACHE;
    }

    cache[clock].valid_bit = false;
    return &cache[clock];
}

void buffer_cache_flush_entry(struct buffer_cache_entry* temp_buffer_cache_entry){
    
    if (temp_buffer_cache_entry != NULL  && temp_buffer_cache_entry->valid_bit == true) {
        temp_buffer_cache_entry->dirty_bit = false;
        block_write(fs_device, temp_buffer_cache_entry->disk_sector, temp_buffer_cache_entry->buffer);
    }
}
void buffer_cache_flush_all(){
    lock_acquire(&buffer_cache_lock);    
    for (int i = 0 ; i< NUM_CACHE ; i++) {
        if (cache[i].dirty_bit == true )
            buffer_cache_flush_entry(&cache[i]);
    }
    lock_release(&buffer_cache_lock);    

};

void buffer_cache_evict_set_up(struct buffer_cache_entry* temp_buffer_cache_entry,block_sector_t sector_idx)
{
    if (!temp_buffer_cache_entry->valid_bit) temp_buffer_cache_entry->valid_bit = true; 
    if (temp_buffer_cache_entry->dirty_bit == true) {buffer_cache_flush_entry(temp_buffer_cache_entry);}        
        
    temp_buffer_cache_entry->disk_sector = sector_idx;
    temp_buffer_cache_entry->valid_bit = true;
    temp_buffer_cache_entry->dirty_bit= false;
    block_read(fs_device,sector_idx,temp_buffer_cache_entry->buffer);

}