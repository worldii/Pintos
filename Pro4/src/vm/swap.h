#ifndef SWAP_H
#define SWAP_H

struct lock swap_lock;
uint8_t *swap_array;
struct block *swap_block;

void swap_initialize(void);
//copy to physical address from the data of swapped_index in swap slot.
void swap_in(size_t swapped_index, void* physical_address);
// write page directed to physical address to swap partition and return swap slot written in page s
size_t swap_out(void* physical_address);

#endif