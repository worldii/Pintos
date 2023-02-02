#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "vm/swap.h"
#include "vm/page.h"

void swap_initialize(void)
{
	lock_init(&swap_lock);
	/* Returns the block device fulfilling the given ROLE, or a null
	pointer if no block device has been assigned that role. */
	swap_block = block_get_role(BLOCK_SWAP);
	if (swap_block == NULL)
		return ;

	//  0 은 사용 가능한 자료, 1은 사용 불가능한 자료임을 나타낼 때 쓰인다.
	swap_array = malloc(sizeof(uint8_t) * (block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE);
	if (!swap_array)
		return ;
	
	for (int  i =0 ; i< (block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE ; i++) {
		swap_array[i] = 0;
	}
}

void swap_in(size_t swapped_index, void* physical_address)
{
	lock_acquire(&swap_lock);
	if (swap_array[swapped_index] ==0){
		lock_release(&swap_lock);
		exit(-1);	
	}
	
	for (int i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++)
		block_read(swap_block, swapped_index * PGSIZE/BLOCK_SECTOR_SIZE + i, physical_address + i * BLOCK_SECTOR_SIZE);
	swap_array[swapped_index] = 0;

	lock_release(&swap_lock);
}


size_t swap_out(void *physical_address)
{
	int index = -1;

	lock_acquire(&swap_lock);

	for (int  i = 0 ; i < (block_size(swap_block) * BLOCK_SECTOR_SIZE) / PGSIZE ; i++ ){
		if (swap_array[i] == 0) {
			index = i;
			break;
		}
	}
	
	if (index == -1){
		lock_release(&swap_lock);
		return SIZE_MAX;
	}

	for(int i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
		block_write(swap_block, index * PGSIZE/BLOCK_SECTOR_SIZE + i, physical_address + i * BLOCK_SECTOR_SIZE);
	swap_array[index] = 1;
	
	lock_release(&swap_lock);
	
	return index;
}
