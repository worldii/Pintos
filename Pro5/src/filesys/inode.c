#include "filesys/inode.h"
#include "filesys/buffer_cache.h"

//static block_sector_t index_to_sector (const struct inode_disk *idisk, off_t index);
static bool inode_allocated (struct inode_disk *disk_inode, off_t length);
static bool inode_indirect_allocated (block_sector_t* temp_sector, size_t num_sectors, int level);
static void inode_freed (struct inode *inode);
static void inode_indirect_freed (block_sector_t entry, size_t num_sectors, int level);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

// Project 5 //
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  if (pos >= inode->data.length) return -1;
  struct inode_disk *idisk = &inode->data;
  off_t index = pos / BLOCK_SECTOR_SIZE;
  block_sector_t block_result;
  off_t start = 0 , end = 0;

  // Direct
  end = NUM_DIRECT_BLOCK;
  if (index < end) {
    return idisk->direct_blocks[index];
  }

  // Indirect
  start = end;
  end += INDIRECT_BLOCKS_PER_SECTOR *NUM_INDIRECT_BLOCK ;
  if ( index < end ) 
  {
    struct  indir_block * temp_indirect_block = calloc(1,sizeof(struct indir_block));
    if (temp_indirect_block== NULL)
      return -1;

    buffer_cache_read(idisk->indirect_block, temp_indirect_block);
    block_result = temp_indirect_block->blocks[index - start];
    free(temp_indirect_block);
    return block_result;
  }

  // Double Indirect 
  start = end ;
  end +=  INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR ;
  if (index < end ) 
  {
    struct indir_block * temp_indirect_block =calloc(1,sizeof(struct indir_block));
    if (temp_indirect_block == NULL)
      return -1;
    buffer_cache_read(idisk->double_indirect_block,temp_indirect_block);
    buffer_cache_read(temp_indirect_block->blocks[(index-start) /INDIRECT_BLOCKS_PER_SECTOR],temp_indirect_block);
    block_result = temp_indirect_block->blocks[(index-start) % INDIRECT_BLOCKS_PER_SECTOR];
    free(temp_indirect_block);
    return block_result;
  }

  return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length,bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      //size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->is_dir = is_dir;

      disk_inode->magic = INODE_MAGIC;
      //55
      // 여기에 inode_allocated 하는 브븐 들어가야함 . buffer cache    
      if (inode_allocated (disk_inode, disk_inode->length))
      {
        buffer_cache_write (sector, disk_inode); //buffer cache
        success = true;
        free (disk_inode);
      }
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
   // buffer cache 로 바꾸어줌 .
  buffer_cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
         /* free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
        */
        // 55
        // 여기 inoe free 하는 부분 들어야 가함
                  inode_freed (inode);

        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          
          //block_read (fs_device, sector_idx, buffer + bytes_read);
          buffer_cache_read(sector_idx,buffer+bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
         // block_read (fs_device, sector_idx, bounce);
          buffer_cache_read(sector_idx,bounce);

          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

    // 55 
    // FILE GROWTH
  int len = offset + size;
  if ( offset + size > inode -> data.length)
   {
    bool success = inode_allocated (& inode->data, len);
    if (!success) return 0; 
    inode->data.length = len;
    buffer_cache_write (inode->sector, & inode->data);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          //block_write (fs_device, sector_idx, buffer + bytes_written);
          buffer_cache_write(sector_idx,buffer+bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            //block_read (fs_device, sector_idx, bounce);
            buffer_cache_read(sector_idx,bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          //block_write (fs_device, sector_idx, bounce);
          buffer_cache_write(sector_idx,bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}


static bool inode_allocated (struct inode_disk *disk_inode, off_t length)
{
  static char zero[BLOCK_SECTOR_SIZE];

 // ASSERT (length >= 0 && disk_inode != NULL);
  // 파일 크기 없애줌 .
  if (length < 0) return false;
  size_t allocate_index = bytes_to_sectors(length);
  size_t limit ;

  // Direct 
  if (allocate_index < NUM_DIRECT_BLOCK)
  {
    limit = allocate_index;
  }
  else
    limit = NUM_DIRECT_BLOCK;
  
  for (int i = 0 ; i< limit ; i++) 
  {
    if (disk_inode->direct_blocks[i] == 0){
        if(!free_map_allocate(1, &disk_inode->direct_blocks[i]))
          return false;
      buffer_cache_write(disk_inode->direct_blocks[i], zero);}
  }
  allocate_index -= limit ;
  if (allocate_index==0)
    goto end;

  // InDirect
  if (allocate_index < INDIRECT_BLOCKS_PER_SECTOR)
  {
    limit = allocate_index;
  }
  else 
    limit = INDIRECT_BLOCKS_PER_SECTOR;
  if(!inode_indirect_allocated(&disk_inode->indirect_block, limit, INDIRECT_LEVEL)) return false;
  // Indirect 호출 
  allocate_index -= limit ;
  if (allocate_index==0)
    goto end;
  

  // Double InDirect
  if (allocate_index < INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR)
  {
    limit = allocate_index;
  }
  else 
    limit = INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR;
  if(!inode_indirect_allocated(&disk_inode->double_indirect_block, limit, DOUBLE_INDIRECT_LEVEL)) return false;
  // Indirect 호출 
  allocate_index -= limit ;

  if (allocate_index==0)
    goto end;
  
end:
    if (allocate_index==0)
      return true;
    else return false ;
}

static bool inode_indirect_allocated (block_sector_t* temp_sector, size_t num_sectors, int level)
{
  ASSERT (level <=2 );   
  int temp_sector_size ; 
  struct indir_block temp_indirect_block;   
  static char zero[BLOCK_SECTOR_SIZE];
    // 하나 할당 함 .
    if( *temp_sector == 0)
    {
      if (!free_map_allocate(1,temp_sector))
        return false;
      buffer_cache_write(*temp_sector,zero);
    }
  if (level >2) exit(-1);

  if (level == DIRECT_LEVEL) // direct
  {
    return true;
  }
  else {
    buffer_cache_read(*temp_sector, &temp_indirect_block);

    int range =1;
    if (level == INDIRECT_LEVEL)
    {
      range = 1;    
      int limit = DIV_ROUND_UP (num_sectors,range);
      for (int i = 0 ; i< limit ; i++) 
      {
        if (!inode_indirect_allocated(&temp_indirect_block.blocks[i],temp_sector_size,level -1)) return false;
        num_sectors-= 1;
      }

    }
    if (level == DOUBLE_INDIRECT_LEVEL)
    {
      range = INDIRECT_BLOCKS_PER_SECTOR;    
      int limit = DIV_ROUND_UP (num_sectors,range);
      for (int i = 0 ; i< limit ; i++) 
      {
        int temp_sector_size = range;
        if (temp_sector_size > num_sectors) temp_sector_size = num_sectors;
        if (!inode_indirect_allocated(&temp_indirect_block.blocks[i],temp_sector_size,level -1)) return false;
        num_sectors-= temp_sector_size;
      }
    } 

  }
  buffer_cache_write(*temp_sector, &temp_indirect_block);
  //  ASSERT(num_sectors == 0)  
  return true;
}

static void inode_freed (struct inode *inode){

  size_t limit ;
  size_t allocate_index = bytes_to_sectors(inode->data.length);
  
  // Direct 
  if (allocate_index < NUM_DIRECT_BLOCK)
  {
    limit = allocate_index;
  }
  else
    limit = NUM_DIRECT_BLOCK;
  
  for (int i = 0; i < limit;  i++) {
    free_map_release (inode->data.direct_blocks[i], 1);
  }
  allocate_index -= limit ;

  // indirect 
  if (allocate_index < INDIRECT_BLOCKS_PER_SECTOR)
  {
    limit = allocate_index;
  }
  else{
    limit = NUM_DIRECT_BLOCK;
  }
  if (limit >0)
  {  
    inode_indirect_freed (inode->data.indirect_block, limit, INDIRECT_LEVEL);
  // 구현
  allocate_index -= limit ;
  }
  if (allocate_index <  INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR)
  {
    limit = allocate_index;
  }
  else
    limit = INDIRECT_BLOCKS_PER_SECTOR * INDIRECT_BLOCKS_PER_SECTOR;

  // Double Free indirect 
  // 구현
  if (limit >0) {
    inode_indirect_freed (inode->data.double_indirect_block, limit, DOUBLE_INDIRECT_LEVEL);
    allocate_index -= limit ;
  }
  //ASSERT(allocate_index == 0);
}


static void inode_indirect_freed (block_sector_t entry, size_t num_sectors, int level)
{
  ASSERT(level<=2);

  if (level > 2) exit(-1) ;
  
  if (level == DIRECT_LEVEL) // DIRECT  
  {
    free_map_release(entry,1);
  }
  else
   {
  // level 에 따라 range 가 다름 
  int range;
  if (level == INDIRECT_LEVEL)
    range = 1;
  if (level == DOUBLE_INDIRECT_LEVEL)
    range = INDIRECT_BLOCKS_PER_SECTOR;
  struct indir_block temp_indirect_block;

  int limit = DIV_ROUND_UP (num_sectors,range);
  buffer_cache_read(entry, &temp_indirect_block);

  for (int i = 0 ; i< limit ; i++){
    int temp_sector_size = range;
    if (temp_sector_size > num_sectors) temp_sector_size = num_sectors;
    inode_indirect_freed(temp_indirect_block.blocks[i], temp_sector_size, level-1);
    num_sectors -= temp_sector_size;
  }

  ASSERT(num_sectors == 0);
  free_map_release(entry,1);
  }
}




