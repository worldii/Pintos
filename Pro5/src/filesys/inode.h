

#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT_BLOCK 123
#define NUM_INDIRECT_BLOCK 1 
#define NUM_DOUBLE_INDIRECT_BLOCK 1 

#define INDIRECT_BLOCKS_PER_SECTOR 128 // 512/ 4(포인터 사이즈 크기) 
#define MAX_FILE_SIZE 16384 // 핀토스 파일 시스템의 최대 크기는 8MB 이다.

#define DIRECT_LEVEL 0
#define INDIRECT_LEVEL 1 
#define DOUBLE_INDIRECT_LEVEL 2 

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    bool is_dir;
   // block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
   // uint32_t unused[125];               /* Not used. */

    block_sector_t direct_blocks[NUM_DIRECT_BLOCK];
    block_sector_t indirect_block; // (128)
    block_sector_t double_indirect_block; // (128) * (128);
  };

struct indir_block {
  block_sector_t blocks[INDIRECT_BLOCKS_PER_SECTOR];
};


/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

struct bitmap;

void inode_init (void);
bool inode_create (block_sector_t, off_t,bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#endif /* filesys/inode.h */