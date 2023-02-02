#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer_cache.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  // project 5 
  buffer_cache_init();
  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  buffer_cache_terminate();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size,bool is_dir) 
{
  block_sector_t inode_sector = 0;
  //struct dir *dir = dir_open_root ();
  
  // directory 나누기. 55
  char dirname[strlen(name)];
  char filename[strlen(name)];
  split_file_dir_name(name, dirname, filename);
  struct dir *dir = open_subdir_path (dirname);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size,is_dir)
                  && dir_add (dir, filename, inode_sector,is_dir));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{  if (strlen(name) == 0) return NULL;
  // project 55 subdirectory
  char dirname[strlen(name)];
  char filename[strlen(name)];
  split_file_dir_name(name, dirname, filename);
  struct dir *dir = open_subdir_path (dirname); 
  int file_len = strlen(filename);

  struct inode *temp_inode = NULL;
  if (dir == NULL) 
    return false;
  if(file_len <=0)
  {
    temp_inode = dir_get_inode (dir);
  }
  else { 
    dir_lookup (dir, filename, &temp_inode);
    dir_close (dir);
  }
  
  if (!temp_inode)
    return NULL;
  if(temp_inode->removed)
    return NULL;

  return file_open (temp_inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  if (strlen(name)==0) return NULL;
  char dirname[strlen(name)];
  char filename[strlen(name)];
  split_file_dir_name(name, dirname, filename);

  struct dir *dir = open_subdir_path (dirname);
  bool success = dir != NULL && dir_remove (dir, filename);
  dir_close (dir); 
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

// Project 5 
bool filesys_chdir (const char *name)
{
  //if (strlen(name)==0) return false;
  struct dir * dir=open_subdir_path(name);
   if(dir == NULL) {
    return false;
  }
  dir_close (thread_current()->cur_work_dir);
  thread_current()->cur_work_dir = dir;
  return true;
}