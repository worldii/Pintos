#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/thread.h"

#include "threads/malloc.h"
bool dir_is_empty (struct dir *dir);

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  if(!inode_create (sector, entry_cnt * sizeof (struct dir_entry),true))
    return false;
  
    struct dir_entry temp_entry;
    struct dir *dir = dir_open(inode_open(sector));
    temp_entry.inode_sector = sector;
    if (dir == NULL)
      return false;
    if (inode_write_at(dir->inode, &temp_entry, sizeof temp_entry, 0) != sizeof temp_entry)
    {
      dir_close (dir);
      return false;
    }	
    dir_close(dir);
  return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      // 바꿔줌
      dir->pos = sizeof (struct dir_entry);
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

// 변경
  // 0 is parent dir
  for (ofs = sizeof e; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  // parent entry
  if (strcmp (name, "..") == 0) {
    inode_read_at (dir->inode, &e, sizeof e, 0);
    *inode = inode_open (e.inode_sector);
  }
  // current directory
  else if (strcmp (name, ".") == 0) {
    *inode = inode_reopen(dir->inode);
  }
  else if (lookup (dir, name, &e, NULL)) {
    *inode = inode_open (e.inode_sector);
  }
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector,bool is_dir)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;
  if (is_dir)
  {
      struct dir* child_dir = dir_open(inode_open(inode_sector));
      if (!child_dir)
        return success;
            e.inode_sector = inode_get_inumber(dir_get_inode(dir));

      if (inode_write_at(child_dir->inode, &e, sizeof(e), 0) != sizeof(e)) {
        dir_close (child_dir);
         goto done;
      }       
      dir_close (child_dir);

  }
  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;


//55
  if (inode->data.is_dir) {
    struct dir *target = dir_open(inode);
    //dir empty 고치기

    bool is_empty = dir_is_empty(target);
    
    dir_close (target);
    if (!is_empty) goto done;
  }
  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}



void split_file_dir_name (const char *path, char *directory, char *filename)
{
  char * dir_ptr = directory;
  char * file_ptr = filename;
  char * saveptr;
  char * temp_size;
  char* temp_size2="";
  char path2[strlen(path)+1];
  memcpy(path2,path,strlen(path)+1);

  if (path && strlen(path)&& path[0] == '/') {
    (*dir_ptr)= '/';  
    dir_ptr++;
  }// 절대

  temp_size = strtok_r(path2,  "/", &saveptr);

  while (temp_size != NULL) {
    if (!strlen(temp_size2)) {
      temp_size2 = temp_size;
      temp_size = strtok_r(NULL,"/",&saveptr);
    }
    else {
      if (strlen(temp_size2)>0 && dir_ptr)
      {
        memcpy(dir_ptr,temp_size2, strlen(temp_size2));
        dir_ptr[strlen(temp_size2)] = '/';
        dir_ptr += strlen(temp_size2) +1;
      }
      temp_size2 = temp_size;
      temp_size = strtok_r(NULL,"/",&saveptr);
    }
  }
  *dir_ptr= '\0';
  memcpy(file_ptr,temp_size2, strlen(temp_size2)+1);     
  
}

struct dir* open_subdir_path (const char *path)
{  
  struct dir* cur_work_dir;
    struct thread *t = thread_current();

  char path2[ strlen(path)+1];
  memcpy(path2,path ,strlen(path)+1);
  if (path &&path[0]!='/')
  {
    if (t->cur_work_dir == NULL) cur_work_dir = dir_open_root();
    else cur_work_dir = dir_reopen(t->cur_work_dir);
  }
  if (path &&path[0]=='/')
  {
      cur_work_dir = dir_open_root();
  }
   struct inode *temp_inode;
  char*savePtr;
  struct dir* dir_next;
  char*temp_size = strtok_r(path2,"/",&savePtr);
  while(temp_size != NULL){
     temp_inode = NULL;
    bool success = true;
    if(!dir_lookup(cur_work_dir, temp_size, &temp_inode)) {
      dir_close(cur_work_dir);
      return NULL;
    }
    dir_next = dir_open(temp_inode);
    if(dir_next == NULL) {
      dir_close(cur_work_dir);
      return NULL;
    }
    dir_close(cur_work_dir);
    cur_work_dir = dir_next;
    temp_size = strtok_r(NULL, "/", &savePtr);
  }

  if ( dir_get_inode(cur_work_dir)->removed) {
    dir_close(cur_work_dir);
    return NULL;
  }
  return cur_work_dir;
}
// PROJECT 5 
bool dir_is_empty (struct dir *target)
{
  struct dir_entry temp_entry;
  size_t ofs;

  for (ofs = sizeof  temp_entry; inode_read_at (target->inode, &temp_entry, sizeof temp_entry, ofs) == sizeof temp_entry;ofs += sizeof temp_entry){
    if (temp_entry.in_use) 
      return false;
  }
  return true;
}
