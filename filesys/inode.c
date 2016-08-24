#include "filesys/inode.h"
#include <stdio.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define BLOCK_SECTOR_BITS 9
#define IND_MAX_CNT (BLOCK_SECTOR_SIZE/sizeof(block_sector_t))
#define SECTOR_NULL 0xffffffff                  /* The sector number does not exists */
#define DB_CNT 123                              /* The count of directly mapped blocks */
#define IND_ONE_IDX ((uint32_t)123)             /* The index in mapping for first level indirect block. */
#define IND_TWO_IDX ((uint32_t)124)             /* The index in mapping for second level indirect block. */
#define INODE_MAX_IDX (DB_CNT + IND_MAX_CNT + IND_MAX_CNT * IND_MAX_CNT)

static block_sector_t allocate_sector_zeros(void);
static block_sector_t allocate_sector_content(block_sector_t *content);
void allocate_direct(struct inode *inode, block_sector_t start, size_t cnt);
static block_sector_t allocate_indirect_Lone(size_t cnt, block_sector_t start, block_sector_t sector);
static block_sector_t allocate_indirect_Ltwo(size_t cnt, block_sector_t start, block_sector_t sector);
bool inode_growth(struct inode *inode, size_t size, off_t pos);

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t start;               /* First data sector, set to 0 now. */
//    bool isdir;                         /* If the sector is a indirect mapping */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t mapping[125];              /* Direct and indirect mapping. */    
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

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

/* print out whold directory */
void print_dir(block_sector_t *sector){
   unsigned i;
   printf("================   print dir: \n ");
   for(i = 0; i < 128; i ++){
    printf("%d  ", sector[i]);
   }
   printf("\n");
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns SECTOR_NULL if INODE does not contain data for a byte at offset
   POS. */
block_sector_t
byte_to_sector (const struct inode *inode, off_t pos, size_t size) 
{
  block_sector_t return_idx;
  ASSERT (inode != NULL);

  if ((pos + size) > inode->data.length){
    return SECTOR_NULL;
  }

  if (pos  < inode->data.length){
//    printf("byte_to_sector %d %d\n", pos, inode->data.length);
  //  size_t sec_pos = bytes_to_sectors(pos); This is confusing
//    size_t sec_cnt = bytes_to_sectors(pos); /* virtual sector number */

    /* the virtual sector number locates pos */
    block_sector_t sec_pos = pos / BLOCK_SECTOR_SIZE;
//    printf("pos %d, sec_pos %d\n", pos, sec_pos);
    if(sec_pos < DB_CNT){
      // example is sec_pos = 0 or sec_pos = 122
      return inode->data.mapping[sec_pos];
    }else if(sec_pos < DB_CNT + IND_MAX_CNT){
      block_sector_t *sector_l1 = calloc(1, BLOCK_SECTOR_SIZE);
      ASSERT(sector_l1 != NULL);
      cache_read_block(inode->data.mapping[IND_ONE_IDX], 
                       sector_l1, 0, BLOCK_SECTOR_SIZE);
      // example is sec_pos = 123, then it is the first one 

//      printf("print_dir sector_l1  %d:\n", inode->data.mapping[IND_ONE_IDX]);
//      print_dir(sector_l1);

      unsigned idx = sec_pos - DB_CNT;
/*      if((pos % BLOCK_SECTOR_SIZE == 0) && (size != 1)){
        idx += 1;
      }*/
      return_idx = sector_l1[idx];
      free(sector_l1);
//      printf("byte to sector: sec_pos %d idx %d pos %d size %d length %d return_idx %d\n", sec_pos, idx, pos, size, inode->data.length, return_idx);
      return return_idx;
    }else{
      block_sector_t *sector_l2 = calloc(1, BLOCK_SECTOR_SIZE);
      block_sector_t *sector_l1 = calloc(1, BLOCK_SECTOR_SIZE);

      ASSERT(sector_l2 != NULL);
      ASSERT(sector_l1 != NULL);

      cache_read_block(inode->data.mapping[IND_TWO_IDX], 
                       sector_l2, 0, BLOCK_SECTOR_SIZE);
      // example is sec_pos = 123 + 128
      unsigned idx2 = (sec_pos - DB_CNT - IND_MAX_CNT) / IND_MAX_CNT;
      // in this example, idx2 is 0
      cache_read_block(sector_l2[idx2], sector_l1, 0, BLOCK_SECTOR_SIZE);
      unsigned idx1 = (sec_pos - DB_CNT - IND_MAX_CNT*(1+idx2) ) % IND_MAX_CNT;
/*      if((pos % BLOCK_SECTOR_SIZE == 0) && (size != 1)){
        idx1 += 1;
      }*/
      return_idx = sector_l1[idx1];
      free(sector_l1);
      free(sector_l2);
      return return_idx;
    }
  }else
    return SECTOR_NULL;
}

/* Allocate a sector with all zero written */
static block_sector_t
allocate_sector_zeros(void)
{
  static char zeros[BLOCK_SECTOR_SIZE];
   
  block_sector_t sector = SECTOR_NULL;
  if(free_map_allocate(1, &sector))
  {
    cache_write_block(sector, zeros, 0, BLOCK_SECTOR_SIZE);
  }
  return sector;
}

/* Allocate a sector with CONTENT writeen */
static block_sector_t
allocate_sector_content(block_sector_t *content)
{
  block_sector_t sector = SECTOR_NULL;
  if(free_map_allocate(1, &sector))
  {
    cache_write_block(sector, content, 0, BLOCK_SECTOR_SIZE);
  }
  return sector;
}

/* From Start, allocate CNT blocks, e.g. start = 0, cnt = 1,
   or start = 122, cnt = 1 */
void
allocate_direct(struct inode *inode, block_sector_t start, size_t cnt)
{
    ASSERT(start + cnt <= IND_ONE_IDX);
 
    size_t i;
    block_sector_t sector_tmp = SECTOR_NULL;
    for(i = 0; i < cnt; i ++){
      sector_tmp = allocate_sector_zeros();
//      printf("%x\n", sector_tmp);
      ASSERT(sector_tmp != SECTOR_NULL);
      inode->data.mapping[start + i] = sector_tmp;
    }
    return;
}

/* Allocate a indirect sector, with CNT sub-level sectors written with empty block written */
static block_sector_t
allocate_indirect_Lone(size_t cnt, block_sector_t start, block_sector_t sector)
{
  ASSERT(cnt <= IND_MAX_CNT);

  block_sector_t *ind_block = calloc(1, BLOCK_SECTOR_SIZE);
  ASSERT(ind_block != NULL);

//  printf("in alloc_Lone: %d %d %x\n", cnt, start, sector);
 
  // If still no L1 block
  if(sector == SECTOR_NULL){
    sector = allocate_sector_zeros();
    start = 0;
  }else{
//    cache_read_block(sector, ind_block, 0, BLOCK_SECTOR_SIZE);
  }
  
//  printf("print check sector: %d\n", sector);

  ASSERT(sector != SECTOR_NULL); 
  ASSERT(start >= 0 && start <= IND_MAX_CNT);
  ASSERT(start + cnt <= IND_MAX_CNT );
  // TODO: sector is L1 level block ?
  cache_read_block(sector, ind_block, 0, BLOCK_SECTOR_SIZE);

  unsigned i = 0;
  for(i = 0; i < cnt; i ++){
    block_sector_t sector_tmp = SECTOR_NULL;
    sector_tmp = allocate_sector_zeros();
    ASSERT(sector_tmp != SECTOR_NULL);
    ind_block[start + i] = sector_tmp;
//    printf("start + i: %d", start + i);
  }
//  printf("print_dir: ind_block %d \n", sector);
//  print_dir(ind_block);
  cache_write_block(sector, ind_block, 0, BLOCK_SECTOR_SIZE);
  free(ind_block);
  return sector;
}

//TODO: what is START meaning?  
static block_sector_t
allocate_indirect_Ltwo(size_t cnt, block_sector_t start, block_sector_t sector)
{
  ASSERT(cnt <= IND_MAX_CNT * IND_MAX_CNT);
  ASSERT(start >= 0 && start <= IND_MAX_CNT * IND_MAX_CNT);
  ASSERT(start + cnt <= IND_MAX_CNT * IND_MAX_CNT);
  block_sector_t *ind_block = calloc(1, BLOCK_SECTOR_SIZE);
  ASSERT(ind_block != NULL);

  if (sector == SECTOR_NULL){
    sector = allocate_sector_zeros();
    start = 0;
  }
   
  cache_read_block(sector, ind_block, 0, BLOCK_SECTOR_SIZE);
  // start = 0, start = 128, start = 127
  block_sector_t ind_start = start / IND_MAX_CNT;
  block_sector_t ind_end = (cnt + start) / IND_MAX_CNT;
  unsigned i = 0;
  for(i = ind_start; i <= ind_end; i ++){
    block_sector_t sector_tmp = SECTOR_NULL;
    size_t sec_cnt;
    off_t sec_start;
    block_sector_t sec_sector = SECTOR_NULL;
    if(i == ind_start){
      sec_start = start % IND_MAX_CNT;
      sec_cnt = IND_MAX_CNT - sec_start;
//      sec_cnt = cnt > sec_cnt ? sec_cnt : cnt;
      if( cnt < sec_cnt )
        sec_cnt = cnt;
      cnt = cnt - sec_cnt;
      /* If write from the middle of a l1 directory, no need to apply for a new directory section */
      if(sec_start != 0)
        sec_sector = ind_block[i];
    }else{
      sec_start = 0;
      sec_cnt = cnt > IND_MAX_CNT ? IND_MAX_CNT : cnt;
      cnt = cnt - IND_MAX_CNT;
    }
    sector_tmp = allocate_indirect_Lone(sec_cnt, sec_start, sec_sector);
    ASSERT(sector_tmp != SECTOR_NULL);
    ind_block[i] = sector_tmp;
  }

  cache_write_block(sector, ind_block, 0, BLOCK_SECTOR_SIZE);

  return sector;
}

/* The size is in bytes */
bool
inode_growth(struct inode *inode, size_t size, off_t pos)
{ 
  bool success = false;
  ASSERT(inode->data.start == 0);
  /* the start sector idx to write, the first empty sector */
  block_sector_t sec_end_org = inode->data.start + bytes_to_sectors(inode->data.length);
  /* the idx of the sector where pos locates */
  block_sector_t sec_pos = inode->data.start + pos / BLOCK_SECTOR_SIZE;
  /* the idx of the next sector after writing */
  block_sector_t sec_end = inode->data.start + bytes_to_sectors(pos + size);
  /* total number of sectors for writing */
  size_t sec_cnt = sec_end - sec_end_org;
  block_sector_t sec_start = 0;

//  printf("inode growth: size %d, pos %d sec_cnt %d\n", size, pos, sec_cnt);
  
  ASSERT(sec_pos <= sec_end);
  ASSERT(sec_end >= sec_end_org);
  ASSERT(sec_end <= INODE_MAX_IDX);
  
  if (sec_cnt == 0){
    printf("inode growth error: no need to grow.\n");
    return true;
  }
  
/*  if (sec_end_org < DB_CNT) {
    size_t cnt_tmp = sec_end < DB_CNT ? sec_cnt : (DB_CNT - sec_end_org);
    allocate_direct(inode, sec_end_org, sec_cnt);
    inode->data.length = pos + size;
    printf("direct mapping: length %d\n", inode->data.length);
    success = true;
  }else if (sec_end_org < DB_CNT + IND_MAX_CNT) {
*/  

  //e.g. sec_end = 123, sec_end_org = 122 (means 0-121 is allocated)
  if (sec_end <= DB_CNT){
    allocate_direct(inode, sec_end_org, sec_cnt);
    inode->data.length = pos + size;
//    printf("direct mapping: length %d\n", inode->data.length);
    success = true;
  } 
  // e.g. sec_end = 123+128
  else if (sec_end <= DB_CNT + IND_MAX_CNT){
//    printf("HERE in first level indirect %d %d.\n", sec_end, sec_end_org);
    block_sector_t sector_tmp = SECTOR_NULL;
    //eg, sec_end_org = 123
    if (sec_end_org < DB_CNT) {
//      printf("sec_end_org < DB_CNT.\n");
      // eg, sec_end_org = 122, then map[122] is allocated
      allocate_direct(inode, sec_end_org, DB_CNT - sec_end_org);
      sec_cnt = sec_end - DB_CNT;
      sec_end_org = IND_ONE_IDX;
//      printf("sec_end_org < DB_CNT %d %d\n", sec_cnt, sec_end_org); 
    } else { 
//      printf("sec_end_org >= DB_CNT.\n");
      sector_tmp = inode->data.mapping[IND_ONE_IDX];
    }
    //TODO: sec_end_org change
    sec_start = sec_end_org - DB_CNT;
    block_sector_t sector_rec;
    sector_rec = allocate_indirect_Lone(sec_cnt, sec_start , sector_tmp);
    ASSERT(sector_rec != SECTOR_NULL);
    inode->data.length = pos + size;
    inode->data.mapping[IND_ONE_IDX] = sector_rec;
//    printf("indirect l1 mapping: length %d\n", inode->data.length);
    success = true;
  }
  
  else if (sec_end > (DB_CNT + IND_MAX_CNT)){
    block_sector_t sector_l1 = SECTOR_NULL;
    block_sector_t sector_l2 = SECTOR_NULL;

    //e.g. sec_end_org = 123
    if (sec_end_org < DB_CNT){
      allocate_direct(inode, sec_end_org, DB_CNT - sec_end_org);
      sec_cnt = sec_end - DB_CNT;
      sec_end_org = IND_ONE_IDX ;
    } else {
      sector_l1 = inode->data.mapping[IND_ONE_IDX];
    }
    //eg, sec_end_org = 124 or sec_end_org = 123
    if ( sec_end_org < DB_CNT + IND_MAX_CNT ) {
      int cnt_tmp = DB_CNT + IND_MAX_CNT - sec_end_org;
      sec_start = sec_end_org - DB_CNT;
      block_sector_t sector_rec;
      sector_rec = allocate_indirect_Lone(cnt_tmp, sec_start, sector_l1);
      inode->data.mapping[IND_ONE_IDX] = sector_rec;
 
      sec_end_org = DB_CNT + IND_MAX_CNT;
      sec_cnt = sec_end - sec_end_org;
    }else{
      sector_l2 = inode->data.mapping[IND_TWO_IDX];
    }

    sec_start = sec_end_org - (DB_CNT + IND_MAX_CNT);
    block_sector_t sector_rec;
    sector_rec =  allocate_indirect_Ltwo(sec_cnt, sec_start, sector_l2);
    inode->data.mapping[IND_TWO_IDX] = sector_rec;
    inode->data.length = pos + size;
//    printf("indirect l2 mapping: length %d\n", inode->data.length);
    success = true;
  }
  return success;
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
inode_create (block_sector_t sector, off_t length)
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
      size_t sectors = bytes_to_sectors (length);
      disk_inode->start = 0;
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
/*      if (free_map_allocate (sectors, &disk_inode->start)) 
        {
//          block_write (fs_device, sector, disk_inode);
          cache_write_block(sector, (void *)disk_inode, 0, BLOCK_SECTOR_SIZE);
          //TODO: prefetch whatever block you want
          cache_run_ahead_fetch(sector + 1);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) { 
//                block_write (fs_device, disk_inode->start + i, zeros);
                cache_write_block(disk_inode->start + i, zeros, 
                                  0, BLOCK_SECTOR_SIZE);
                //TODO: prefetch whatever block you want
                cache_run_ahead_fetch(disk_inode->start + i +1 );
              }
            }
          success = true; 
        }
*/
        cache_write_block(sector, (void *)disk_inode, 0, BLOCK_SECTOR_SIZE);
        //TODO: prefetch whatever block you want
        cache_run_ahead_fetch(sector + 1);
        struct inode * inode = inode_open(sector);
        ASSERT (inode);
        if (sectors > 0)
          {
//            printf("inode_create.\n");
            if (inode_growth(inode, length, disk_inode->start))
              success = true;
          } 
        //after inode is set, write back disk_inode back to disk
        cache_write_block(sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
      free (disk_inode);
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
  cache_read_block (inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
//TODO: prefetch whatever block you want
  cache_run_ahead_fetch(inode->sector +1 );
//  block_read (fs_device, inode->sector, &inode->data);
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
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
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
//      printf("read at all byte to sector.\n");
      block_sector_t sector_idx = byte_to_sector (inode, offset, size);
//      printf("read at: offset %d\n", offset);
      if(sector_idx == SECTOR_NULL){
//        printf("read_at error: Cannot find sector.\n");
        return 0;
      }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
 
//      printf("read at: sector_idx %x \n", sector_idx);     
      cache_read_block(sector_idx, buffer+bytes_read, sector_ofs, chunk_size);
      //TODO: prefetch whatever block you want
//      cache_run_ahead_fetch(sector_idx +1 );
/*
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          // Read full sector directly into caller's buffer. 
//          block_read (fs_device, sector_idx, buffer + bytes_read);
          cache_read_block(sector_idx, buffer+bytes_read, 
                            sector_ofs, chunk_size);
        }
      else 
        {
          // Read sector into bounce buffer, then partially copy
          //   into caller's buffer. 
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
          cache_read_block(sector_idx, buffer+bytes_read, 
                            sector_ofs, chunk_size);
        }
*/      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  if(bounce != NULL)
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

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
//      printf("write at call byte to sector.\n");
      block_sector_t sector_idx = byte_to_sector (inode, offset, size);
//      printf("write at: offset %d\n", offset);
      if(sector_idx == SECTOR_NULL){
        printf("write_at: file extended %d %d %d.\n", offset, size, inode->data.length);
        if(inode_growth(inode, size, offset)){
          printf("write at all byte to sector after growth.\n");
          sector_idx = byte_to_sector(inode, offset, size);
        }
      }
      
      ASSERT(sector_idx != SECTOR_NULL);      

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      
      cache_write_block(sector_idx, (void *)(buffer+bytes_written), 
                        sector_ofs, chunk_size );
      //TODO: prefetch whatever block you want
      //TODO: will the prefetch involve file growth ???

      cache_run_ahead_fetch( sector_idx+1 );
/*
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          // Write full sector directly to disk. 
         // block_write (fs_device, sector_idx, buffer + bytes_written);
          cache_write_block(sector_idx, (void *)(buffer + bytes_written), 0, chunk_size);
        }
      else 
        {
          // We need a bounce buffer.
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          // If the sector contains data before or after the chunk
          //   we're writing, then we need to read in the sector
          //   first.  Otherwise we start with a sector of all zeros. 
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
//          block_write (fs_device, sector_idx, bounce);
          cache_write_block(sector_idx, bounce, 0, BLOCK_SECTOR_SIZE);
        }
*/

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if(bounce)
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
