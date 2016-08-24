#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <debug.h>
#include <list.h>
#include "filesys/off_t.h"
#include "devices/block.h"

#define CACHE_D 0x2   /* 0 is clean 1 is dirty */
#define CACHE_V 0x1   /* 0 is not valid, 1 is valid */
#define CACHE_IO 0x4  /* 0 is not in I/O operation, 1 is in I/O operation */
#define CACHE_EVICTING 0x8  /* 1: this entry is being evicted */
#define CACHE_FLUSH_TICKS 100 /* Cache will be flushed every 100 ticks */

struct cache_entry
  {
    block_sector_t sector ; /* Tag for this cache entry */
    uint8_t flag;           /* Valid, Dirty, I/O using flag */
    int64_t access_time;    /* Time Stamp, used for LRU */
    int32_t sharing;        /* Indicate this entry is being read/written, 
                               Only when it is finishes, I/O op could begin */
    void *data;             /* Data in this cache entry */
  };

struct run_ahead_fetch_block
  {
    block_sector_t sector;
    struct list_elem elem;
  };
typedef struct run_ahead_fetch_block prefetch_block_t;

void cache_init(void);
void cache_destroy(void);
struct cache_entry *cache_fetch(block_sector_t sector, bool pinned);
void cache_run_ahead_fetch(block_sector_t sector);
void cache_run_ahead(void);
void cache_read_block (block_sector_t sector, void *buf, off_t ofs, int length);
void cache_write_block (block_sector_t, void *buf, off_t ofs, int length);
void cache_write_back_all (void);
void cache_write_back (block_sector_t sector);
#endif
