#include "filesys/cache.h"
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/timer.h"

static struct cache_entry cache[64];
static int cache_usage = 0;
static struct cache_entry * get_free_entry(void);
void cache_read(struct cache_entry *entry, void *buf, off_t ofs, int length);
void cache_write(struct cache_entry *entry, void *buf, off_t ofs, int length);
struct cache_entry * cache_lookup( block_sector_t, bool, bool);

struct lock cache_lock;
//struct lock cache_evict_lock;
struct condition cache_cond;
struct condition cache_io_cond;

/* This will be the fetch queue list run ahead used to fetch */
struct list fetch_list;
struct lock run_ahead_list_lock;

void 
cache_init()
{
  void *kpage;
  int i;
  /* 64 blocks is 8 pages */
  kpage = palloc_get_multiple(PAL_ZERO | PAL_ASSERT, 8);
  cache_usage = 0;
  int64_t current_time = timer_ticks();
  for(i = 0; i< 64; i++ ){
    cache[i].flag = 0;  /* not a valid entry now */
    cache[i].sharing = 0;
    cache[i].access_time = current_time;
    cache[i].data = kpage + i*BLOCK_SECTOR_SIZE;
  }
  lock_init(&cache_lock);
//  lock_init(&cache_evict_lock);
  cond_init(&cache_cond);
  cond_init(&cache_io_cond);
  list_init(&fetch_list);
  lock_init(&run_ahead_list_lock);
}

void
cache_destroy()
{
  cache_usage = 0;
  palloc_free_multiple(cache[0].data, 8);
}

void 
cache_read_block (block_sector_t sector, void *buf, off_t ofs, int length)
{
  /* Look up entry, fetch on miss, pinned, so it could not be evicted */
  struct cache_entry * entry = cache_lookup(sector, true, true);
  ASSERT(entry);
  cache_read(entry, buf, ofs, length);
}

void 
cache_write_block (block_sector_t sector, void *buf, off_t ofs, int length)
{
  /* Look up entry, fetch on miss, pinned, so it could not be evicted */
  struct cache_entry * entry = cache_lookup(sector, true, true);
  ASSERT(entry);
  cache_write(entry, buf, ofs, length);
}

/* If pinned, means later read or write will happen on this entry */
struct cache_entry *
cache_fetch(block_sector_t sector, bool pinned)
{
  ASSERT(!lock_held_by_current_thread(&cache_lock));
  struct cache_entry *entry = get_free_entry();

  block_read (fs_device, sector, entry->data);

  lock_acquire(&cache_lock);
  /* set the sector number, tag this add valid entry */
  entry->sector = sector;
  entry->flag = CACHE_V;  //reset evicting bit as 0
  cache_usage ++;

  /* set the access time */
  entry->access_time = timer_ticks();
  /* some process may read or write on this entry soon */
  if(pinned)
    entry->sharing = 1; 
  else
    entry->sharing = 0;
  lock_release(&cache_lock);
  ASSERT(entry->flag & CACHE_V);
  return entry;
}

/* Lookup SECTOR in cache, decide whether fetch on miss, whether pin this 
   cache line from eviction */
struct cache_entry *
cache_lookup( block_sector_t sector, bool fetch_on_miss, bool pinned )
{
  int i;
  lock_acquire(&cache_lock);
  for( i = 0; i< 64; i++ )
    if((cache[i].flag & CACHE_V) && cache[i].sector == sector ) {
    /* wait for I/O finishes */
      while(cache[i].flag & CACHE_IO)
        cond_wait(&cache_io_cond, &cache_lock);
      
      /* If want to pin this entry without eviction */
      ASSERT(cache[i].sharing >= 0);
      if(pinned)
        cache[i].sharing ++;  //this process are going to read and write on
      break;
    }
  lock_release(&cache_lock);
  if(i == 64) /* cache miss */
    {
      if(fetch_on_miss) 
          return cache_fetch(sector, pinned); 
      else
        return NULL;
    } 
  else { 
    return &cache[i];
  }
}

/* Read cache entry begin from the OFS offset, LENGTH data, to buffer BUF */
void 
cache_read( struct cache_entry *entry, void *buf, off_t ofs, int length)
{
  ASSERT( ofs + length <= BLOCK_SECTOR_SIZE);
  ASSERT( ofs >= 0 && ofs <= BLOCK_SECTOR_SIZE);
  memcpy(buf, entry->data + ofs, length);


  lock_acquire(&cache_lock);
  entry->access_time = timer_ticks();
  //sharing is set in lookup or fetch
  ASSERT(entry->sharing);
  entry->sharing -- ;
  /* read/write finish, let I/O proceed */
  if(entry->sharing == 0)
    cond_signal(&cache_cond, &cache_lock);
  lock_release(&cache_lock);
  ASSERT(entry->flag & CACHE_V);
}

/* Write cache entry begin from the OFS offset, LENGTH data, from buffer BUF */
void 
cache_write(struct cache_entry *entry, void *buf, off_t ofs, int length)
{
  ASSERT ( ofs + length <= BLOCK_SECTOR_SIZE );
  memcpy(entry->data+ofs, buf, length);

  lock_acquire(&cache_lock);
  entry->access_time = timer_ticks();
  /* during read or write, I/O could not happen */
  ASSERT(entry->sharing > 0);
  entry->sharing -- ;
  if(entry->sharing == 0)
    cond_signal(&cache_cond, &cache_lock);
  entry->flag |= CACHE_D;
  lock_release(&cache_lock);
  ASSERT(entry->flag & CACHE_V);

}

void
cache_write_back_all()
{
  /* If cache is actually used, then periodically write back to file system */
  if(!cache_usage)
    return;
  /* after cache is destroyed, then no data will be written back */
  int i;
  for ( i = 0; i < 64; i++) {
    lock_acquire(&cache_lock);
    struct cache_entry *entry = &cache[i];
    if( !(entry->flag & CACHE_V) ) {
      lock_release(&cache_lock);
      continue;
    }
    while(entry-> sharing > 0)
      cond_wait(&cache_cond, &cache_lock);
    
    /* I/O will block other reading and writing */
    if( !(entry->flag & CACHE_D) ) {  /* only write back dirty block */
      lock_release(&cache_lock);
      continue;
    }
    /* This cache line has just been evicted, no need to write back now */
    if( entry->flag & CACHE_EVICTING ) {
      lock_release(&cache_lock);
      continue;
    }
    entry->sharing = -1;
    /* after write back, this cache line is still valid */
    entry->flag |= CACHE_IO;
    entry->flag &= ~CACHE_D; //reset dirty bit
    lock_release(&cache_lock);
    block_write(fs_device, entry->sector, entry->data);
    
    lock_acquire(&cache_lock);
    entry->flag &= ~CACHE_IO; //reset I/O using bit
    entry->sharing = 0;       //Now this entry could be read/write
    /* Other process could read and write  */
    cond_signal(&cache_io_cond, &cache_lock);
    lock_release(&cache_lock);
  }
}

/* One process will decide which block it would like to prefetch */
void 
cache_run_ahead_fetch( block_sector_t sector_ )
{
  lock_acquire(&run_ahead_list_lock);
  prefetch_block_t *fetch_block = 
    (prefetch_block_t *)malloc(sizeof(prefetch_block_t));
  if(fetch_block == NULL){
    lock_release(&run_ahead_list_lock);
    return;
  }
  fetch_block->sector = sector_;
  list_push_back(&fetch_list, &fetch_block->elem);
  lock_release(&run_ahead_list_lock);
}

/* Just prefetch one and return, this will be periodically called */
void
cache_run_ahead(void)
{
  /* if cache does not begin to use, just return */
  if (!cache_usage)
    timer_sleep ((int64_t) 50);
    return;
  lock_acquire(&run_ahead_list_lock);

  /* no busy waiting, just sleep */
  if( list_empty(&fetch_list) ){
    lock_release(&run_ahead_list_lock);
    timer_sleep ((int64_t) 50);
    return;
  }
  struct list_elem * e = list_pop_front(&fetch_list);
  lock_release(&run_ahead_list_lock);
  prefetch_block_t *block = list_entry(e, prefetch_block_t, elem);
  /* lookup the sector in the cache, if not existed, fetch it, but do not
     pin it, because it will not be immediately used */
  cache_lookup(block->sector, true, false);
  free(block);
}

/* If this block in cache, then write back to file, used in close file */
void 
cache_write_back (block_sector_t sector)
{
  /* no fetch on miss, still pinned; do not let other process to evict */
  struct cache_entry * entry = cache_lookup(sector, false, true);
  if(entry == NULL)
    return;
  lock_acquire(&cache_lock);
  ASSERT (entry->sharing > 0);
  entry->sharing --;
  while(entry-> sharing > 0 )
    cond_wait(&cache_cond, &cache_lock);

  /* Now this cache line could be evicted after I/O finishes */
  cond_signal(&cache_cond, &cache_lock);
  ASSERT( entry-> flag & CACHE_V );
  if( entry->flag & CACHE_D )
    {
      entry->flag |= CACHE_IO;
      entry->flag &= ~CACHE_D; //reset dirty bit
      lock_release(&cache_lock);
      block_write(fs_device, entry->sector, entry->data);

      lock_acquire(&cache_lock);
      entry->flag &= ~CACHE_IO; //reset I/O using bit
      cond_signal(&cache_io_cond, &cache_lock);
    }
   ASSERT(entry->flag & CACHE_V);
  lock_release(&cache_lock);
}


static struct cache_entry * 
get_free_entry()
{
  ASSERT(cache_usage <= 64 );
  lock_acquire(&cache_lock);
  if (cache_usage  < 64) {
    int idx = cache_usage;
    cache_usage++;
    lock_release(&cache_lock);
    return &cache[idx];
  }
  /* LRU used to get a cache entry, TODO: no cache could be evicted ?*/
  int i=0, evict_idx = 64;
  int64_t earliest = INT64_MAX;
  for (i=0; i<64; i++)
    /* an entry could not be evicted, could not wait for I/O access */
    if( !(cache[i].flag & CACHE_EVICTING) && !(cache[i].flag & CACHE_IO)
        && cache[i].access_time < earliest ) 
      {
        earliest = cache[i].access_time;
        evict_idx = i;
      }
  ASSERT(evict_idx != 64 );
  /* wait all reading/writing on this entry to finish, hope this not happen */
  struct cache_entry *entry = &cache[evict_idx];
  while(entry->sharing > 0){
    cond_wait(&cache_cond, &cache_lock);
  }
  entry-> sharing = -1;
  /* now pick up this entry, reset valid bit */
  entry->flag &= ~CACHE_V;  //flip valid bit
  cache_usage --;
  entry->flag |= CACHE_EVICTING;  //set evicting bit
  entry->flag |= CACHE_IO;
  bool dirty = entry->flag & CACHE_D;
  lock_release(&cache_lock);
  if( dirty ){
    block_write(fs_device, entry->sector, entry->data);
  }
  return entry;
}

