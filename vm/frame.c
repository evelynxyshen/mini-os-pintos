#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/spage.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include <string.h>
#include <random.h>

static frame_table_t frame_table;

//static bool install_page_swap (void *upage, void *kpage, bool writable);
//void frame_get_vaddr(void *kpage, void *vaddr);


void 
frame_table_init(size_t user_page_limit)
{
  /* Free memory starts at 1 MB and runs to the end of RAM. */
  uint8_t *free_start = ptov (1024 * 1024);
  uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start) / PGSIZE;
  size_t user_pages = free_pages / 2;
  size_t frame_cnt = user_pages - 1;
  if (user_pages > user_page_limit)
    user_pages = user_page_limit;
  size_t kernel_pages = free_pages - user_pages;
  
  uint8_t *start_pg = (uint8_t *)(free_start + kernel_pages * PGSIZE);
  frame_table.ft_size = user_pages - 1;
  frame_table.fte = (fte_t *)malloc(sizeof(fte_t)*frame_cnt);
  lock_init(&frame_table.ft_lock);
  memset(frame_table.fte, 0, sizeof(fte_t)*frame_cnt);
  //the actual available pages in user pool is 383 not 384
  //Seems it need +1 
  frame_table.start_page = pg_no(start_pg)+1;
  printf("FRAME TABLE START PAGE IS %u\n", frame_table.start_page);
  printf("FRAME TABLE SIZE IS %u\n", frame_table.ft_size);
  //Do not include the end page
  frame_table.end_page = frame_table.start_page + frame_table.ft_size;
}

void
destroy_frame_table(void)
{
  free(frame_table.fte);
}
/*
void * 
frame_palloc(void)
{
  uint8_t *kpage = palloc_get_page( PAL_USER | PAL_ZERO );
  if(kpage != NULL) {
    uint32_t kpage_no = pg_no(kpage);
//    lock_acquire(&frame_table.lock);
    uint32_t ft_idx = kpage_no - frame_table.start_page; //index for frame table
    frame_table.fte[ft_idx].inuse = true;
//    lock_release(&frame_table.lock);
//  } else {
    //put one page into the swap space, then allocate a new page
    //TODO: If it is backed by file, then write to file
//    kpage = frame_evict_page_simple();
  }
  return kpage;
}
*/

bool
frame_set_pte(uint32_t *pd, void *vaddr, uint8_t flag)
{
  lock_acquire(&frame_table.ft_lock);
  void *paddr = pagedir_get_page(pd, vaddr);
  uint32_t ft_idx = pg_no(paddr) - frame_table.start_page;
/*  if(frame_table.fte[ft_idx].inuse){
    printf("Frame table entry is already in use.\n");
    lock_release(&frame_table.ft_lock);
    return false;
  }
*/
  frame_table.fte[ft_idx].pd = pd;
  frame_table.fte[ft_idx].vaddr = vaddr;
  frame_table.fte[ft_idx].flag = flag;
  frame_table.fte[ft_idx].inuse = true;
  lock_release(&frame_table.ft_lock);
  return true;
}

struct frame_table_entry *
frame_get_entry(void *kpage)
{
  uint32_t kpage_no = pg_no(kpage);
  if(kpage_no < frame_table.start_page || kpage_no >= frame_table.end_page)
    return NULL;

  uint32_t ft_idx = kpage_no - frame_table.start_page;
  if(frame_table.fte[ft_idx].inuse)
    return &frame_table.fte[ft_idx];
  else
    return NULL;
}

uint32_t *
frame_get_pd(void *kpage)
{
  //kpage and pte is checked in pagedir.c
  uint32_t kpage_no = pg_no(kpage);
  if(kpage_no < frame_table.start_page || kpage_no >= frame_table.end_page)
    return NULL;

//  lock_acquire(&frame_table.lock);
  uint32_t ft_idx = kpage_no - frame_table.start_page;
  if(frame_table.fte[ft_idx].inuse)
    return frame_table.fte[ft_idx].pd;
  else
    return NULL;
//  lock_release(&frame_table.lock);
}

void *
frame_get_vaddr(void *kpage)
{
  uint32_t kpage_no = pg_no(kpage);
  if(kpage_no < frame_table.start_page || kpage_no >= frame_table.end_page)
    return NULL;

//  lock_acquire(&frame_table.lock);
  uint32_t ft_idx = kpage_no - frame_table.start_page;
  if(frame_table.fte[ft_idx].inuse)
    return frame_table.fte[ft_idx].vaddr;
  else
    return NULL;
//  lock_release(&frame_table.lock);
}

/* Randomly pick up an entry in the frame table, evict this frame by
   1. Dump this page to swap space; 2. Disconnect the pointer to previous pte
   3. TODO: If this memory is backed up by file mapping, write to file
*/
/*
void * 
frame_evict_page_simple(void)
{
  uint32_t free_idx, *pte;
//  lock_acquire(&frame_table.lock);
  free_idx = random_ulong()%frame_table.ft_size; //frame_table.evict_frame;
//  free_idx = frame_table.evict_frame;
  pte = frame_table.fte[free_idx].pte;
  frame_table.fte[free_idx].pte = 0;
  //manage page table
  *pte = *pte ^ PTE_P;
  void *free_page =
          (void *)((frame_table.start_page + free_idx) << PGBITS);
//  lock_release(&frame_table.lock);
  uint32_t block = swap_in_page(free_page);
  //change PTE_S bit, indicate this page is put in swap
  *pte = *pte | PTE_S;
  *pte = (*pte & PGMASK) | (block << PGBITS);
  memset(free_page, 0, PGSIZE);
  return free_page;
}


static bool
install_page_swap (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  * Verify that there's not already a page at that virtual
     address, then map our page there. */
//  return (pagedir_set_page (t->pagedir, upage, kpage, writable));
//}

uint32_t
frame_pick_evict_page(void)
{
  lock_acquire(&frame_table.ft_lock);
  while(true){
//    enum intr_level old_level;
//    old_level = intr_disable (); 
    frame_table.evict_idx = (frame_table.evict_idx + 1) % frame_table.ft_size;

    uint32_t free_idx = frame_table.evict_idx;
/*    if(frame_table.fte[free_idx].inuse == false)
      continue;
*/
    uint32_t *pd = frame_table.fte[free_idx].pd;
    void *vaddr = frame_table.fte[free_idx].vaddr;
    if (pd == NULL){
      continue;
    }
    if (pagedir_is_dirty(pd, vaddr)){
      pagedir_set_dirty(pd, vaddr, false);
      uint8_t flag = frame_table.fte[free_idx].flag;
      flag = flag | FTE_D;
//      intr_set_level (old_level);
      continue;
    }  
    if (pagedir_is_accessed(pd, vaddr)){
      pagedir_set_accessed(pd, vaddr, false);
//      intr_set_level (old_level);
      continue; 
    }else{
      pagedir_clear_page(pd, vaddr);
//      intr_set_level (old_level);
      frame_table.fte[free_idx].inuse = false;
      uint8_t flag = frame_table.fte[free_idx].flag;
      if((flag & FTE_SWAP) || (flag & FTE_EXEC)){
        frame_evict_to_swap(free_idx); //TODO 
        lock_release(&frame_table.ft_lock);
        return free_idx;
      }
      if(flag & FTE_FS){
//        frame_evict_to_fs();  //TODO
        frame_evict_to_swap(free_idx);
        lock_release(&frame_table.ft_lock);
        return free_idx;
      }
      continue;
    }
  }
}

void *
page_eviction()
{
  bool held_spt_lock=false;
  /* If no other process is in page fault handler, it is safe to evict any one
   * It will cause page fault for other process, and they will sleep until this
   * function return */
  if(lock_held_by_current_thread(&spt_lock))
    held_spt_lock = true;
  else
    lock_acquire(&spt_lock);
  void * temp_kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if(temp_kpage){
    if(held_spt_lock == false)
      lock_release(&spt_lock);
    return temp_kpage;
  }
  uint32_t idx = frame_pick_evict_page();
  uint32_t kpage = (uint32_t)((idx + frame_table.start_page) * PGSIZE);
  ASSERT(idx < frame_table.ft_size);
//  printf("PAGE NO is %u\n", pg_no((void *)kpage));
  if(held_spt_lock == false)
    lock_release(&spt_lock); 
  return (void *)kpage;
}

void
frame_evict_to_swap(uint32_t idx)
{
  uint32_t kpage = (uint32_t)(idx + frame_table.start_page) * PGSIZE;
  ASSERT(pg_ofs(kpage)==0);
//  printf("PAGE NO is %u\n", pg_no((void *)kpage));
  uint32_t swap_slot = swap_in_page((void *)kpage);
  void *vaddr = frame_table.fte[idx].vaddr;
  uint32_t *pd = frame_table.fte[idx].pd;
  spage_set_entry(pd, vaddr, SPAGE_SWAP, swap_slot, NULL, 0, 0);
  return;
}

void
frame_evict_to_fs(uint32_t idx, bool is_exec, bool is_dirty)
{
  uint32_t kpage = (uint32_t)(idx + frame_table.start_page) * PGSIZE;
  ASSERT(pg_ofs(kpage)==0);
  void *vaddr = frame_table.fte[idx].vaddr;
  uint32_t *pd = frame_table.fte[idx].pd;
  
  struct spage_elem *sp_elem = spage_lookup_entry(pd, vaddr);
  if (sp_elem == NULL){
    printf("ERROR: evicting a page to fs, which isn't from fs.\n");
    return NULL;
  }

  if(is_exec || (!is_dirty)){
    sp_elem->ploc = sp_elem->ploc & (~SPAGE_PMEM);
    sp_elem->ploc = sp_elem->ploc | SPAGE_FS;      
  }else{
    struct file *file = sp_elem->file; 
    off_t file_ofs = sp_elem->file;
    off_t file_size = sp_elem->file_size;
    off_t file_write_size = file_write_at(file, kpage, file_size, file_ofs);
    if (file_write_size != file_size){
        printf("Frame_evict_to_fs: No enough space to finish writing file.\n");
        return;
    }
    sp_elem->ploc = sp_elem->ploc & (~SPAGE_PMEM);
    sp_elem->ploc = sp_elem->ploc | SPAGE_FS;
  }
  return;
}


/*
void *
frame_evict_to_swap(void *upage, struct spage_elem *sp_elem)
{
//  printf("Frame to Swap eviction.\n");
  uint32_t swap_slot = sp_elem->swap_slot;
  uint32_t free_idx, *pte;
//  lock_acquire(&frame_table.lock);
  free_idx = random_ulong()%frame_table.ft_size; //frame_table.evict_frame;
  pte = frame_table.fte[free_idx].pte;
  void *vaddr = frame_table.fte[free_idx].vaddr;
  frame_table.fte[free_idx].pte = 0;
  *pte = *pte & ~PTE_P;
//  printf("pte invalided.\n");
  
  uint32_t kpage = (uint32_t)((void *)free_idx + frame_table.start_page) * PGSIZE;
  uint32_t kpage_no = (void *)free_idx + frame_table.start_page;
//  lock_release(&frame_table.lock);
  kpage = (void *)pg_round_down(kpage);
//  printf("page kpage 0x%x\n", kpage);
  uint32_t add_swap_slot = swap_in_page ((void *)kpage);
//  printf("swap_slot added.\n");

  palloc_free_page(ptov(kpage_no));
  uint8_t *kpage_new = palloc_get_page (PAL_USER | PAL_ZERO);

  swap_out_page(kpage_new, swap_slot);
  install_page_swap(sp_elem->upage, kpage_new, true);
//  *pte = *pte | PTE_P;
  spage_remove_entry(sp_elem);
  spage_set_entry(vaddr, PAGE_SWAP, NULL, add_swap_slot);
//  printf("Frame to Swap eviction END.\n");
  return;
}
*/
