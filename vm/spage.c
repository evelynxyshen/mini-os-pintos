#include "vm/spage.h"
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "filesys/off_t.h"

/* Initiation function */
void 
sup_page_table_init(void)
{
  list_init(&sup_page_table);
  lock_init(&spt_lock);
}

void
sup_page_table_destroy(void)
{
  struct list_elem *e;
  for (e = list_begin (&sup_page_table); e != list_end (&sup_page_table);)
  {
    struct spage_elem *sp = list_entry(e, struct spage_elem, elem);
    struct list_elem * e_next = list_next(e);
    list_remove(e);
    e = e_next;
    free(sp);
  }
  return;
}

void
spage_elem_init(struct spage_elem *sp_elem)
{
  sp_elem->pd = NULL;
  sp_elem->vaddr = NULL;
  sp_elem->swap_id = 0;
  sp_elem->file = NULL;
  sp_elem->file_ofs = 0;
  sp_elem->file_size = 0;
  sp_elem->ploc = 0x000;
  return;
}  

/* Lookup the supplemental page table for a user virtual address.
   If the page exist, return pointer to entry, the specific location (memory, swap, filesys) is recorded in the spage_elem
   If the page doesn't exist, return NULL. Should fire page_fault afterwards.
*/
struct spage_elem *
spage_lookup_entry(uint32_t *pd, void *vaddr)
{
  struct list_elem *e;
//  lock_acquire(&spt_lock);
  for (e = list_begin (&sup_page_table); e != list_end (&sup_page_table); e = list_next (e))
  {
    struct spage_elem *sp = list_entry(e, struct spage_elem, elem);
    ASSERT(sp);
//    printf("look up, find 0x%x org 0x%x\n", sp->upage, upage);
    if(sp->pd == pd && sp->vaddr == vaddr){
//      lock_release(&spt_lock);
      return sp;
    }
  }
//  printf("Return NULL.\n");
//  lock_release(&spt_lock);
  return NULL;
}


/* Setup supplemental page table entry, the content of SPAGE_ELEM depends on the
 location of page: 
   If page in physical memory, record the frame table entry. 
   If page in swap space, record swap_slot number. */
void
spage_set_entry (uint32_t *pd, void *upage, page_location ploc, uint32_t swapid, struct file* file, off_t file_ofs, off_t file_size)
{
  struct spage_elem *sp_elem;
  sp_elem = spage_lookup_entry(pd, upage);
  if(sp_elem == NULL){
    sp_elem = (struct spage_elem *)malloc(sizeof(struct spage_elem));
    spage_elem_init(sp_elem);
    sp_elem->pd = pd;
    sp_elem->vaddr = upage;
    list_push_front(&sup_page_table, &sp_elem->elem);
  }
  sp_elem->ploc = sp_elem->ploc & 0x00;
  sp_elem->ploc = sp_elem->ploc | ploc;

/*  if(ploc == SPAGE_PMEM){
    sp_elem->swap_id = NULL;
    sp_elem->file = NULL;
    sp_elem->file_ofs = 0;
  }*/
  if(ploc & SPAGE_FS){
    sp_elem->file = file;
    sp_elem->file_ofs = file_ofs;
    sp_elem->file_size = file_size;
    sp_elem->swap_id = 0;
  }
  if((ploc & SPAGE_SWAP) && (ploc & (~SPAGE_PMEM))){
    sp_elem->swap_id = swapid;
    sp_elem->file = NULL;
    sp_elem->file_ofs = 0;
    sp_elem->file_size = 0;
  }
//  printf("spage_entry_set.\n");
  return;
} 

bool
spage_writeback_fs(uint32_t *pd, void *vaddr, struct file *file_in, off_t of_in, off_t size_in)
{
    printf("writeback called.\n");
    struct spage_elem * sp_elem = spage_lookup_entry(pd, vaddr);
    if (sp_elem == NULL){
      printf("error unmap:the sp_elem for file doesn't exist.\n");
      return false;
    }
    
    struct file * file = sp_elem ->file;
    off_t file_ofs = sp_elem->file_ofs;
    off_t file_size = sp_elem->file_size;

    if (file_in != NULL){
      if (file_in != file   ||
          of_in != file_ofs ||
          size_in != file_size)
      {
        printf("writeback error: records in sup_page_table diff from expected.\n");
        return false;
      }
    }
    
    uint32_t *pte = lookup_page(pd, vaddr, false);
    if(pte == NULL){
      printf("writeback error: pte for vaddr doesn't exist.\n");
      return false;
    }
    
    if((*pte & PTE_P) != 0){
      void *kpage = pagedir_get_page(pd, vaddr);
      if (pagedir_is_dirty(pd, vaddr)){
        size_t write_size = file_write_at (file, kpage, file_size, file_ofs);
        if(write_size != file_size){
          printf("write_back error: do not have enough space to write file.\n");
          return false;
        }
      }
      pagedir_clear_page (pd, vaddr);
    }
    printf("writeback correctly returned.\n");
    return true;
}
    
    

 
void
spage_remove_entry(struct spage_elem *sp_elem)
{
//  lock_acquire(&spt_lock); 
  list_remove(&sp_elem->elem);
  spage_elem_init(sp_elem);
  free(sp_elem);
//  lock_release(&spt_lock);
//  printf("spage_entry_removed\n");
  return;
}
  
bool
spage_handle_pf(uint32_t *pd, void *upage, bool write){
  lock_acquire(&spt_lock);
  struct spage_elem * sp_entry = spage_lookup_entry(pd, upage);
  if(sp_entry == NULL ){
//    printf("cannot fine entry in the sup_page_table.\n");
    goto return_false;
  }

  if(sp_entry->ploc & SPAGE_SWAP) {
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if(kpage == NULL ){
      kpage = page_eviction();
      ASSERT(kpage);
      memset(kpage, 0, PGSIZE);
    }
//    printf("+++++ GET OR EVICT A PAGE\n");
    swap_out_page(kpage, sp_entry ->swap_id);
    //TODO: verify it is a writable page
    /* Need to reset page table entry and then flush TLB */
    pagedir_set_page(pd, upage, kpage, true);
    frame_set_pte(pd, upage, FTE_SWAP);
    pagedir_activate(pd);
    if((sp_entry->ploc & SPAGE_FS) == 0 ){
      spage_remove_entry(sp_entry);
    }else{
      sp_entry->ploc = sp_entry->ploc & (~SPAGE_SWAP);
      sp_entry->ploc = sp_entry->ploc | SPAGE_PMEM;
    }
//    printf("++++ HANDLED TRUE\n");
    goto return_true;
  } else if(sp_entry->ploc & SPAGE_FS ) {
    uint32_t *pte = lookup_page(pd, upage, false);
    ASSERT(pte);
    bool writable = *pte & PTE_W;
    if(write && !writable){
      printf("write and not writable.\n");
      goto return_false;
    }else{
      void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
      if(kpage == NULL ){
        kpage = page_eviction();
        ASSERT(kpage);
        memset(kpage, 0, PGSIZE);
      }
      bool check = spage_read_fs(sp_entry, kpage);
      if (check){
        pagedir_set_page(pd, upage, kpage, true);
        goto return_true;
      }else{
        goto return_false;
        printf("xxxx EXIT due to not handle SPAGE_FS");
      }
    }
  } else if(sp_entry->ploc & SPAGE_EXEC) {
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if(kpage == NULL ){
      kpage = page_eviction();
      if(kpage == NULL)
        goto return_false;
      //This pte should be set during loading
      uint32_t *pte = lookup_page(pd, upage, false);
      if(pte == NULL)
        goto return_false;
      bool writable = *pte & PTE_W;
      memset(kpage, 0, PGSIZE);
      uint32_t length = sp_entry->file_size;
      if(length > 0) {
        file_seek(sp_entry->file, sp_entry->file_ofs);
        if(file_read(sp_entry->file, kpage, length) != length){
          palloc_free_page(kpage);
          goto return_false;
        }
      }
      pagedir_set_page(pd, upage, kpage, true);
      uint8_t flag = FTE_EXEC;
      if(writable)
        flag |= FTE_W;
      frame_set_pte(pd, upage, flag);
      pagedir_activate(pd);
      //do not remove this sup page table entry
      goto return_true;
    }
  } else {
    printf("xxxx EXIT due to not handle ELSE");
    goto return_false;
  }
return_true:
  lock_release(&spt_lock);
  return true;
return_false:
  lock_release(&spt_lock);
  return false;
}

bool
spage_lazy_load_file(void *upage, struct file* file, 
                    off_t file_ofs, off_t length_in_page,
                    bool writable)
{
  struct thread *t=thread_current();
  if(pagedir_get_page (t->pagedir, upage) != NULL)
    return false;
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (is_user_vaddr (upage));
  uint32_t *pte = lookup_page(t->pagedir, upage, true);
  if(!pte)
    return false;
  //explicted want to page fault here
  *pte = (writable ? PTE_W : 0) | PTE_U;
  page_location ploc = SPAGE_EXEC;
  ASSERT(length_in_page <= PGSIZE);
  spage_set_entry(t->pagedir, upage, ploc, 0, file, file_ofs, length_in_page);
  return true;
}

bool
spage_read_fs(struct spage_elem *sp_entry, void *kpage)
{
  memset(kpage, 0, PGSIZE);
  if (sp_entry == NULL || sp_entry->file == NULL){
      printf("spage_read_fs: Cannot find file, return a page of 0.\n");
      return true;
  }

  uint32_t length = sp_entry->file_size;
  if(length > 0) {
    file_seek(sp_entry->file, sp_entry->file_ofs);
    if(file_read(sp_entry->file, kpage, length) != length){
    //TODO: may need synch here because free page
    //Currently, this is called inside page fault handler, no other process evicting page
      palloc_free_page(kpage);
      return false;
    }
    sp_entry->ploc = sp_entry->ploc | SPAGE_PMEM;
  }
  return true;
}

