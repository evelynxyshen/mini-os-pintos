#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/vaddr.h"
#include <string.h>
#include <random.h>
/*
bool
handle_page_fault(uint32_t *pte)
{
  //If this page is in swap space
  if(*pte & PTE_S){
    void *kpage = frame_evict_page_simple();
    ASSERT(pg_ofs(kpage) == 0);
    frame_get_pte(kpage, pte);
    uint32_t swap_slot = *pte >> PGBITS;
    swap_out_page(kpage, swap_slot);
    *pte = (vtop(kpage) | (*pte & PGMASK) | PTE_P )^ PTE_S ;
    ASSERT((*pte & PTE_S) == 0);
    return true; 
  } else
    return false;
}
*/
