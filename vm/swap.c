#include "vm/swap.h"
#include "vm/page.h"
#include "vm/spage.h"
#include <stdio.h>
#include <debug.h>
#include "devices/block.h"
#include <bitmap.h>
#include <string.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

//one page is 4KB, one block is 0.5KB, so one page will occupy 8 blocks
#define PGBLOCKBITS 3
#define SPLITPG     8

struct swap_pool 
  {
    size_t block_num;
    struct lock lock;
    struct bitmap *used_map;
  };

static struct swap_pool *swap_table;
static struct block * swap_block;

void swap_print(void)
{
  printf("***** IN SWAP_C\n");
  struct block * swap_block = block_get_role(BLOCK_SWAP);
  printf("**** BLOCK SIZE IS %u\n", block_size(swap_block));
  char temp[512] = "HELLO WORLD";
  char temp2[1024] = "HELLO WORLD HOW ARE YOU";
  char read_out[512];
  printf("***** BLOCK's NAME IS %s\n", block_name(block_get_role(BLOCK_SWAP)));
  block_write (swap_block, 0, temp);
  block_write (swap_block, 0, temp2+512);
  block_read (swap_block, 0, read_out);
  printf("**** READ FROM BLOCK IS %s\n", read_out);
}

void
test_swap(void)
{
  printf("++++ SWAP TEST BEGIN\n");
  uint8_t *kpage = palloc_get_page(0);
  memset (kpage, 0x5a, PGSIZE);
  uint32_t block = swap_in_page(kpage);
  printf("++++ BLOCK %u\n", block);
  uint8_t *upage = palloc_get_page(0);
  swap_out_page(upage, block);
  size_t i;
  for(i=0; i<8; i++){
//    block_write(swap_block, i, kpage+i*512);
//    block_read(swap_block, i, upage+i*512);
  }
  palloc_free_page(kpage);
  palloc_free_page(upage);
  for (i = 0; i < PGSIZE; i++)
    if (upage[i] != 0x5a)
      PANIC ("byte %zu != 0x5a", i);

}


void 
swap_table_init(void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  swap_table = (struct swap_pool *)malloc(sizeof (struct swap_pool));
  //free this lock when destroy?
  lock_init(&swap_table->lock);
  //get how many block number
  size_t block_num = block_size(swap_block);
  swap_table->block_num = block_num;
  //how many pages could be stored in the swap space
  size_t pages_in_swap = block_num >> PGBLOCKBITS;
  printf("---- SWAP COULD STORE %u PAGES\n",pages_in_swap);
  swap_table->used_map = bitmap_create(pages_in_swap);
}

void 
swap_table_destroy(void)
{
  bitmap_destroy(swap_table->used_map);
  free(swap_table);
}

uint32_t 
swap_get_slot(void)
{
  uint32_t swap_slot;
  lock_acquire(&swap_table->lock);
  size_t swap_page_idx = 
    bitmap_scan_and_flip(swap_table->used_map, 0, 1, false);
  lock_release(&swap_table->lock);
 
//  printf("---- GET SWAP PAGE is %u\n",swap_page_idx);
 
  if(swap_page_idx != BITMAP_ERROR)
    swap_slot = swap_page_idx << PGBLOCKBITS;
  else
    PANIC ("want to get a swap slot, no enough swap slot");
  return swap_slot;
}

void 
swap_write_page(void *kpage, uint32_t swap_slot)
{
  ASSERT(kpage);
  int i;
  lock_acquire(&swap_table->lock);
  for(i=0; i<SPLITPG; i++){
    block_write(swap_block, swap_slot+i, kpage+i*512);
  }
  lock_release(&swap_table->lock);
}

/*
bool 
swap_palloc(struct file *file, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
/*  if (spage_lookup_entry(upage) != NULL)
    return true;
*/
/*  uint8_t *kpage = palloc_get_page(0);
  if (kpage == NULL){
    printf("CANNOT GET A TEMP KERNEL PAGE.\n");
    return false;
  }
  while(read_bytes > 0 || zero_bytes > 0)
  {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
//    printf("good here.\n");
    uint32_t swap_slot = swap_get_slot ();
    if (file_read(file, kpage, page_read_bytes) != (int) page_read_bytes)
      {
          printf("READ FILE FAIL\n");
          palloc_free_page (kpage);
          return false;
        }
    memset (kpage + page_read_bytes, 0, page_zero_bytes);
    swap_write_page(kpage, swap_slot);
//    palloc_free_page(kpage);
//    printf("SWAP WRITE PAGE.\n");  
   
     Record SWAP_SLOT into supplemental page table */
//    spage_set_entry(upage, PAGE_SWAP, NULL, swap_slot);
//    printf("page 0x%x is saved into SWAP %d \n", upage, swap_slot);    

    /* Advance. */
/*    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage = upage + PGSIZE;
  }
*/
/*  return true;

}*/

uint32_t 
swap_in_page(void *kpage)
{
  uint32_t swap_slot = swap_get_slot();
  if(swap_slot!=BITMAP_ERROR){
    swap_write_page(kpage, swap_slot);
  }
//  printf ("RETURN FROM SWAP IN\n");
  return swap_slot;
}

//swap a page out, then free these swap slot
//1 bit in swap table bitmap represent 8 consecutive swap slots
void 
swap_out_page(void *kpage, uint32_t swap_slot)
{
  lock_acquire(&swap_table->lock);
  ASSERT(kpage);
  ASSERT(swap_slot < swap_table->block_num);
  ASSERT(swap_slot % 8 == 0);
  uint32_t swap_page_idx = swap_slot >> PGBLOCKBITS;
  ASSERT (bitmap_all(swap_table->used_map, swap_page_idx, 1))
  int i;
  for(i=0; i<SPLITPG; i++){
    block_read(swap_block, swap_slot+i, kpage+i*512);
  }
  //bitmap free these swapped slot
  bitmap_set(swap_table->used_map, swap_page_idx, false);
  lock_release(&swap_table->lock);
}
