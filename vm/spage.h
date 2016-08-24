#ifndef VM_SPAGE_H
#define VM_SPAGE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <debug.h>
#include <list.h>
#include "filesys/off_t.h"

typedef uint8_t page_location;

#define  SPAGE_PMEM 0x1      /* page locates in physical memory */
#define  SPAGE_SWAP 0x2      /* page locates in swap space */
#define  SPAGE_FS   0x4      /* page locates in file system */
#define  SPAGE_EXEC 0x8      /* page locates in file system, and is exec file */

struct spage_elem
{
  uint32_t *pd;
  void *vaddr;
  uint32_t swap_id;
  struct file *file;
  off_t file_ofs;
  off_t file_size;
  page_location ploc;
  struct list_elem elem;
};

/* Use list as the data structure of the supplemental page table
   The entry number can be dynamically changed */
struct list  sup_page_table;
struct lock spt_lock;

void sup_page_table_init(void);
void sup_page_table_destroy(void);
void spage_elem_init(struct spage_elem *);
struct spage_elem * spage_lookup_entry(uint32_t *, void *);
void spage_set_entry(uint32_t *, void *, page_location, uint32_t, struct file*, off_t, off_t);
bool spage_writeback_fs(uint32_t *pd, void *vaddr, struct file *file_in, off_t of_in, off_t size_in);
bool spage_read_fs(struct spage_elem *sp_entry, void *kpage);
void spage_remove_entry(struct spage_elem *);
//This is called in page_fault handler
bool spage_handle_pf(uint32_t *pd, void *upage, bool write);
#endif

