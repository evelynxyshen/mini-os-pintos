#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "vm/spage.h"
#include "threads/synch.h"

#define FTE_FLAGS 0xff  /* Flag bits */
#define FTE_ORG   0x0f  /* The origin of the entry */
#define FTE_EXEC  0x1   /* From the executable file */
#define FTE_SWAP  0x2   /* File from the swap space */
#define FTE_FS    0x4   /* File from the file system */
#define FTE_EVIC  0xf0  /* Flags for eviction */
#define FTE_A     0x10  /* 1=accessed, 0=not accessed */
#define FTE_D     0x20  /* 1=dirty, 0=not dirty */
#define FTE_W     0x40  /* 1=writable, 0=read only */


struct frame_table_entry {
  uint32_t * pd;    /* The page directory corresponding to the frame table entry */
  void * vaddr;     
  uint8_t flag;
  bool inuse;
};
typedef struct frame_table_entry fte_t;

struct frame_table {
  fte_t * fte;
  struct lock ft_lock;
  size_t ft_size;
  uint32_t start_page;
  uint32_t end_page;
  uint32_t evict_idx;   /* the index of the frame which was evicted from last eviction) */
};
typedef struct frame_table frame_table_t;

//frame table will be an array, it is malloc at the palloc_initation
void frame_table_init(size_t user_page_limit);
void destroy_frame_table(void);

bool frame_set_pte(uint32_t *pd, void *vaddr, uint8_t flag);
struct frame_table_entry * frame_get_entry(void *kpage);
//void * frame_palloc(void);
//void * frame_evict_page_simple(void);
uint32_t frame_pick_evict_page(void);
void * page_eviction(void);
void frame_evict_to_swap(uint32_t idx);
void frame_evict_to_fs(uint32_t idx, bool is_exec, bool is_dirty);
void *page_eviction(void);
uint32_t * frame_get_pd(void *kpage);
void *frame_get_vaddr(void *kpage);
//bool frame_all_full(void);

//void * frame_evict(void);

#endif
