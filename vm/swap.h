#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void swap_print(void);
void swap_table_init(void);
void swap_table_destroy(void);

bool swap_palloc(struct file *, uint8_t *, uint32_t, uint32_t, bool);

//panic if could not get a swap slot
uint32_t swap_get_slot(void);
void swap_write_page(void *kpage, uint32_t swap_slot);

//If could not get a swap slot to put in the page, it will panic
uint32_t swap_in_page(void *kpage);
void swap_out_page(void *kpage, uint32_t swap_slot);
void swap_out_use_pte(uint32_t *pte);
#endif


