#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool handle_page_fault(uint32_t *pte);

void test_swap(void);
#endif
