#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/spage.h"
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

void print_stack (uint8_t * esp);

/* Help function: print the stack for argument passing */
void print_stack (uint8_t * esp)
{
  printf ("**** Print Stack ****\n");
  printf ("** return address is %x\n", (unsigned int) esp);
  int i, argc = *(int *) (esp+4);
  printf ("** arg number is %d\n", argc);
  char *argument, **argv = (char **) (esp+8);
  for (i = 0, argument = *argv; i!=argc; i++, argument +=4){
    printf("** arg %d is: %s\n",(i+1), *(char **)argument);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy, *pre_page;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  pre_page = palloc_get_page (0);
  
  /* this is there real name begin */
  if (fn_copy == NULL || pre_page == NULL)
    return TID_ERROR;
  /* check file_name length here */
  strlcpy (fn_copy, file_name, PGSIZE);
  struct synch_page *synch_page = (struct synch_page *)pre_page;
  /* synchronization between parent and child process */
  lock_init(&synch_page->load_lock);
  cond_init(&synch_page->load_cond);
  synch_page->next_page = &fn_copy;

  char *file_name_cpy = palloc_get_page (0);
  if(file_name_cpy == NULL ){
    /* first free previous page */
    palloc_free_page(fn_copy);
    palloc_free_page(pre_page);
    return TID_ERROR;
  }

  char *file_name_page = file_name_cpy;
  strlcpy(file_name_cpy, fn_copy, PGSIZE);
  char *fn_real, *save_ptr;
  fn_real = strtok_r(file_name_cpy, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  lock_acquire(&synch_page->load_lock);
  tid = thread_create (fn_real, PRI_DEFAULT, start_process, pre_page);
  bool create_success=true;
  if(tid == TID_ERROR ){
    create_success = false;
    lock_release(&synch_page->load_lock);
  } else {
    /*wait to know whether that thread is successfully loaded */
    cond_wait(&synch_page->load_cond, &synch_page->load_lock);   
    /* Now Parent Process knows whether Child Process successfully loaded */
    struct thread * child_t = thread_lookup_tid(tid);
    bool success = false;
    if(child_t)
      success = thread_lookup_tid(tid)->load_success;
    if(!success){
      tid = -1;
    } else {
    /* record its child, use link list*/
      process_add_child(tid);
    }
    lock_release(&synch_page->load_lock);  
  }
  palloc_free_page (file_name_page);
  /* Here, all synch is used, so free the synchronization page */
  palloc_free_page (synch_page);
  /* If create is not successful, free this page*/
  if (tid == TID_ERROR && !create_success)
    palloc_free_page (fn_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  /* move the pointer */
  struct synch_page * pre_page = ( struct sync_page *)file_name_;
  char *file_name = *(pre_page->next_page);
  struct intr_frame if_;
  bool success;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
//  printf("xxxx %d: LOAD SUCCESS %s\n", success, thread_current()->name);
  lock_acquire(&pre_page->load_lock);
  thread_current()->load_success = success;
  /* tell parent process whether loading is success */
  cond_signal(&pre_page->load_cond, &pre_page->load_lock);
  lock_release(&pre_page->load_lock);
  
  /* if success, add an entry in the exit status table */
  if(success)
    process_add_exit_status();

  /* Let the father thread know the status of loading */
  thread_yield();

  /* If load failed, quit. */
  /* There is a lock on the page file_name_, so it could not be freed */
  palloc_free_page (file_name);
//  printf("FREE PAGE OK\n");
  if (!success) {
    process_edit_exit_status(-1);
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  if(child_tid == -1)
    return -1;
  if(!process_is_child(child_tid)) {
    return -1;
  }
  /* If the child process not exit yet, child process hold lock until exit, so
   * parent process will wait here. Otherwise, parent process get wait status */
  int child_status = process_get_exit_status(child_tid);
  return child_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /* close all files this process opens, this release the space */
  fs_acquire_lock();
  if(cur->exec_file != NULL)
    file_close(cur->exec_file);
  thread_close_all_file();
  fs_release_lock();
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Add child_tid as current process's child process*/
void 
process_add_child(tid_t child_tid_)
{
  t_child_t* child_t = (t_child_t *)malloc(sizeof(t_child_t));
  child_t->child_t = child_tid_;
  struct thread * t = thread_current();
  list_push_back(&t->children_list, &child_t->elem);
  struct thread * child_thread = thread_lookup_tid(child_tid_);
  if(child_thread){
    child_thread->father_tid = t->tid;
  }
}
/* Is tid_ a child process of current process */
bool 
process_is_child(tid_t tid_)
{
  struct list_elem *e;
  struct list * children_list = &(thread_current()->children_list);
  for(e = list_begin(children_list); e != list_end(children_list);
      e = list_next (e))
  {
    if(list_entry(e, t_child_t, elem)->child_t == tid_)
      return true;
  }
  return false;
}

/* When a process is successfully created and loaded, added an entry in the 
 * exit_status list, and acquire the lock. This lock will be released after
 * this process's exit status is written*/
void
process_add_exit_status(void)
{
  struct thread_exit_status * t_status;
  t_status = (t_exit_status *)malloc(sizeof(t_exit_status));
  if ( t_status == NULL ){
    /* NO ENOUGH SPACE, this thread's exit status is not recorded */
    return;
  }
  t_status->lock = (void *)malloc(sizeof(struct lock));
  if(t_status->lock == NULL){
    free(t_status);
    return;
  }
  lock_init((struct lock *)t_status->lock);
  t_status->tid = thread_current ()->tid;
  list_push_back(exit_status_list(), &t_status->elem);
  lock_acquire((struct lock *)t_status->lock);
}

/* When a process exit, either normal or terminated by kernel, record its 
 * exit status, release the lock, so parent process could read its exit
 * status */
void
process_edit_exit_status(int status)
{
  struct list_elem *e;
  t_exit_status *t = NULL;
  fs_exit_release_lock();
  for(e = list_begin(exit_status_list()); e != list_end(exit_status_list());
      e = list_next (e))
  {
    t=list_entry(e, t_exit_status, elem);
    if(t->tid == thread_current()->tid){
      t->status = status;
      lock_release((struct lock *)t->lock);
      return;
    }
  }
}

/* Parent process get the exit status of a child's process, if child process
 * does not exit yet, this process will wait till child process written its
 * exit status */
int
process_get_exit_status(tid_t child_t)
{
  struct list_elem *e;
  t_exit_status *t = NULL;
  for(e = list_begin(exit_status_list()); e != list_end(exit_status_list());
      e = list_next (e))
  {
    t=list_entry(e, t_exit_status, elem);
    if(t->tid == child_t){
      lock_acquire((struct lock *)t->lock);
      list_remove(e);
      int status = t->status;
      lock_release((struct lock *)t->lock);
      free((struct lock *)t->lock);
      free(t);
      return status;
    }
  }
  return -1;
}

void 
process_remove_exit_status(tid_t tid)
{ 
  struct list_elem *e;
  t_exit_status *t = NULL; 
  for(e = list_begin(exit_status_list()); e != list_end(exit_status_list());)
//      e = list_next (e))
  {
    t=list_entry(e, t_exit_status, elem);
    struct list_elem *e_next = list_next (e);
    if(t->tid == tid){
      list_remove(e); 
      free((struct lock *)t->lock);
      free(t); 
    }
    e = e_next;
  } 
}
/* When a process exit, if children process already exit, free their entry in 
 * the exit_status_list */
void 
process_clear_children_exit_status(void)
{
  struct list * children_list = &(thread_current()->children_list);
  struct list_elem *e;
  for(e = list_begin(children_list); e != list_end(children_list);
      e = list_next (e))
  {
    tid_t child_tid = list_entry(e, t_child_t, elem)->child_t;
    struct thread * child_t = thread_lookup_tid(child_tid);
    if(child_t == NULL) /* if child already exit, remove its exit status */
      process_remove_exit_status(child_tid);
  }
}
/* When a parent process already exit, clear the entry in the exit_status, 
 * because no other process are allowed to read this process's exit status */
void 
process_clear_self_exit_status(void)
{
  struct thread * parent_t = thread_lookup_tid(thread_current()->father_tid);
  if(parent_t == NULL)
    process_remove_exit_status(thread_current()->tid);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp,  char *arg_list);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Enable file system synchronization here */
  fs_acquire_lock ();

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* XY: find the real file name in the argument list */
  bool set_stack_yet = false;
  char *fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    goto done;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *fn_real, *save_ptr;
  fn_real = strtok_r(file_name, " ", &save_ptr);

  /* Open executable file. */
  file = filesys_open (fn_real);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", fn_real);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", fn_real);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  set_stack_yet = true;
  /* Set up stack. */
  if (!setup_stack (esp, fn_copy))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(success){
  /* If success, lock this file, and release in thread exit or process exit */
    thread_current()->exec_file = file;
    file_deny_write (file);
  } else {
    file_close (file);
  }
  if(!set_stack_yet && fn_copy)
    palloc_free_page(fn_copy);
  fs_release_lock();
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */

static bool
load_segment_lazy (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
//  printf("LOADING SEGMENT\n");
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      /* lazy load, no need to read that page */
      if(!spage_lazy_load_file(upage, file, ofs, page_read_bytes, writable))
        return false;
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
//  printf("LOADING SEGMENT\n");
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
//      printf("LOADING GET PAGE: %u\n", pg_no(kpage));
      if (kpage == NULL){
//        printf("PALLOC PAGE FAIL, Eviction happen here:\n");
        kpage = page_eviction();
//        printf("EVICT AND GET PAGE: %u\n", pg_no(kpage));
      }

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          printf("READ FILE FAIL\n");
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          printf("INSTALL PAGE FAIL\n");
          palloc_free_page (kpage);
          return false; 
        }
      
      /* Add the page into frame table */
      uint8_t flag;
      if(writable)
        flag = FTE_EXEC | FTE_FS | FTE_W;
      else
        flag = FTE_EXEC | FTE_FS;
      struct thread * t = thread_current();
      if (!frame_set_pte(t->pagedir, upage, flag)){
        printf("INSTALL FRAME TABLE FAIL\n");
        return false;      
      }
    
      /* Add the record into supplementary page table */
      page_location ploc = SPAGE_PMEM | SPAGE_FS;
      spage_set_entry(t->pagedir, upage, ploc, 0, file, ofs, page_read_bytes);
//      printf("++++ LOAD FILE SET ENTRY CORRECT\n");
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
}

uint8_t *arg_passing_tokenize(char *arg_list, void *temp_page){
  uint8_t *addr = PHYS_BASE;
  uint8_t *addr_new;
  uint8_t *addr_page, *addr_p;
  char *token, *save_ptr;
  unsigned count = 0, i;
  addr_page = (uint8_t *)temp_page; 
  addr_p = addr_page;

  /* push the arguments from argument list into the stack */
  for (i=0, token = strtok_r (arg_list, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr), i++)
  {
    unsigned len = strlen(token) + 1;
    addr = addr - len;
    memcpy(addr, token, len);
    count ++;
    memcpy(addr_p, &addr, 4);
    addr_p = addr_p + 4;
  }

  /* set the word align */
  unsigned diff = (uint8_t*)PHYS_BASE - (uint8_t*)addr;
  addr_new = addr - (4 - (diff%4));
  
  if((uint8_t*)PHYS_BASE - addr_new > PGSIZE){
    printf("ERROR: argument stack overflow.\n");
    return NULL;
  }
  memset(addr_new, 0, addr - addr_new);
  
  /* check stack page overflow */
  if((uint8_t*)PHYS_BASE - (addr_new - 4*count - 16) > PGSIZE){
    printf("ERROR: argument stack overflow.\n");
    return NULL;
  }

  /* set the null pointer */
  addr = addr_new - 4;
  memset(addr, 0, 4);

  /* copy the addresses into the stack */
  addr = addr - 4 * count;
  addr_p = addr_page;
  memcpy(addr, addr_p, 4 * count);

  /* set the argv */
  addr_new = addr - 4;
  memcpy(addr_new, &addr, 4);

  /* set the argc */
  addr = addr_new - 4;
  *addr = count;

  /* the address for return address */
  addr = addr - 4;

  return addr;
}



/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
/*       1. push argument value, and get the addr where they are pushed
         2. align the data
         3. push the argument pointer 
         4. push argv, argc, ra, set final ESP */
static bool
setup_stack (void **esp, char * arg_list) 
{
  uint8_t *kpage;
  bool success = false;

  struct thread * t = thread_current();
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if(kpage == NULL)
    kpage = page_eviction();
  memset(kpage, 0, PGSIZE);
//  kpage = frame_palloc();
//  kpage = palloc_get_page (PAL_ZERO);
//  printf("SETUP STACK LOAD PAGE: %u\n",pg_no(kpage));
  /* To setup the stack, need a buffer space to store the pointer */
  void *temp_page = palloc_get_page (0);
  if (kpage != NULL && temp_page != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      //TODO: set the correct flag here
      uint8_t flag = FTE_SWAP | FTE_W;
      success = success &
          frame_set_pte(t->pagedir, ((uint8_t *) PHYS_BASE) - PGSIZE, flag);
      if (success){
          void * input_page = (void *)arg_list;
          *esp = arg_passing_tokenize(arg_list, temp_page);
          palloc_free_page (temp_page);
          palloc_free_page (input_page);
      }
      else {
        palloc_free_page (kpage);
        palloc_free_page (temp_page);
      }
    } else {
      /* clean the page it just allocated */
      if(kpage!=NULL)
        palloc_free_page(kpage);
      if(temp_page!=NULL)
        palloc_free_page(temp_page);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
