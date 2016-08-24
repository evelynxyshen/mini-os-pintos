#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h" 
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "lib/round.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>
#ifdef VM
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/spage.h"
#include "vm/frame.h"
#endif

#define BLOCK_SECTOR_SIZE 512

static void syscall_handler (struct intr_frame *);
struct mmap_struct *file_mmap_lookup_mapid(struct thread *t, mapid_t mapid);

void syscall_print_argument (struct intr_frame *f UNUSED);
static bool valid_ptr (void * ptr);
static void validate_syscall_args(const void * ptr, int argc);
static void check_page(void * ptr, struct intr_frame *f);
static void check_writable(void * ptr);
static void exit_and_print(void);
void syscall_exit (struct intr_frame *f UNUSED);
void syscall_write (struct intr_frame *f UNUSED);
void syscall_exec (struct intr_frame *f);
void syscall_wait (struct intr_frame *f);
void syscall_create (struct intr_frame *f);
void syscall_remove (struct intr_frame *f);
void syscall_open (struct intr_frame *f);
void syscall_close (struct intr_frame *f);
void syscall_read (struct intr_frame *f);
void syscall_filesize (struct intr_frame *f);
void syscall_seek (struct intr_frame *f);
void syscall_tell (struct intr_frame *f);
void syscall_mmap (struct intr_frame *f);
void syscall_munmap (struct intr_frame *f);

int thread_open_file(struct file * file_);
void thread_close_file(int fd);
void thread_close_all_file(void);
struct file * fd_find_file(int fd);
/* Print out the return address of a system call, and its argument */
void
syscall_print_argument (struct intr_frame *f UNUSED)
{
  printf ("**** Print System Call ****\n");
  void * esp = f->esp;
  printf ("** return address is %d\n", *(int *)f->esp);
  int i, argc = *(int *) (esp+4);
  printf ("** arg number is %d\n", argc);
  char *argument, **argv = (char **) (esp+8);
  for (i = 0, argument = *argv; i!=argc; i++, argument +=4){
    printf("** arg %d is: %s\n",(i+1), argument);
  }
  printf ("** buffer size is %d\n", *(unsigned int *)(esp+12));
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* check if a user pointer points below PHYS_BASE */
  if ((void *) f->esp >= PHYS_BASE) {
    exit_and_print ();
  }
  /* tell page fault handler whether page fault happen in kernel or user */
  struct thread * t=thread_current();
  t->user_esp = f->esp;
  t->in_syscall = true;

  uint32_t ra = *((int32_t *)f->esp);

  switch(ra){
    case SYS_HALT   : shutdown_power_off(); break;
    case SYS_WRITE  : syscall_write(f); break;
    case SYS_EXIT   : syscall_exit(f);  break;
    case SYS_EXEC   : syscall_exec(f);  break;
    case SYS_WAIT   : syscall_wait(f);  break;
    case SYS_CREATE : syscall_create(f); break;
    case SYS_REMOVE : syscall_remove(f);  break;
    case SYS_OPEN   : syscall_open(f);  break;
    case SYS_CLOSE  : syscall_close(f); break;
    case SYS_READ   : syscall_read(f);  break;
    case SYS_FILESIZE : syscall_filesize(f);  break;
    case SYS_SEEK : syscall_seek(f);  break;
    case SYS_TELL : syscall_tell(f);  break;
    case SYS_MMAP : syscall_mmap(f);  break;
    case SYS_MUNMAP : syscall_munmap(f); break;
    default       : printf ("system call number %d to be implemented!\n", ra);
                    process_edit_exit_status(-1);
                    thread_exit ();
  }
  /* return from syscall */
  t->in_syscall = false;
}

static bool
valid_ptr(void *ptr)
{
  struct thread *t = thread_current();
  if( ptr == NULL ||  is_kernel_vaddr (ptr))
//      || lookup_page(t->pagedir, ptr, false) == NULL )
    return false;
  else {
    uint32_t * pte = lookup_page(t->pagedir, ptr, false);
    if(pte == NULL)
      return false;
    else {
      return true;
    }
  } 
  return true;
}

static 
void check_page(void * ptr, struct intr_frame *f)
{
  struct thread *t = thread_current();
  if((ptr + 32) < f->esp) {
//    printf("ESP is %x\n", f->esp);
//    printf("PAGE FAULT AT %x\n", ptr);
//    exit_and_print();
  }
  // Check If Physical Page Exist
  if(pagedir_get_page(t->pagedir, ptr) == NULL){
  //TODO: use frame table to do the allocation
    uint8_t *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    void * page_bound = pg_round_down (ptr);
    if (kpage != NULL) {
      pagedir_set_page (t->pagedir, page_bound, kpage, true);
    } else {
      printf("TODO: NEED SWAP PAGE\n");
    }
  }
}

static void
check_writable(void *ptr)
{
  struct thread *t = thread_current();
  uint32_t * pte = lookup_page(t->pagedir, ptr, false);
  if(pte){
    bool writable = *pte & PTE_W;
    if(!writable)
      exit_and_print();
  }else{
    exit_and_print();
  }
}

/* When error happens in syscall, print message and exit(-1) */
static void
exit_and_print(void)
{
  process_edit_exit_status(-1);
  #ifdef USERPROG
      printf("%s: exit(%d)\n", thread_current()->name, -1);
  #endif
  thread_exit ();
}

/* Given esp, validate if all arguments in the syscall is valid*/
static void 
validate_syscall_args(const void * ptr, int argc)
{
  void * ptr_bottom = (void *)(ptr + argc*sizeof(void *));
  if(!valid_ptr(ptr_bottom))
    exit_and_print();
}

void
syscall_exit(struct intr_frame *f)
{
  if(intr_context()){
    printf("IN INTERRUPT CONTEXT\n");
  }
  validate_syscall_args(f->esp, 1);
  int status = * (int *)(f->esp + 4);
  if(status < 0 )
    status = -1;
  /* record the status when it returns */
  process_edit_exit_status(status);
#ifdef USERPROG
  printf ("%s: exit(%d)\n", thread_current()->name, status);
#endif
  thread_exit ();
}
void
syscall_exec(struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  char ** cmd_line = (char **)(f->esp+4);
  if( !valid_ptr (cmd_line) || !valid_ptr(*cmd_line)){
    exit_and_print();
  }
  if(cmd_line != NULL && *cmd_line != NULL){
      f->eax = process_execute(*cmd_line);
  }else
    f->eax = -1;
}
void
syscall_wait(struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  tid_t pid = *(tid_t *)(f->esp + 4);
  if (pid != -1)
    f->eax = process_wait(pid);
  else
    f->eax = -1;
}  

void
syscall_create (struct intr_frame *f)
{   
  validate_syscall_args(f->esp, 2);
  uint32_t file_size = *(uint32_t *)(f->esp + 8);
  char ** buffer = (char **)(f->esp+4);
  if( !valid_ptr (buffer) || !valid_ptr(*buffer)){
    exit_and_print();
  }
  fs_acquire_lock ();
  if(filesys_create(*buffer, file_size))
    f->eax = 1;
  else
    f->eax = 0;
  fs_release_lock ();
}

void
syscall_remove (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  char ** file_name = (char **)(f->esp+4);
  if(!valid_ptr(file_name) || !valid_ptr(*file_name)){
    exit_and_print();
  }
  if(file_name != NULL && *file_name != NULL){
    fs_acquire_lock();
    f->eax = filesys_remove (*file_name);
    fs_release_lock();
  }else
    f->eax = -1;
}

void
syscall_open (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  char ** file_name = (char **)(f->esp+4);
  if(!valid_ptr(file_name) || !(valid_ptr(*file_name))){
    exit_and_print();
  }
  fs_acquire_lock();
  struct file * open_file = filesys_open (*file_name);
  if(open_file){
    int fd = thread_open_file(open_file);
    if(fd == -1)
      file_close(open_file);
    f->eax = fd;
  } else {
    f->eax = -1;
  }
  fs_release_lock();
  return;
}
void
syscall_close (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  int * fd = (int *)(f->esp+4);
  if(!valid_ptr(fd))
    exit_and_print();
  fs_acquire_lock();
  thread_close_file(*fd);
  fs_release_lock();
  return;
}


void 
syscall_write (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 3);
  int *fd = (int *)(f->esp + 4);
  unsigned int size = *(uint32_t *)(f->esp + 12);
  char ** buffer = (char **)(f->esp+8);
  if(!valid_ptr(buffer) || !valid_ptr(*buffer) ){
    exit_and_print();
  }
//  check_page (*buffer, f);
  if (*fd == 1){
    if((*buffer == NULL)&&(strlen(*buffer) < size)){
      exit_and_print();
    }
    putbuf (*buffer, size);
    f->eax = size;
  } else {
    struct file * find_file = fd_find_file (*fd);
    if(find_file != NULL){
      fs_acquire_lock();
      f->eax = file_write(find_file, *buffer, size);
      fs_release_lock();
    } else 
      f->eax = 0;
  }
}
void
syscall_filesize (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  int *fd = (int *)(f->esp + 4);
  if (fd != NULL){
    struct file * find_file = fd_find_file (*fd);
    if(find_file){
      fs_acquire_lock();
      f->eax = file_length(find_file);
      fs_release_lock();
    }else
      f->eax = -1;
  }
}
void
syscall_read (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 3);
  int *fd = (int *)(f->esp + 4);
  if(fd != NULL){
    char ** buffer = (char **)(f->esp+8);
//    printf("ADDR IS %x\n", *buffer);
//    printf("BUFFER SIZE IS %d\n", strlen(*buffer));
//    if(!valid_ptr(buffer) || !valid_ptr(*buffer)){
    if(!valid_ptr(*buffer)){
      exit_and_print();
    }
    unsigned int size = *(uint32_t *)(f->esp + 12);
/*    check_page(*buffer, f);
    if(size <= PGSIZE) {
      check_page(*buffer+size, f);
    } else {
//      printf("FIXME, NEED TO CHECK OVER PAGE BOUNDARY\n");
    }
*/
    if(*fd == 0){
      if(strlen(*buffer) < size){
        exit_and_print();
      }
      unsigned i = 0;
      for(i = 0; i < size; i++){
        uint8_t temp = input_getc();
        // copy to buffer
        *(uint8_t*)(buffer+i) = temp;
      }
      f->eax = size;
    }
    struct file * file_find = fd_find_file(*fd);
    if(file_find){
      fs_acquire_lock();
      f->eax = file_read(file_find, *buffer, size);
      fs_release_lock();
    }else
      f->eax = -1;
  }
}
void syscall_seek (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 2);
  int *fd = (int *)(f->esp + 4);
  unsigned file_size = *(uint32_t *)(f->esp + 8);
    
  if (fd != NULL){
    struct file * find_file = fd_find_file(*fd);
    if(find_file){
      fs_acquire_lock();
      file_seek(find_file,file_size);
      fs_release_lock();
    }
  }
}

void syscall_tell (struct intr_frame *f)
{
  validate_syscall_args(f->esp, 1);
  int *fd = (int *)(f->esp + 4);
  if (fd != NULL){
    struct file * file_find = fd_find_file(*fd);
    if(file_find){
      fs_acquire_lock();
      f->eax = file_tell(file_find);
      fs_release_lock();
    } 
  } else {
    f->eax = 0;
  }
}

/* allocate a new mmap file id */
static mapid_t
allocate_mapid (void)
{
  struct thread *t = thread_current ();

  mapid_t map_id = t->file_mmap_mapid_valid;
  t->file_mmap_mapid_valid ++;

  return map_id;
}

void syscall_mmap (struct intr_frame *f)
{
//  printf("syscall_mmap.\n");
  validate_syscall_args(f->esp, 3);
  int fd = * (int*) (f->esp + 4);
  void *addr = * (void **)(f->esp + 8);
  struct file *file_fd = fd_find_file (fd);
  if (file_fd == NULL){
    f->eax = -1;
    return;
  }
  unsigned file_size = file_length(file_fd);
  if(!is_user_vaddr(addr) ||
     pg_ofs(addr) != 0    ||
     fd == STDIN_FILENO   ||
     fd == STDOUT_FILENO   ||
     file_size == 0)
  {
//     printf("exit NO 2");
     f->eax = -1;
     return;
  }
  void *addr_tmp = addr;
  struct thread *t = thread_current ();
  while(addr_tmp < addr + file_size )          /* +file_size or +file_size + PGSIZE */
  {
//    printf("first while loop.\n");
    uint32_t *pte = lookup_page(t->pagedir, addr_tmp, false);
    if (pte && (*pte & PTE_P)){
//      printf("exit NO 3");
        f->eax = -1;
        return;
    }
    if (pte){
      struct spage_elem * sp_elem;
      sp_elem = spage_lookup_entry(t->pagedir, addr_tmp);
      if(sp_elem){
          f->eax = -1;
          return;
      }
      if(sp_elem){
        page_location ploc = sp_elem->ploc;
        if (ploc & SPAGE_PMEM ||
            ploc & SPAGE_SWAP ||
            ploc & SPAGE_FS   ){
            f->eax = -1;
            return;
        }
      }
/*      enum address_status addr_state;
      addr_state = pagedir_address_origin(t->pagedir, addr_tmp);
      if (addr_state == ADDRESS_ON_SWAP ||
          addr_state == ADDRESS_MAPPED_FILE ||
          addr_state == ADDRESS_LAZY_EXEC ){
          f->eax = -1;
          return;
      }*/
    }

/*    size_t spt_page_idx = lookup_upage_supplementary_table(t->pagedir, addr_tmp);
    if(spt_page_idx != 1024){
      f->eax = -1;
      return;
    }*/

    addr_tmp += PGSIZE;
  }

//  printf("I am out.\n");
  struct mmap_struct *mmap;
  mmap = (struct mmap_struct *)malloc(sizeof(struct mmap_struct));

  if(mmap == NULL){
//    printf("exit No 5\n");
    exit_and_print();
  }

  fs_acquire_lock ();
  struct file *file_fd_mmap = file_reopen(file_fd);
  if (file_fd_mmap == NULL){
    fs_release_lock ();
    exit_and_print();
  }
  fs_release_lock ();

  mapid_t mapid_fd = allocate_mapid ();
  mmap->mapid = mapid_fd;
  mmap->vaddr = addr;
  mmap->file = file_fd_mmap;
  if(mmap->file == NULL){
    free(mmap);
//    printf("exit NO 1\n");
    exit_and_print();
  }

  list_push_back(&t->file_mmap_list, &mmap->elem);

  uint32_t  read_bytes = file_size;
  uint32_t  zero_bytes = ROUND_UP(read_bytes, PGSIZE) - read_bytes;
  block_sector_t sector_idx = byte_to_sector (file_get_inode (mmap->file), 0);
  off_t ofs = 0;
  while (read_bytes > 0 || zero_bytes > 0)
  {
//    printf("I am in while loop.\n");
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    uint32_t *pte;
    pte = lookup_page(t->pagedir, addr, true);
    pagedir_clear_page(t->pagedir, addr);
    *pte = *pte | PTE_W | PTE_U;
//    printf("set writable.\n");
//    put_page_to_supplementary_table(t->pagedir, addr, file_fd_mmap, ofs, page_read_bytes, true);
    spage_set_entry(t->pagedir, addr, SPAGE_FS, 0, file_fd_mmap, ofs, page_read_bytes);
    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    addr += PGSIZE;
    ofs += PGSIZE;
    sector_idx += PGSIZE / BLOCK_SECTOR_SIZE;
  }
  f->eax = mapid_fd;
  return;
}

struct mmap_struct *
file_mmap_lookup_mapid(struct thread *t, mapid_t mapid)
{
  struct list_elem *e;
  for (e = list_begin (&t->file_mmap_list); e != list_end (&t->file_mmap_list);
       e = list_next(e))
  {
    struct mmap_struct *mmap;
    mmap = list_entry(e, struct mmap_struct, elem);
    if(mmap->mapid == mapid)
      return mmap;
  }
  return NULL;
}

void syscall_munmap (struct intr_frame *f)
{
//  printf("syscall_munmap.\n");
  validate_syscall_args(f->esp, 1);
  mapid_t mapping = *(mapid_t *)(f->esp + 4);
  struct thread *t = thread_current();
  struct mmap_struct *mmap = file_mmap_lookup_mapid(t, mapping);

  if (mmap == NULL){
      printf("ERROR: mmap doesn't exist.\n");
      exit_and_print();
  }

  uint32_t file_size = file_length(mmap->file);
  void *vaddr = mmap->vaddr;
  uint32_t write_bytes = file_size;
  while (write_bytes > 0)
  {
//    printf("I am in the while loop.\n");
    size_t page_write_bytes = write_bytes < PGSIZE ? write_bytes : PGSIZE;
    uint32_t *pte = lookup_page(t->pagedir, vaddr, false);
    if(pte == NULL){
      printf("error unmap: pte for vaddr doesn't exist.\n");
      exit_and_print();
    } 
    
struct spage_elem * sp_elem = spage_lookup_entry(t->pagedir, vaddr);
    if (sp_elem == NULL){
      printf("error unmap:the sp_elem for file doesn't exist.\n");
      exit_and_print();
    }
    if (sp_elem){

    if((*pte & PTE_P) != 0){
      void *kpage = pagedir_get_page(t->pagedir, vaddr);
      if (pagedir_is_dirty(t->pagedir, vaddr)){
        size_t write_size = file_write_at (mmap->file, kpage, page_write_bytes, vaddr - mmap->vaddr);
        if(write_size != page_write_bytes){
          printf("unmap error: do not have enough space to write file.\n");
          exit_and_print();
        }
      }
      palloc_free_page (pte_get_page(*pte));
      *pte = 0;
    }

    /* Remove the frame table entry and the sup_page_table entry*/
//    struct spage_elem * sp_elem = spage_lookup_entry(t->pagedir, vaddr);
//    if (sp_elem){
//      spage_remove_entry(sp_elem);
    }

    /* Advance */
    write_bytes -= page_write_bytes;
    vaddr += PGSIZE;
  }

  /* Remove the mapid record */
  file_close(mmap->file);
  list_remove(&mmap->elem);
  free(mmap);
  return;
}


int thread_open_file(struct file * file_)
{
  struct thread *t = thread_current();
  f_opened_t * file_elem = (f_opened_t *)malloc(sizeof(f_opened_t));
  /* if successfully malloc an entry */
  if(file_elem == NULL)
    return -1;
  file_elem->file = file_;
  file_elem->fd = t->fd_valid;
  t->fd_valid ++;
  list_push_back(&(t->file_list), &file_elem->elem);
  return file_elem->fd;
}
void thread_close_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  for( e = list_begin(&t->file_list); e!= list_end(&t->file_list); 
       e = list_next(e))
  {
    f_opened_t * file_elem = list_entry(e, f_opened_t, elem);
    if(file_elem->fd == fd){
      list_remove(e);
      file_close(file_elem->file);
      free(file_elem);
      return;
    }
  } 
}
struct file * 
fd_find_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  for( e = list_begin(&t->file_list); e!= list_end(&t->file_list);
       e = list_next(e))
  {
    f_opened_t * file_elem = list_entry(e, f_opened_t, elem);
    if(file_elem->fd == fd){
      return file_elem->file;
    }
  }
  /* could not find such file */
  return NULL;
}
void thread_close_all_file(void)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  for( e = list_begin(&t->file_list); e!= list_end(&t->file_list);)
  {
    f_opened_t * file_elem = list_entry(e, f_opened_t, elem);
    if(file_elem == NULL)
      return;
    /* point to the next element */
    e = list_remove(e);
    file_close(file_elem->file);
    free(file_elem);
  }
}

