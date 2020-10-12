#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f ) 
{
  if(!is_valid_addr(f->esp)){
    exit(-1);
    return;
  }
  int syscall_number = * (int *)f->esp;

  switch(syscall_number){
    case SYS_HALT:
      syscall_halt(f);  
      break;
    case SYS_EXIT:
      syscall_exit(f);  
      break;
    case SYS_EXEC:
      syscall_exec(f);     
      break;
    case SYS_WAIT:
      syscall_wait(f);   
      break;
    case SYS_CREATE:
      syscall_create(f);   
      break;
    case SYS_REMOVE:
      syscall_remove(f); 
      break;
    case SYS_OPEN:
      syscall_open(f); 
      break;
    case SYS_FILESIZE:
      syscall_filesize(f); 
      break;
    case SYS_READ:
      syscall_read(f); 
      break;
    case SYS_WRITE:
      syscall_write(f);  
      break;
    case SYS_SEEK:
      syscall_seek(f);  
      break;
    case SYS_TELL:
      syscall_tell(f);   
      break;
    case SYS_CLOSE:
      syscall_close(f); 
      break;

    default:
      exit(-1);
  }
}

void exit (int status){
  struct thread *current_thread=thread_current ();
  struct list_elem *l;

  while (!list_empty (&current_thread->file_list))
    {
      l = list_begin (&current_thread->file_list);
      close (list_entry (l, struct process_file,elem)->fd);
    }

  current_thread->exit_status = status;
  thread_exit ();
}
pid_t exec (const char *file){

}
int wait (pid_t pid){

}
bool create (const char *file, unsigned initial_size){

}
bool remove (const char *file){

}
int open (const char *file){

}
int filesize (int fd){

}
int read (int fd, void *buffer, unsigned length){

}
int write (int fd, const void *buffer, unsigned length){
  if(fd==STDOUT){
    putbuf(buffer,length);
    return length;
  }else{
    struct file *f = get_file_by_fd(fd);
    if(f==NULL){
      exit(-1);
    }
    return (int) file_write(f,buffer,length);

  }
}
void seek (int fd, unsigned position){

}
unsigned tell (int fd){

}
void close (int fd){

}



void syscall_halt (struct intr_frame* f){
  shutdown_power_off();
}
void syscall_exit (struct intr_frame* f){
  if(!is_valid_addr(f->esp+4)){
    exit(-1);
  }
  int status = *(int *)(f->esp +4);
  exit(status);
}
void syscall_exec (struct intr_frame* f){

}
void syscall_wait (struct intr_frame* f){

}
void syscall_create (struct intr_frame* f){

}
void syscall_remove (struct intr_frame* f){

}
void syscall_open (struct intr_frame* f){

}
void syscall_filesize (struct intr_frame* f){

}
void syscall_read (struct intr_frame* f){

}
void syscall_write (struct intr_frame* f){
  if(!is_valid_addr(f->esp+4)){
    exit(-1);
  }
  int fd = *(int *)(f->esp +4);
  void *buffer = *(char**)(f->esp + 8);
  unsigned size = *(unsigned *)(f->esp + 12);

  if(!is_valid_buffer(buffer,size)){
    exit(-1);
  }

  f->eax=write(fd,buffer,size);
  return;
}
void syscall_seek (struct intr_frame* f){

}
void syscall_tell (struct intr_frame* f){

}
void syscall_close (struct intr_frame* f){

}








struct file*
get_file_by_fd(int fd){
  struct thread *current_thread=thread_current ();
  struct list_elem *tmp;
  for (tmp = list_begin (&current_thread->file_list); tmp != list_end (&current_thread->file_list); tmp = list_next (tmp)){
    if(list_entry (tmp, struct process_file, elem)->fd== fd)
      return list_entry (tmp, struct process_file, elem)->file;
  }
  return NULL;
}

bool
is_valid_addr(const void *vaddr){
	if (!is_user_vaddr(vaddr) || !(pagedir_get_page(thread_current()->pagedir, vaddr))){
		return false;
	}
	return true;
}

bool
is_valid_buffer (void *vaddr, unsigned size)
{
  unsigned i;
  char* tmp=vaddr;
  for (i = 0; i < size; i++){
    if(!is_valid_addr(tmp+i)){
      return false;
    }
  }
  return true;
}