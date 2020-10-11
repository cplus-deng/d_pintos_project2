#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
void syscall_halt (void){
  shutdown_power_off();
}
void syscall_exit (int status){

}
pid_t syscall_exec (const char *file){

}
int syscall_wait (pid_t pid){

}
bool syscall_create (const char *file, unsigned initial_size){

}
bool syscall_remove (const char *file){

}
int syscall_open (const char *file){

}
int syscall_filesize (int fd){

}
int syscall_read (int fd, void *buffer, unsigned length){

}
int syscall_write (int fd, const void *buffer, unsigned length){
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
void syscall_seek (int fd, unsigned position){

}
unsigned syscall_tell (int fd){

}
void syscall_close (int fd){

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