#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

#define STDIN 0
#define STDOUT 1

struct process_file{
    int fd;
    struct file *file;
    struct list_elem elem;
}

void syscall_init (void);

void syscall_halt (void);
void syscall_exit (int status);
pid_t syscall_exec (const char *file);
int syscall_wait (pid_t pid);
bool syscall_create (const char *file, unsigned initial_size);
bool syscall_remove (const char *file);
int syscall_open (const char *file);
int syscall_filesize (int fd);
int syscall_read (int fd, void *buffer, unsigned length);
int syscall_write (int fd, const void *buffer, unsigned length);
void syscall_seek (int fd, unsigned position);
unsigned syscall_tell (int fd);
void syscall_close (int fd);

struct file* get_file_by_fd(int fd);

#endif /* userprog/syscall.h */
