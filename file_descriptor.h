#ifndef SIMPLE_DESCRIPTOR_H
#define SIMPLE_DESCRIPTOR_H

#include <stdint.h>
#include "stat.h"

#define N_FILE_STRUCTURE 128
#define N_FILE_DESCRIPTOR_PER_PROCESS 16

enum file_type {
  FILE_TYPE_INODE
};

typedef struct file {
  enum file_type type;
  char* path;               /* path into the mount point */
  int32_t open_flags;
  struct fs_mount_point* mount_point;        /* Mount Point ID  */
  uint64_t inum;                  /* File serial number.	*/
  int32_t ref;                    /* Reference count */
  char readable;
  char writable;
  uint32_t offset;
} file;

// Per-process state
typedef struct proc {
  file *opended_files[N_FILE_DESCRIPTOR_PER_PROCESS];  // Open files
} proc;

#endif