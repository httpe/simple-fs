#ifndef PROC_H
#define PROC_H

#include "file_system.h"

#define N_FILE_DESCRIPTOR_PER_PROCESS 16

// Per-process state
typedef struct proc {
  file *files[N_FILE_DESCRIPTOR_PER_PROCESS];  // Opened files
} proc;

#endif