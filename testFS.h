#ifndef TESTFS_H
#define TESTFS_H

#include <stdint.h>
#include <time.h>

#define FS_MAX_FILE_COUNT 32
// Include terminal \0
#define FS_MAX_FILENAME_LEN 12
#define FS_MAX_FILE_CONTENT 512

typedef struct file_entry {
    char path[FS_MAX_FILENAME_LEN];
    char parent_path[FS_MAX_FILENAME_LEN];
    int16_t is_dir;
    int16_t size;
} file_entry_t;

typedef struct file_data {
    char content[FS_MAX_FILE_CONTENT];
} file_data_t;

typedef struct file_layout {
    file_entry_t entry;
    file_data_t data;
} file_layout_t;

typedef struct fs_layout {
    file_layout_t file[FS_MAX_FILE_COUNT];
} fs_layout_t;

#endif