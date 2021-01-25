#ifndef SIMPLE_FS_H
#define SIMPLE_FS_H

#define FS_MAX_FILE_COUNT 32
// Include terminal \0
#define FS_MAX_FILENAME_LEN 12
#define FS_DATA_BLOCK_LEN 512

#include <stdint.h>

typedef struct file_entry {
    char path[FS_MAX_FILENAME_LEN];
    struct file_attr {
        uint16_t is_dir:1;
        uint16_t reserved:15;
    } attr;
    uint16_t size;
} file_entry_t;

typedef struct data_block {
    char data[FS_DATA_BLOCK_LEN];
} data_block_t;

typedef struct fs_header {
    file_entry_t file_table[FS_MAX_FILE_COUNT];
} fs_header_t;

typedef struct fs_layout {
    fs_header_t header;
    data_block_t data[FS_MAX_FILE_COUNT];
} fs_layout_t;

#endif