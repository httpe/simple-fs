#ifndef _BLOCK_IO_H
#define _BLOCK_IO_H

#include <stdint.h>

typedef enum block_storage_type {
    BLK_STORAGE_TYP_IMAGE_FILE,
    BLK_STORAGE_TYP_ATA_HARD_DRIVE
} block_storage_type;

typedef struct block_storage {
    uint32_t device_id; // shall be assigned by kernel device manager, a unique and constant id for each device
    block_storage_type type;
    uint32_t block_size; // block (sector) size in bytes
    uint32_t block_count; // total number of blocks
    int64_t (*read_blocks)(struct block_storage* storage, void* buff, uint32_t LBA, uint32_t block_count); // return bytes read, 0 means error
    int64_t (*write_blocks)(struct block_storage* storage, uint32_t LBA, uint32_t block_count, const void* buff); // return bytes written,  0 means error
    void* internal_info; // internal data structure for the specfic storage type
} block_storage;

block_storage* get_block_storage(uint32_t device_id);

// Shall use the this signature when implementing in kernel
// int32_t initialize_block_storage();
int32_t initialize_block_storage(const char* disk_image_path);

#endif