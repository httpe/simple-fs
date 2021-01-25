#ifndef BLOCK_STORAGE_API_H
#define BLOCK_STORAGE_API_H

#include <stdint.h>

typedef enum block_storage_type {
    BLK_STORAGE_TYP_IMAGE_FILE
} block_storage_type_t;

typedef struct block_storage {
    uint8_t device_id;
    block_storage_type_t type;
    uint32_t block_size; // block (sector) size in bytes
    uint32_t block_count; // total number of blocks
    int32_t (*read_blocks)(struct block_storage* storage, void* buff, uint32_t LBA, uint32_t block_count);
    int32_t (*write_blocks)(struct block_storage* storage, uint32_t LBA, uint32_t block_count, const void* buff);
    void* internal_info;
} block_storage_t;

block_storage_t* get_block_storage(uint32_t device_id);

// Shall use the this signature when implementing in kernel
// int32_t initialize_block_storage();
int32_t initialize_block_storage(const char* disk_image_path);

#endif