#ifndef BLOCK_STORAGE_API_H
#define BLOCK_STORAGE_API_H

#include <stdint.h>

typedef enum block_storage_type {
    BLK_STORAGE_TYP_IMAGE_FILE,
    BLK_STORAGE_TYP_ATA_HARD_DRIVE
} block_storage_type_t;

typedef struct block_storage {
    uint32_t device_id; // shall be assigned by kernel device manager, a unique and constant id for each device
    block_storage_type_t type;
    uint32_t block_size; // block (sector) size in bytes
    uint32_t block_count; // total number of blocks
    uint32_t (*read_blocks)(struct block_storage* storage, uint8_t* buff, uint32_t LBA, uint32_t block_count); // return bytes read, 0 means error
    uint32_t (*write_blocks)(struct block_storage* storage, uint32_t LBA, uint32_t block_count, const uint8_t* buff); // return bytes written,  0 means error
    void* internal_info; // internal data structure for the specfic storage type
} block_storage_t;

block_storage_t* get_block_storage(uint32_t device_id);

// Shall use the this signature when implementing in kernel
// int32_t initialize_block_storage();
int32_t initialize_block_storage(const char* disk_image_path);

#endif