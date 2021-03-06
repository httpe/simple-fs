#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "block_io.h"

// If image does not exist, create image of size 512MiB
#define BLOCK_COUNT (1 << 20)

#define BLOCK_SIZE 512
#define MAX_STORAGE_DEV_COUNT 8

typedef struct file_storage {
    char image_path[4096];
} file_storage_t;

static block_storage disk_image_storage;
static file_storage_t disk_image_internal_info;

static block_storage* storage_list[MAX_STORAGE_DEV_COUNT];
static uint32_t n_storage;

int64_t read_blocks(block_storage* storage, void* buff,  uint32_t LBA, uint32_t block_count)
{
    file_storage_t* fs = (file_storage_t*) storage->internal_info;
    int fd = open(fs->image_path, O_RDONLY);
    if(fd < 0) {
        return -errno;
    }
    int size = block_count*storage->block_size;
    int offset = LBA*storage->block_size;
    int64_t res = pread(fd, buff, size, offset);
    close(fd);
    if(res < 0) {
        return -errno;
    }
    return res;
}

int64_t write_blocks(block_storage* storage, uint32_t LBA, uint32_t block_count, const void* buff)
{
    file_storage_t* fs = (file_storage_t*) storage->internal_info;
    int fd = open(fs->image_path, O_WRONLY);
    if(fd == -1) {
        return -errno;
    }
    int size = block_count*storage->block_size;
    int offset = LBA*storage->block_size;
    int64_t res = pwrite(fd, buff, size, offset);
    close(fd);
    if(res < 0) {
        return -errno;
    }
    return res;
}

block_storage* initialize_disk_image(const char* image_path) 
{
    uint32_t image_size;
    // Create disk image if not exist
    if(access(image_path, F_OK) != 0) {
        int fd = open(image_path, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
        int res = ftruncate(fd, BLOCK_COUNT*BLOCK_SIZE);
        close(fd);
        if(res < 0) {
            return NULL;
        }
        image_size = BLOCK_SIZE*BLOCK_COUNT;
    } else {
        FILE * pFile = fopen (image_path, "rb");
        fseek(pFile, 0L, SEEK_END);
        int size = ftell(pFile);
        fclose(pFile);
        if(size < 0) {
            return NULL;
        }
        image_size = size;
    }
    assert(image_size%BLOCK_SIZE==0);
    uint32_t block_count = image_size / BLOCK_SIZE;

    // Use absolute path since FUSE will change curent dirrectory to root dir /
    strcpy(disk_image_internal_info.image_path, realpath(image_path, NULL));

    disk_image_storage = (block_storage) {
        .device_id = 0, 
        .type=BLK_STORAGE_TYP_IMAGE_FILE, 
        .block_size=BLOCK_SIZE, 
        .block_count=block_count, 
        .read_blocks=read_blocks,
        .write_blocks=write_blocks,
        .internal_info=&disk_image_internal_info
    };

    return &disk_image_storage;
}

block_storage* get_block_storage(uint32_t device_id)
{
    for(uint32_t i=0; i<=n_storage; i++) {
        if(storage_list[i]->device_id == device_id) {
            return storage_list[i];
        }
    }
    return NULL;
}

int32_t initialize_block_storage(const char* disk_image_path)
{
    block_storage* storage = initialize_disk_image(disk_image_path);
    if(storage == NULL) {
        return -1;
    }
    storage_list[0] = storage;
    n_storage = 1;
    return 0;
}