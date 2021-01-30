#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "block_io.h"

#define BLOCK_COUNT 64
#define BLOCK_SIZE 512
#define MAX_STORAGE_DEV_COUNT 8

typedef struct file_storage {
    char image_path[4096];
} file_storage_t;

static block_storage_t disk_image_storage;
static file_storage_t disk_image_internal_info;

static block_storage_t* storage_list[MAX_STORAGE_DEV_COUNT];
static uint32_t n_storage;

uint32_t read_blocks(block_storage_t* storage, uint8_t* buff,  uint32_t LBA, uint32_t block_count)
{
    file_storage_t* fs = (file_storage_t*) storage->internal_info;
    int fd = open(fs->image_path, O_RDONLY);
    int size = block_count*storage->block_size;
    int offset = LBA*storage->block_size;
    int res = pread(fd, buff, size, offset);
    close(fd);
    return res;
}

uint32_t write_blocks(block_storage_t* storage, uint32_t LBA, uint32_t block_count, const uint8_t* buff)
{
    file_storage_t* fs = (file_storage_t*) storage->internal_info;
    int fd = open(fs->image_path, O_WRONLY);
    if(fd == -1) {
        return -1;
    }
    int size = block_count*storage->block_size;
    int offset = LBA*storage->block_size;
    int res = pwrite(fd, buff, size, offset);
    close(fd);
    return res;
}

block_storage_t* initialize_disk_image(const char* image_path) 
{
    uint32_t image_size;
    // Create disk image if not exist
    if(access(image_path, F_OK) != 0) {
        char buff[BLOCK_SIZE*BLOCK_COUNT] = {0};
        int fd = open(image_path, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
        int written = write(fd, buff, BLOCK_SIZE*BLOCK_COUNT);
        close(fd);
        if(written < BLOCK_SIZE*BLOCK_COUNT) {
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

    disk_image_storage = (block_storage_t) {
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

block_storage_t* get_block_storage(uint32_t device_id)
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
    block_storage_t* storage = initialize_disk_image(disk_image_path);
    if(storage == NULL) {
        return -1;
    }
    storage_list[0] = storage;
    n_storage = 1;
    return 0;
}