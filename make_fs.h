#ifndef MAKE_FS_H
#define MAKE_FS_H

#include <stdint.h>
#include "block_io.h"

int32_t fat32_make_fs(block_storage* storage, const char* bootloader_path);

#endif