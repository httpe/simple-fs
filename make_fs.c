#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "make_fs.h"
#include "file_system.h"

#include "fat.h"

int32_t fat32_make_fs(block_storage_t* storage, const char* bootloader_path)
{
    uint32_t bootloader_sector_count = 0;
    
    if(bootloader_path != NULL && strlen(bootloader_path)>0) {
        int fd = open(bootloader_path, O_RDONLY);
        if(fd == -1) {
            return -errno;
        }
        off_t off = lseek(fd, 0, SEEK_END);
        if(off == (off_t) -1) {
            return -errno;
        }
        bootloader_sector_count = (off + (storage->block_size - 1)) / storage->block_size;
        uint8_t* bootloader = malloc(bootloader_sector_count*storage->block_size);
        memset(bootloader, 0, bootloader_sector_count*storage->block_size);
        ssize_t bytes_read = pread(fd, bootloader, off, 0);
        if(bytes_read == -1) {
            return -errno;
        }
        if(!(bootloader[510]==0x55 && bootloader[511]==0xAA)) {
            // not a valid MBR bootloader
            return -1;
        }
        // Verify the MBR partition table is empty
        for(int i=0x1BE;i<0x1EE;i++) {
            if(bootloader[i] != 0) {
                return -1;
            }
        }

        mbr_partition_table_entry_t* first_partition_entry = (mbr_partition_table_entry_t*) &bootloader[0x1BE];
        *first_partition_entry = (mbr_partition_table_entry_t) {
            .driver_attributes = 0x80, // active / bootable
            .CHS_partition_start = {0}, // CHS not filled
            .partition_type = 0x0C, // 0C: WIN95 OSR2 FAT32, LBA-mapped
            .CHS_partition_end = {0}, // CHS not filled
            .LBA_partition_start = bootloader_sector_count,
            .partition_sector_count = storage->block_count - bootloader_sector_count,
        };

        // Write MBR and bootloader
        int64_t res = storage->write_blocks(storage, 0, bootloader_sector_count, (uint8_t*) bootloader);
        free(bootloader);
        if(res < 0) {
            return -errno;
        }
    }

    uint16_t date, time;
    fat32_set_timestamp(&date, &time);

    fat32_bootsector_t boot = {
        .bootjmp = {0xE9, 0x57, 0x00}, // jmp to the begining of boot_code
        .oem_name = "SimpleFS",
        .bytes_per_sector = storage->block_size,
        .sectors_per_cluster = 8,
        .reserved_sector_count = 32,
        .table_count = 2,
        .root_entry_count = 0,
        .total_sectors_16 = 0,
        .media_type = 0xF8, // "fixed" (non-removable) media
        .table_sector_size_16 = 0,
        .sectors_per_track = 0,
        .head_side_count = 0,
        .hidden_sector_count = bootloader_sector_count, // partitioned
        .total_sectors_32 = storage->block_count - bootloader_sector_count,
        .table_sector_size_32 = 0, // fill it later
        .extended_flags = 0, // all FATs are mirrored at runtime
        .fat_version = 0,
        .root_cluster = 2,
        .fs_info_sector = 1,
        .backup_BS_sector = 6,
        .reserved_0 = {0},
        .drive_number = 0x80, // hda: 0x80
        .reserved_1 = 0,
        .boot_signature = 0x29,
        .volume_id = (date << 16) + time,
        .volume_label = "NO NAME    ",
        .fat_type_label = "FAT32   ",
        .boot_code = {0},
        .mbr_signature = 0xAA55,
    };

    // Ref: http://board.flatassembler.net/topic.php?t=12680
    uint32_t table_size_numerator = boot.total_sectors_32 - boot.reserved_sector_count + 2*boot.sectors_per_cluster;
    uint32_t table_size_denominator = (2 + boot.bytes_per_sector/4*boot.sectors_per_cluster);
    boot.table_sector_size_32 =  table_size_numerator / table_size_denominator;
    if(table_size_numerator % table_size_denominator != 0) {
        // round up
        boot.table_sector_size_32++;
    }

    fat32_fsinfo_t info = {
        .lead_signature = 0x41615252,
        .reserved = {0},
        .structure_signature = 0x61417272,
        .free_cluster_count = boot.table_sector_size_32 * boot.bytes_per_sector / 4 - 2 - 1, // first two are reserved, cluster 2 is root dir
        .next_free_cluster = 3,
        .reserved2 = {0},
        .trailing_signature = 0xAA550000
    };

    uint32_t* fat = malloc(boot.table_sector_size_32 * boot.bytes_per_sector);
    fat[0] = boot.media_type | 0x0FFFFF00; // FAT ID
    fat[1] = 0x0FFFFFFF; // EOC mark
    fat[2] = 0x0FFFFFFF; // EOC mark of the root dir

    fat32_direntry_short_t* root_dir = malloc(boot.sectors_per_cluster*boot.bytes_per_sector);
    root_dir[0] = (fat32_direntry_short_t) {
        .nameext = "NO NAME    ",
        .attr = FAT_ATTR_VOLUME_ID,
        .ctime_time = time,
        .ctime_date = date,
        .mtime_time = time,
        .mtime_date = date,
    };

    // Write FAT partition bootsector
    int64_t res = storage->write_blocks(storage, boot.hidden_sector_count, 1, (uint8_t*) &boot);
    if(res < 0) {
        goto free_and_error;
    }
    // Write backup bootsector
    res = storage->write_blocks(storage, boot.hidden_sector_count + 6, 1, (uint8_t*) &boot);
    if(res < 0) {
        goto free_and_error;
    }
    // Write FSInfo
    res = storage->write_blocks(storage, boot.hidden_sector_count + 1, 1, (uint8_t*) &info);
    if(res < 0) {
        goto free_and_error;
    }
    // Write FAT
    res = storage->write_blocks(storage, boot.hidden_sector_count + boot.reserved_sector_count, boot.table_sector_size_32, (uint8_t*) fat);
    if(res < 0) {
        goto free_and_error;
    }
    // Write backup FAT
    res = storage->write_blocks(storage, boot.hidden_sector_count + boot.reserved_sector_count + boot.table_sector_size_32, boot.table_sector_size_32, (uint8_t*) fat);
    if(res < 0) {
        goto free_and_error;
    }
    // Write root dir
    res = storage->write_blocks(storage, boot.hidden_sector_count + boot.reserved_sector_count + 2*boot.table_sector_size_32, boot.sectors_per_cluster, (uint8_t*) root_dir);
    if(res < 0) {
        goto free_and_error;
    }

    return 0;

free_and_error:
    free(fat);
    free(root_dir);
    return -1;
}
