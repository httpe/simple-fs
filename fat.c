#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

#include "fat.h"

#define FUSE_USE_VERSION 31
#include <fuse.h>

#define HAS_ATTR(file,attr) (((file)&(attr)) == (attr))

static fat32_meta_t global_fat_meta;

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
	const char *image_path;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
	OPTION("--image_path=%s", image_path),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void *fs_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

// Source: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
static uint8_t lfn_checksum(const uint8_t *pFCBName)
{
   int i;
   uint8_t sum = 0;

   for (i = 11; i; i--)
      sum = ((sum & 1) << 7) + (sum >> 1) + *pFCBName++;

   return sum;
}

// Source: Xv6/fs.c (skipelem)
// Copy the next path element from path into name.
// Return a pointer to the element following the copied one.
// The returned path has no leading slashes,
// so the caller can check *path=='\0' to see if the name is the last one.
// If no name to remove, return 0.
//
// Examples:
//   split_path("a/bb/c", name) = "bb/c", setting name = "a"
//   split_path("///a//bb", name) = "bb", setting name = "a"
//   split_path("a", name) = "", setting name = "a"
//   split_path("", name) = split_path("////", name) = NULL
//   split_path("/a", name) = "", setting name = "a"
// Edge Cases:
//   split_path("/a") = "", name = "a"
//   split_path("/") = NULL, name not touched
//   split_path("/a/bb") = "bb", name = "a"
//   split_path("bb") = "", name = "bb"
//   split_path("bb/cc") = "cc", name = "bb"
//
static char* split_path(char *path, char *name)
{
  char *s;
  int len;

  while(*path == '/')
    path++;
  if(*path == 0)
    return NULL;
  s = path;
  while(*path != '/' && *path != 0)
    path++;
  len = path - s;
  if(len >= FAT32_FILENAME_SIZE)
    memmove(name, s, FAT32_FILENAME_SIZE);
  else {
    memmove(name, s, len);
    name[len] = 0;
  }
  while(*path == '/')
    path++;
  return path;
}

fat_cluster_status_t fat32_interpret_fat_entry(uint32_t entry)
{
    entry = entry & 0x0FFFFFFF;

    // Cluster value ref: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#Cluster_values
    if(entry == 0x00000000) {
        return FAT_CLUSTER_FREE;
    }
    if(entry >= 0x00000002 && entry <= 0x0FFFFFEF) {
        return FAT_CLUSTER_USED;
    }
    if(entry == 0x0FFFFFF7){
        return FAT_CLUSTER_BAD;
    }
    if(entry >= 0x0FFFFFF8) {
        // End of cluster-chain (EOC)
        return FAT_CLUSTER_EOC;
    }
    return FAT_CLUSTER_RESERVED;
}

int32_t fat32_get_meta(fat32_meta_t* meta)
{
    block_storage_t* storage = meta->storage;
    
    uint32_t sectors_to_read = 1 + (sizeof(fat32_bootsector_t) - 1) / storage->block_size;
    uint8_t* buff = malloc(storage->block_size);
    int64_t bytes_read = storage->read_blocks(storage, buff, 0, sectors_to_read);
    if(bytes_read != storage->block_size*sectors_to_read) {
        return -1;
    }

    meta->bootsector = malloc(sizeof(fat32_bootsector_t));
    memmove(meta->bootsector, buff, sizeof(*meta->bootsector));
    // Sanity check
    uint32_t good = 1;
    good = good & (meta->bootsector->mbr_signature == 0xAA55); // ensure MBR magic number
    good = good & (meta->bootsector->bytes_per_sector ==  storage->block_size); // ensure sector size
    good = good & (meta->bootsector->root_entry_count == 0); // ensure is FAT32 not FAT12/16
    good = good & (meta->bootsector->boot_signature == 0x29); // ensure FAT32 signature
    // we assume cluster number is in the range of int32_t, check it here
    good = good & (meta->bootsector->total_sectors_32 / meta->bootsector->sectors_per_cluster < 0x7FFFFFFF); 
    if(!good){
        return -1;
    }
    // Read FS Info
    sectors_to_read = 1 + (sizeof(fat32_fsinfo_t) - 1) / storage->block_size;
    bytes_read = storage->read_blocks(storage, buff, meta->bootsector->fs_info_sector, sectors_to_read);
    if(bytes_read != storage->block_size*sectors_to_read) {
        return -1;
    }
    meta->fs_info = malloc(sizeof(fat32_fsinfo_t));
    memmove(meta->fs_info, buff, sizeof(*meta->fs_info));
    good = good & (meta->fs_info->lead_signature == 0x41615252); // check FS_Info magic number
    good = good & (meta->fs_info->structure_signature == 0x61417272);
    good = good & (meta->fs_info->trailing_signature ==  0xAA550000);
    if(!good){
        return -1;
    }
    // Read FAT
    if(meta->bootsector->table_count == 0) {
        return -1;
    }
    uint32_t fat_byte_size = meta->bootsector->table_sector_size_32 * meta->bootsector->bytes_per_sector;
    meta->fat = malloc(fat_byte_size);
    bytes_read = storage->read_blocks(storage, (uint8_t*) meta->fat, meta->bootsector->reserved_sector_count, meta->bootsector->table_sector_size_32);
    if(bytes_read != fat_byte_size) {
        return -1;
    }
    good = good & ((meta->fat[0] & 0x0FFFFFFF) >= 0x0FFFFFF0) & ((meta->fat[0] & 0x0FFFFFFF) <= 0x0FFFFFFF); // check cluster 0 (FAT ID)
    good = good & ((meta->fat[1] & 0x0FFFFFFF) == 0x0FFFFFFF); // check cluster 1 (End of Cluster Mark)
    if(!good){
        return -1;
    }
    // Ensure all FAT are the same
    uint32_t* alternative_fat = malloc(fat_byte_size);
    for(uint32_t fat_idx = 1; fat_idx < meta->bootsector->table_count; fat_idx++){
        bytes_read = storage->read_blocks(storage, (uint8_t*) alternative_fat, meta->bootsector->reserved_sector_count + fat_idx*meta->bootsector->table_sector_size_32, meta->bootsector->table_sector_size_32);
        if(bytes_read != fat_byte_size) {
            return -1;
        }
        if(memcmp(alternative_fat, meta->fat, fat_byte_size) != 0) {
            return -1;
        }
    }

    return 0;
}

fat_cluster_status_t fat32_get_cluster_info(fat32_meta_t* meta, uint32_t cluster_number, fat_cluster_t* cluster)
{
    // First&second cluster are reserved for FAT ID and End of Cluster Mark 
    if(cluster_number <= 1) {
        return FAT_CLUSTER_RESERVED;
    }
    
    fat_cluster_status_t status = fat32_interpret_fat_entry(meta->fat[cluster_number]);
    if(status == FAT_CLUSTER_USED) {
        cluster->next = meta->fat[cluster_number] & 0x0FFFFFFF;
    } else {
        cluster->next = 0;
    }
    cluster->curr = cluster_number;

    return status;
}

static uint32_t count_clusters(fat32_meta_t* meta, uint32_t cluster_number)
{
    fat_cluster_t cluster;
    cluster.next = cluster_number;
    uint32_t total_cluster_count = 0;
    while(1) {
        fat32_get_cluster_info(meta, cluster.next, &cluster);
        total_cluster_count++;
        if(cluster.next == 0) {
            return total_cluster_count;
        }
    }
}

// Get cluster number by indexing into a cluster chain, negative index means counting from EOC
static uint32_t fat32_index_cluster_chain(fat32_meta_t* meta, uint32_t cluster_number, int32_t index)
{
    if(cluster_number == 0) {
        return 0;
    }

    if(index < 0) {
        uint32_t cluster_count = count_clusters(meta, cluster_number);
        index = cluster_count + index;
    }
    if(index < 0) {
        return 0;
    }
    if(index == 0) {
        return cluster_number;
    }
    fat_cluster_t cluster = {.next = cluster_number};
    while(index > 0) {
        if(cluster.next == 0) {
            return 0;
        }
        fat32_get_cluster_info(meta, cluster.next, &cluster);
        index--;
    }
    return cluster.next;
}

// Can only be used to seek existing clusters
static uint32_t fat32_cluster_by_offset(fat32_meta_t* meta, uint32_t starting_cluster_number, uint32_t byte_offset)
{
    uint32_t bytes_per_cluster = meta->bootsector->sectors_per_cluster*meta->bootsector->bytes_per_sector;
    uint32_t cluster_offset = byte_offset / bytes_per_cluster;
    if(cluster_offset == 0) {
        return starting_cluster_number;
    }
    fat_cluster_t cluster = {.next = starting_cluster_number};
    while(cluster_offset>0) {
        assert(cluster.next != 0);
        fat32_get_cluster_info(meta, cluster.next, &cluster);
        cluster_offset--;
    }
    return cluster.next;
}

int32_t fat32_write_fs_info(fat32_meta_t* meta)
{
    uint32_t sectors_to_read = 1 + (sizeof(fat32_fsinfo_t) - 1) / meta->storage->block_size;
    uint32_t bytes_written = meta->storage->write_blocks(meta->storage, meta->bootsector->fs_info_sector, sectors_to_read, (uint8_t*) meta->fs_info);
    if(bytes_written != meta->storage->block_size*sectors_to_read) {
        return -1;
    } else {
        return 0;
    }
}

int32_t fat32_write_fat(fat32_meta_t* meta, uint32_t* new_fat)
{
    uint32_t fat_byte_size = meta->bootsector->table_sector_size_32*meta->bootsector->bytes_per_sector;
    // Write new FAT to main FAT and backups
    uint32_t fat_idx;
    uint32_t bytes_written;
    for(fat_idx = 0; fat_idx < meta->bootsector->table_count; fat_idx++){
        bytes_written = meta->storage->write_blocks(meta->storage, meta->bootsector->reserved_sector_count + fat_idx*meta->bootsector->table_sector_size_32, meta->bootsector->table_sector_size_32, (uint8_t*) new_fat);
        if(bytes_written != fat_byte_size) {
            break;
        }
    }
    // If failed
    if(fat_idx != meta->bootsector->table_count) {
        // FAT corrupted!
        // Try restore back to the original FAT
        for(uint32_t fat_idx_recover = 0; fat_idx_recover <= fat_idx; fat_idx_recover++){
            bytes_written = meta->storage->write_blocks(meta->storage, meta->bootsector->reserved_sector_count + fat_idx_recover*meta->bootsector->table_sector_size_32, meta->bootsector->table_sector_size_32, (uint8_t*) meta->fat);
            // If recover attempt failed, panic
            assert(bytes_written != fat_byte_size);
        }
        return -1;
    }
    
    return 0;
}

static void fat32_copy_meta(fat32_meta_t* new_meta, fat32_meta_t* meta)
{

    uint32_t fat_byte_size = meta->bootsector->table_sector_size_32*meta->bootsector->bytes_per_sector;
    if(new_meta->fat == NULL) {
        new_meta->fat = malloc(fat_byte_size);
    }
    memmove(new_meta->fat, meta->fat, fat_byte_size);

    if(new_meta->fs_info == NULL) {
        new_meta->fs_info = malloc(sizeof(fat32_fsinfo_t));
    }
    memmove(new_meta->fs_info, meta->fs_info, sizeof(fat32_fsinfo_t));

    if(new_meta->bootsector == NULL) {
        new_meta->bootsector = malloc(sizeof(fat32_bootsector_t));
    }
    memmove(new_meta->bootsector, meta->bootsector, sizeof(*meta->bootsector));

    new_meta->storage = meta->storage;
}

static void fat32_free_meta(fat32_meta_t* meta)
{
    free(meta->bootsector);
    meta->bootsector = NULL;
    free(meta->fs_info);
    meta->fs_info = NULL;
    free(meta->fat);
    meta->fat = NULL;
    meta->storage = NULL;
}

// Return: Cluster number of the first newly allocated cluster
uint32_t fat32_allocate_cluster(fat32_meta_t* meta, uint32_t prev_cluster_number, uint32_t cluster_count_to_allocate)
{
    uint32_t cluster_number = meta->fs_info->next_free_cluster;
    if(cluster_number == 0xFFFFFFFF) {
        cluster_number = 2;
    }
    uint32_t cluster_number_first_tried = cluster_number;
    uint32_t max_cluster_number = meta->bootsector->total_sectors_32 / meta->bootsector->sectors_per_cluster - 1;
    uint32_t allocated = 0, first_new_cluster_number = 0;
    
    fat32_meta_t new_meta = {0};
    fat32_copy_meta(&new_meta, meta);
    
    while(allocated < cluster_count_to_allocate) {
        fat_cluster_status_t status = fat32_interpret_fat_entry(new_meta.fat[cluster_number]);
        if(status == FAT_CLUSTER_FREE) {
            if(prev_cluster_number != 0) {
                fat_cluster_status_t prev_status = fat32_interpret_fat_entry(new_meta.fat[prev_cluster_number]);
                assert(prev_status == FAT_CLUSTER_EOC);
                new_meta.fat[prev_cluster_number] = (new_meta.fat[prev_cluster_number] & 0xF0000000) | (cluster_number & 0x0FFFFFFF);
            }
            new_meta.fat[cluster_number] = (new_meta.fat[cluster_number] & 0xF0000000) | (FAT_CLUSTER_EOC & 0x0FFFFFFF);
            prev_cluster_number = cluster_number;
            if(allocated == 0) {
                first_new_cluster_number = cluster_number;
            }
            allocated++;
        }
        if(cluster_number == max_cluster_number) {
            cluster_number = 2;
        } else {
            cluster_number++;
        }
        if(cluster_number == cluster_number_first_tried && allocated < cluster_count_to_allocate) {
            // all FAT entries tested, no free entry, disk is full
            return 0;
        }
    }

    int32_t res = fat32_write_fat(meta, new_meta.fat);
    if(res == 0) {
        // Update memory cache
        fat32_copy_meta(meta, &new_meta);
        fat32_free_meta(&new_meta);

        // FS info is for information only, so even if the I/O failed, we still return success status
        // And the cached fs_info will always be the latest version, even though it may be written to disk successfully
        meta->fs_info->free_cluster_count -= allocated;
        meta->fs_info->next_free_cluster = cluster_number; // not a free cluster, but a good place to start looking for one
        res = fat32_write_fs_info(meta);

        return first_new_cluster_number;
    } else {
        fat32_free_meta(&new_meta);
        return 0;
    }
}


// cluster_count_to_free = 0 means free to the end of the chain
static int32_t fat32_free_cluster(fat32_meta_t* meta, uint32_t prev_cluster_number, uint32_t cluster_number, uint32_t cluster_count_to_free)
{
    fat_cluster_t cluster;

    fat32_meta_t new_meta = {0};
    fat32_copy_meta(&new_meta, meta);
    
    uint32_t cluster_freed = 0;
    cluster.next = cluster_number;
    while(cluster.next && (cluster_freed < cluster_count_to_free || cluster_count_to_free == 0)) {
        fat_cluster_status_t status = fat32_get_cluster_info(meta, cluster.next, &cluster);
        assert(status == FAT_CLUSTER_USED || status == FAT_CLUSTER_EOC);
        // set as free cluster
        new_meta.fat[cluster.curr] = (new_meta.fat[cluster.curr] & 0xF0000000) | (FAT_CLUSTER_FREE & 0x0FFFFFFF);
        if(prev_cluster_number != 0) {
            if(cluster.next != 0) {
                // if removing cluster in the middle of the chain, connect prev and next cluster
                new_meta.fat[prev_cluster_number] = (new_meta.fat[prev_cluster_number] & 0xF0000000) | (cluster.next & 0x0FFFFFFF);
            } else {
                new_meta.fat[prev_cluster_number] = (new_meta.fat[prev_cluster_number] & 0xF0000000) | (FAT_CLUSTER_EOC & 0x0FFFFFFF);
            }   
        }
        cluster_freed++;
    }

    int32_t res = fat32_write_fat(meta, new_meta.fat);
    if(res == 0) {
        // Update memory cache
        fat32_copy_meta(meta, &new_meta);
        fat32_free_meta(&new_meta);

        // FS info is for information only, so even if the I/O failed, we still return success status
        // And the cached fs_info will always be the latest version, even though it may be written to disk successfully
        meta->fs_info->free_cluster_count += cluster_freed;
        res = fat32_write_fs_info(meta);

        return 0;
    } else {
        fat32_free_meta(&new_meta);
        return -EIO;
    }

}

int64_t fat32_read_clusters(fat32_meta_t* meta, uint32_t cluster_number, uint32_t clusters_to_read, uint8_t* buff) 
{
    assert(cluster_number >= 2);
    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;

    fat_cluster_t cluster = {.next = cluster_number};
    int64_t total_bytes_read = 0;
    for(uint32_t i=0; i < clusters_to_read; i++) {
        assert(cluster.next != 0);
        fat_cluster_status_t status = fat32_get_cluster_info(meta, cluster.next, &cluster);
        assert(status == FAT_CLUSTER_USED || (status == FAT_CLUSTER_EOC && i == clusters_to_read-1));
        // the cluster 0 and 1 are not of size sectors_per_cluster
        uint32_t lba = meta->bootsector->reserved_sector_count + meta->bootsector->table_sector_size_32*meta->bootsector->table_count + (cluster.curr-2)*meta->bootsector->sectors_per_cluster;
        int64_t bytes_read = meta->storage->read_blocks(meta->storage, buff, lba, meta->bootsector->sectors_per_cluster);
        if(bytes_read < 0) {
            return -errno;
        }
        total_bytes_read += bytes_read;
        buff += cluster_byte_size;
        lba += meta->bootsector->sectors_per_cluster;
    }

    return total_bytes_read;
}

int64_t fat32_write_clusters(fat32_meta_t* meta, uint32_t cluster_number, uint32_t clusters_to_write, uint8_t* buff)
{
    assert(cluster_number >= 2);
    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;

    fat_cluster_t cluster = {.next = cluster_number};
    int64_t total_bytes_written = 0;
    for(uint32_t i=0; i < clusters_to_write; i++) {
        assert(cluster.next != 0);
        fat_cluster_status_t status = fat32_get_cluster_info(meta, cluster.next, &cluster);
        assert(status == FAT_CLUSTER_USED || (status == FAT_CLUSTER_EOC && i == clusters_to_write-1));
        // the cluster 0 and 1 are not of size sectors_per_cluster
        uint32_t lba = meta->bootsector->reserved_sector_count + meta->bootsector->table_sector_size_32*meta->bootsector->table_count + (cluster.curr-2)*meta->bootsector->sectors_per_cluster;
        int64_t bytes_written = meta->storage->write_blocks(meta->storage, lba, meta->bootsector->sectors_per_cluster, buff);
        if(bytes_written < 0) {
            return -errno;
        }
        total_bytes_written += bytes_written;
        buff += cluster_byte_size;
        lba += meta->bootsector->sectors_per_cluster;
    }
    return total_bytes_written;
}

// trim leading and trailing spaces and trailing periods
void trim_file_name(char* str)
{
    if(str == NULL) {
        return;
    }
    uint32_t start = 0;
    while(str[start] == ' ' && str[start] != 0) {
        start++;
    }
    if(str[start] == 0) {
        // str is all spaces
        str[0] = 0;
        return;
    }
    uint32_t end = strlen(str) - 1;
    while((str[end] == ' ' || str[end] == '.') && end > start) {
        end--;
    }
    memmove(str, &str[start], end - start + 1);
    str[end - start + 1] = 0;
}

static void fat32_reset_dir_iterator(fat_dir_iterator_t* iter)
{
    iter->current_dir_entry_idx = 0;
}

static void fat_free_dir_iterator(fat_dir_iterator_t* iter)
{
    free(iter->dir_entries);
    iter->dir_entries = NULL;
    iter->dir_entry_count = 0;
    iter->entry_per_cluster = 0;
    fat32_reset_dir_iterator(iter);
}

// Convert the 8.3 filename entry to its displayed version
static void fat_standardize_short_name(char* filename, fat32_direntry_short_t* short_entry)
{
    memmove(filename,short_entry->name, FAT_SHORT_NAME_LEN);
    filename[FAT_SHORT_NAME_LEN] = 0;
    trim_file_name((char*)filename);
    uint32_t name_len = strlen((char*)filename);
    filename[name_len] = '.';
    memmove(&filename[name_len+1],  short_entry->ext, FAT_SHORT_EXT_LEN);
    filename[name_len+1+FAT_SHORT_EXT_LEN] = 0;
    trim_file_name((char*)filename);
    if(filename[0] == 0x05) {
        // If DIR_Name[0] == 0x05, then the actual file name character for this byte is 0xE5
       filename[0] = 0xE5;
    }
}

fat_iterate_dir_status_t fat32_iterate_dir(fat32_meta_t* meta, fat_dir_iterator_t* iter, fat32_file_entry_t* file_entry)
{
    if(iter->dir_entries == NULL) {
        // if buff is null, read the whole dir into memory
        uint32_t cluster_byte_size = meta->bootsector->sectors_per_cluster * meta->bootsector->bytes_per_sector;
        uint32_t dir_total_cluster_count = count_clusters(meta, iter->first_cluster);
        iter->dir_entries = malloc(dir_total_cluster_count*cluster_byte_size);
        int64_t read_res = fat32_read_clusters(meta, iter->first_cluster, dir_total_cluster_count, (uint8_t*) iter->dir_entries);
        if(read_res < 0) {
            fat_free_dir_iterator(iter);
            return FAT_DIR_ITER_ERROR;
        }
        iter->entry_per_cluster = cluster_byte_size/sizeof(fat32_direntry_t);
        iter->dir_entry_count = dir_total_cluster_count*iter->entry_per_cluster;
        fat32_reset_dir_iterator(iter);
    }

    memset(file_entry, 0, sizeof(*file_entry));
    file_entry->dir_cluster = iter->first_cluster;
	uint32_t lfn_entry_buffered = 0;
	uint8_t last_lfn_checksum = 0;

    while(1)
    {
        if(iter->current_dir_entry_idx >= iter->dir_entry_count) {
            return FAT_DIR_ITER_NO_MORE_ENTRY;
        }

        fat32_direntry_t* entry = &iter->dir_entries[iter->current_dir_entry_idx];
        // Algo Ref: https://wiki.osdev.org/FAT#Reading_Directories
        if(entry->short_entry.attr == FAT_ATTR_LFN && entry->short_entry.nameext[0] != 0xE5){
            // Is this entry a long file name entry? If the 11'th byte of the entry equals 0x0F, then it is a long file name entry. Otherwise, it is not.
            // Read the portion of the long filename into a temporary buffer. Goto 8.
            if((entry->long_entry.seq & 0x40) == 0x40) {
                // first LFN entry
                // if some entries are already buffered, they will be abandoned
                memset(file_entry->filename, 0, sizeof(file_entry->filename));
                void* end_of_filename = ((void*) file_entry->filename) + sizeof(file_entry->filename);
                memmove(end_of_filename-=sizeof(entry->long_entry.name3), entry->long_entry.name3, sizeof(entry->long_entry.name3));
                memmove(end_of_filename-=sizeof(entry->long_entry.name2), entry->long_entry.name2, sizeof(entry->long_entry.name2));
                memmove(end_of_filename-=sizeof(entry->long_entry.name1), entry->long_entry.name1, sizeof(entry->long_entry.name1));
                file_entry->first_dir_entry_idx = iter->current_dir_entry_idx;
                // file_entry->dir_entry_idx_start = iter->current_dir_entry_idx % iter->entry_per_cluster;
                // file_entry->dir_entry_cluster_start = fat32_cluster_by_offset(meta, iter->first_cluster, iter->current_dir_entry_idx*sizeof(fat32_direntry_t));
                last_lfn_checksum = entry->long_entry.csum;
                lfn_entry_buffered = 1;
            } else if(last_lfn_checksum != entry->long_entry.csum) {
                // skip this LFN entry if checksum doesn't match the last checksum
                lfn_entry_buffered = lfn_entry_buffered;
            } else {
                // not first LFN and checksum is consistent
                void* offset = ((void*) file_entry->filename) + sizeof(file_entry->filename) - FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*(lfn_entry_buffered);
                memmove(offset-=sizeof(entry->long_entry.name3), entry->long_entry.name3, sizeof(entry->long_entry.name3));
                memmove(offset-=sizeof(entry->long_entry.name2), entry->long_entry.name2, sizeof(entry->long_entry.name2));
                memmove(offset-=sizeof(entry->long_entry.name1), entry->long_entry.name1, sizeof(entry->long_entry.name1));
                lfn_entry_buffered++;
            }
            file_entry->dir_entry_count++;
            iter->current_dir_entry_idx++;
            continue;
        } else {
            // Parse the data for this entry using the table from further up on this page. It would be a good idea to save the data for later. Possibly in a virtual file system structure. goto 6
            file_entry->direntry = iter->dir_entries[iter->current_dir_entry_idx].short_entry;
            file_entry->dir_entry_count++;
            // Is there a long file name in the temporary buffer? Yes, goto 7. No, goto 8
            // Apply the long file name to the entry that you just read and clear the temporary buffer. goto 8
            if(lfn_entry_buffered > 0) {
                // We do not support USC-2 UNICODE character, any non US-ASCII character will be replaced by '_'
                // as per Microsoft's documentation "Microsoft Extensible Firmware Initiative FAT32 File System Specification" 
                // https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
                uint32_t lfn_name_byte_len =  FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*lfn_entry_buffered;
                char* start_of_filename = &file_entry->filename[sizeof(file_entry->filename)] - lfn_name_byte_len;
                for(uint32_t i=0; i<lfn_name_byte_len/2; i++) {
                    char usc2_first = start_of_filename[i*2];
                    char usc2_second = start_of_filename[i*2+1];
                    // Unicode (and UCS-2) is compatible with 7-bit ASCII / US-ASCII
                    if(usc2_first < 0 || usc2_second != 0) {
                        // if not US-ASCII
                        file_entry->filename[i] = '_';
                    } else {
                        file_entry->filename[i] = usc2_first;
                    }
                }
                file_entry->filename[lfn_name_byte_len] = 0;
                trim_file_name((char*)file_entry->filename);
            } else {
                // if not LFN buffered, use the 8.3 short name
                file_entry->first_dir_entry_idx = iter->current_dir_entry_idx;
                // file_entry->dir_entry_idx_start = iter->current_dir_entry_idx % iter->entry_per_cluster;
                // file_entry->dir_entry_cluster_start = fat32_cluster_by_offset(meta, iter->first_cluster, iter->current_dir_entry_idx*sizeof(fat32_direntry_t));
                fat_standardize_short_name((char*) file_entry->filename, &file_entry->direntry);
            }
            
            // Increment pointers and/or counters and check the next entry. (goto number 1)
            iter->current_dir_entry_idx++;

            if(entry->short_entry.nameext[0] == 0) {
                // If the first byte of the entry is equal to 0 then there are no more files/directories in this directory. FirstByte==0, finish.
                return FAT_DIR_ITER_FREE_ENTRY;
            }
            if(entry->short_entry.nameext[0] == 0x2E) {
                // Entry for either "." or ".."
                return FAT_DIR_ITER_DOT_ENTRY;
            }
            if(entry->short_entry.nameext[0] == 0xE5) {
                // If the first byte of the entry is equal to 0xE5 then the entry is unused. FirstByte==0xE5, goto 8
                return FAT_DIR_ITER_DELETED;
            }
            if(lfn_entry_buffered > 0 && last_lfn_checksum != lfn_checksum(file_entry->direntry.nameext)) {
                // invalid LFN entry, see as error
                return FAT_DIR_ITER_ERROR;
            }
            return FAT_DIR_ITER_VALID_ENTRY;
        }
    }


}

static fat_resolve_path_status_t fat32_dir_lookup(fat32_meta_t* meta, fat_dir_iterator_t* iter, const char *filename, fat32_file_entry_t* file_entry)
{
    char shortname[FAT_SHORT_NAME_LEN + FAT_SHORT_EXT_LEN+1];
    fat32_reset_dir_iterator(iter);
    while(1) {
        fat_iterate_dir_status_t iter_status = fat32_iterate_dir(meta, iter, file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            return FAT_PATH_RESOLVE_ERROR;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_ITER_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            return FAT_PATH_RESOLVE_NOT_FOUND;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        // TODO: Case insensitive matching
        if(strcmp((char*) file_entry->filename, filename) == 0) {
            return FAT_PATH_RESOLVE_FOUND;
        }
        fat_standardize_short_name(shortname, &file_entry->direntry);
        if(strcmp((char*) shortname, filename) == 0) {
            return FAT_PATH_RESOLVE_FOUND;
        }
    }
}

static fat_resolve_path_status_t fat32_resolve_path(fat32_meta_t* meta, const char *path, fat32_file_entry_t* file_entry)
{

    char filename[FAT32_FILENAME_SIZE] = {0};
    char* remainding_path = split_path((char*) path, filename);

    fat_dir_iterator_t iter = {.first_cluster = meta->bootsector->root_cluster};

    if(strlen(path) == 0) {
        return FAT_PATH_RESOLVE_INVALID_PATH;
    }
    if(*path != '/') {
        return FAT_PATH_RESOLVE_INVALID_PATH;
    }
    if(remainding_path == NULL) {
        return FAT_PATH_RESOLVE_ROOT_DIR;
    }

    fat_resolve_path_status_t resolve_status;
    while(1) {
        resolve_status = fat32_dir_lookup(meta, &iter, filename, file_entry);
        if(resolve_status != FAT_PATH_RESOLVE_FOUND) {
            // if not found or error
            break;
        }
        if(remainding_path == NULL || *remainding_path==0) {
            // if is last part of the path
            break;
        } else {
            if(!HAS_ATTR(file_entry->direntry.attr,FAT_ATTR_DIRECTORY)) {
                // not a dir
                resolve_status = FAT_PATH_RESOLVE_INVALID_PATH;
                break;
            }
            fat_free_dir_iterator(&iter);
            iter.first_cluster = file_entry->direntry.cluster_lo + (file_entry->direntry.cluster_hi << 16);
            remainding_path = split_path(remainding_path, filename);
        }
    }

    fat_free_dir_iterator(&iter);

    if(resolve_status == FAT_PATH_RESOLVE_NOT_FOUND && !(remainding_path == NULL || *remainding_path==0)) {
        // if a middle part of the path is not found, return invalid path instead of not found 
        return FAT_PATH_RESOLVE_INVALID_PATH;
    }

    return resolve_status;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    fat_dir_iterator_t iter = {0};
    fat_iterate_dir_status_t iter_status; 

    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOTDIR;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        iter.first_cluster = global_fat_meta.bootsector->root_cluster;
    }
    if(status == FAT_PATH_RESOLVE_FOUND) {
        if(!HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
            return -ENOTDIR;
        }
        iter.first_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    }

    // TODO: Shall be covered by the dot entries
	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

    while(1) {
        iter_status = fat32_iterate_dir(&global_fat_meta, &iter, &file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            fat_free_dir_iterator(&iter);
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_ITER_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            fat_free_dir_iterator(&iter);
            return 0;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_VOLUME_ID)) {
            // Skip Volume label entry when listing directory
            continue;
        }
        filler(buf, (char*) file_entry.filename, NULL, 0, 0);
    }
}

time_t convert_datetime(uint16_t date_entry, uint16_t time_entry) {
	struct tm * time_info;
	time_t raw_time;

	time(&raw_time);
	time_info = localtime(&raw_time);
	time_info->tm_sec = (time_entry & 0x1F) << 1;
	time_info->tm_min = (time_entry & 0x7E0) >> 5;
	time_info->tm_hour = (time_entry & 0xF800) >> 11;
	time_info->tm_mday = date_entry & 0x1F;
	time_info->tm_mon = ((date_entry & 0x1E0) >> 5) - 1;
	time_info->tm_year = ((date_entry & 0xFE00) >> 9) + 80;
	return mktime(time_info);
}

void get_timestamp(uint16_t* date_entry, uint16_t* time_entry)
{
	struct tm * time_info;
	time_t raw_time;
	time(&raw_time);
	time_info = localtime(&raw_time);
    *time_entry = 0;
    *time_entry += (time_info->tm_sec >> 1);
    *time_entry += (time_info->tm_min << 5);
    *time_entry += (time_info->tm_hour << 11);
    *date_entry = 0;
    *date_entry += time_info->tm_mday;
    *date_entry += (time_info->tm_mon + 1) << 5;
    *date_entry += (time_info->tm_year - 80) << 9;
}

static int fs_getattr(const char *path, struct stat *st,
			 struct fuse_file_info *fi)
{
	(void) fi;

	memset(st, 0, sizeof(struct stat));

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    uint32_t bytes_per_cluster = global_fat_meta.bootsector->bytes_per_sector*global_fat_meta.bootsector->sectors_per_cluster;

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        // For root dir
        st->st_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
        st->st_nlink = 2;
        uint32_t cluster_number = global_fat_meta.bootsector->root_cluster;
        st->st_size = count_clusters(&global_fat_meta, cluster_number)*bytes_per_cluster;
        return 0;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOTDIR;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }

    if(status == FAT_PATH_RESOLVE_FOUND) {
        if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_READ_ONLY)) {
            st->st_mode = S_IRUSR | S_IRGRP | S_IROTH;
        } else {
            st->st_mode = S_IRWXU | S_IRWXG | S_IRWXO;
        }
        if (HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
            st->st_mode |= S_IFDIR;
            st->st_nlink = 2;
            uint32_t cluster_number = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
            st->st_size = count_clusters(&global_fat_meta, cluster_number)*bytes_per_cluster;
        } else {
            st->st_mode |= S_IFREG;
            st->st_nlink = 1;
            st->st_size = file_entry.direntry.size;
        }
    }
	st->st_mtime = convert_datetime(file_entry.direntry.mtime_date, file_entry.direntry.mtime_time);
	st->st_ctime = convert_datetime(file_entry.direntry.ctime_date, file_entry.direntry.ctime_time);

    return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

    if(offset < 0) {
        return -EINVAL;
    }
    uint32_t unsigned_offset = offset;

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EISDIR;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }

    assert(status == FAT_PATH_RESOLVE_FOUND);

    if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
        return -EISDIR;
    }

    if(offset >= file_entry.direntry.size) {
        return 0;
    }

    if(offset + size > file_entry.direntry.size) {
        size = file_entry.direntry.size - offset;
    }

    fat_cluster_t cluster;
    cluster.next = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    uint32_t bytes_per_cluster = global_fat_meta.bootsector->sectors_per_cluster*global_fat_meta.bootsector->bytes_per_sector;
    uint8_t* cluster_buffer = malloc(bytes_per_cluster);
    uint32_t size_in_this_cluster;
    int64_t total_bytes_read = 0;
    while(1) {
        fat_cluster_status_t cluster_status = fat32_get_cluster_info(&global_fat_meta, cluster.next, &cluster);

        if(cluster_status == FAT_CLUSTER_BAD || cluster_status == FAT_CLUSTER_FREE || cluster_status == FAT_CLUSTER_RESERVED) {
            free(cluster_buffer);
            return -EIO;
        }
        assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);

        if(unsigned_offset < bytes_per_cluster) {
            int64_t read_res = fat32_read_clusters(&global_fat_meta, cluster.curr, 1, cluster_buffer);
            if(read_res < 0) {
                free(cluster_buffer);
                return read_res;
            }
            if(size <= bytes_per_cluster - unsigned_offset) {
                size_in_this_cluster = size;
            } else {
                size_in_this_cluster = bytes_per_cluster - unsigned_offset;
            }
            memmove(buf, cluster_buffer + unsigned_offset, size_in_this_cluster);
            buf += size_in_this_cluster;
            unsigned_offset = 0;
            size -= size_in_this_cluster;
            total_bytes_read += size_in_this_cluster;
        } else {
            unsigned_offset -= bytes_per_cluster;
        }

        if(size == 0) {
            free(cluster_buffer);
            return total_bytes_read;
        }

        if(cluster_status == FAT_CLUSTER_EOC) {
            return -EIO;
        }
    }
}

// Free non-used clusters for a directory
// static int32_t fat32_trim_directory(block_storage_t* storage, fat32_meta_t* meta, uint32_t start_cluster_number, uint32_t end_cluster_number)
// {
//     fat_cluster_t cluster;
//     fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, start_cluster_number, &cluster);

//     if(cluster.prev == 0 && start_cluster_number == end_cluster_number) {
//         // do no trim if only first cluster is affected
//         return 0;
//     }
//     if(cluster.prev == 0) {
//         // start trimming from at least the second cluster
//         cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
//     }

//     uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;
//     fat32_direntry_t* dir =  malloc(cluster_byte_size);
//     uint32_t max_dir_entry_count = cluster_byte_size / sizeof(fat32_direntry_t);
    
//     int32_t freed = 0; 
//     while(1) {
//         uint32_t bytes_read = fat32_read_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
//         if(bytes_read != cluster_byte_size) {
//             free(dir);
//             return -1;
//         }
//         // Check if all entries are unused
//         uint32_t idx;
//         for(idx = 0; idx <= max_dir_entry_count; idx++) {
//             if(dir[idx].short_entry.name[0] != 0xE5 && dir[idx].short_entry.name[0] != 0) {
//                 // If an entry is used
//                 break;
//             }
//         }

//         if(idx == max_dir_entry_count) {
//             // all entries are unused
//             int32_t res = fat32_free_cluster(storage, meta, cluster.curr, 1);
//             if(res < 0) {
//                 free(dir);
//                 return -1;
//             }
//             freed++;
//         }

//         if(cluster.curr == end_cluster_number) {
//             free(dir);
//             return freed;
//         }
//         assert(cluster.next != 0);
//         cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
//     }


// }


// Set short name according to the standardized filename
static int32_t fat32_set_short_name(fat32_file_entry_t* file_entry)
{
    // TODO: Add checks for illegal characters
    int32_t filename_len = (int32_t) strlen((char*)file_entry->filename);
    assert(filename_len > 0);
    memset(file_entry->direntry.nameext, ' ', FAT_SHORT_NAME_LEN + FAT_SHORT_EXT_LEN);
    uint32_t copied = 0;
    for(int32_t i = 0; copied < FAT_SHORT_NAME_LEN && i < filename_len; i++) {
        if(file_entry->filename[i] == ' ') {
            continue;
        }
        if(copied == 0 && file_entry->filename[i] == '.') {
            continue;
        }
        if(file_entry->filename[i] == '.') {
            break;
        }
        file_entry->direntry.name[copied] = file_entry->filename[i];
        if(copied == 0 && file_entry->direntry.name[copied] == 0xE5) {
            file_entry->direntry.name[0] = 0x05;
        }
        copied++;
    }
    copied = 0;
    for(int32_t i = filename_len - 1; i >= 0; i--) {
        // find last period
        if(file_entry->filename[i] == '.') {
            for(int32_t j = i + 1; j < filename_len; j++) {
                if(file_entry->filename[j] != ' ' && file_entry->filename[j] != '.') {
                    file_entry->direntry.ext[copied] = file_entry->filename[j];
                    copied++;
                }
                if(copied == FAT_SHORT_EXT_LEN) {
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

// Return: numeric tail appended for short name collision prevention
static int32_t fat32_set_numeric_tail(fat32_meta_t* meta, fat_dir_iterator_t* iter, fat32_file_entry_t* file_entry)
{
    char shortname[FAT_SHORT_NAME_LEN + FAT_SHORT_EXT_LEN+1];
    fat32_file_entry_t existing_entry = {0};
    char buff[FAT_SHORT_NAME_LEN];

    // Assume we always need to add numeric tail here
    // Ref: http://elm-chan.org/fsw/ff/00index_e.html
    for (uint32_t number_tail = 1; number_tail <= 999999; number_tail++) {
        uint32_t seq = number_tail;
        int32_t i=FAT_SHORT_NAME_LEN - 1;
        do {
            uint8_t c = (uint8_t)((seq % 16) + '0');
            if (c > '9') c += 7;
            buff[i--] = c;
            seq /= 16;
        } while(seq);
        buff[i] = '~';

        fat32_file_entry_t working_entry = *file_entry;
        /* Append the number to the SFN body */
        int32_t j = 0;
        for (; j < i && working_entry.direntry.name[j] != ' '; j++);
        do {
            working_entry.direntry.name[j++] = (i < 8) ? buff[i++] : ' ';
        } while (j < 8);

        fat_standardize_short_name(shortname, &working_entry.direntry);
        fat_resolve_path_status_t status = fat32_dir_lookup(meta, iter, shortname, &existing_entry);
        if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
            // if short name has no collision anymore
            memcpy(file_entry->direntry.name, working_entry.direntry.name, FAT_SHORT_NAME_LEN);
            return number_tail;
        }
    }
    return -1;
}

// Return: dir entries added
static int32_t fat32_add_file_entry(fat32_meta_t* meta, fat_dir_iterator_t* iter, fat32_file_entry_t* file_entry)
{
    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;
    uint32_t dir_entry_per_cluster = cluster_byte_size / sizeof(fat32_direntry_t);

    // for sake of simplicity, will always save the file name as LFN entry, even if it fits into 8.3 format
    // filename are US-ASCII characters, each will take a USC-2 char space in LFN
    uint32_t lfn_len = strlen(file_entry->filename);
    uint32_t lfn_entry_needed = lfn_len == 0? 0: (lfn_len - 1)/FAT32_USC2_FILE_NAME_LEN_PER_LFN + 1;
    uint32_t dir_entry_needed = lfn_entry_needed + 1;

    fat32_file_entry_t candidate_entry = {0};
    fat32_reset_dir_iterator(iter);

    // Find contagious free space for the entries
    uint32_t free_entry_count = 0;
    int32_t first_free_entry_idx = -1;
    while(1) {
        if(free_entry_count >= dir_entry_needed) {
            break;
        }
        fat_iterate_dir_status_t iter_status = fat32_iterate_dir(meta, iter, &candidate_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_VALID_ENTRY || iter_status == FAT_DIR_ITER_DOT_ENTRY) {
            free_entry_count = 0;
            first_free_entry_idx = -1;
            continue;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            free_entry_count += candidate_entry.dir_entry_count;
            if(first_free_entry_idx < 0) {
                first_free_entry_idx = candidate_entry.first_dir_entry_idx;
            }
            continue;
        }
        assert(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY);
        assert(free_entry_count < dir_entry_needed);
        // if reach the end of entries and still no enough space, allocate a new cluster
        uint32_t clusters_to_alloc = (dir_entry_needed - free_entry_count - 1) / dir_entry_per_cluster + 1;
        uint32_t first_new_cluster = fat32_allocate_cluster(meta, fat32_index_cluster_chain(meta, iter->first_cluster, -1), clusters_to_alloc);
        if(first_new_cluster == 0) {
            return -EIO;
        }
        fat_free_dir_iterator(iter);
    }

    // Reuse iterator dir buffer
    fat32_direntry_t* dir = iter->dir_entries;

    // Write dir entries to the buffer
    // uint32_t dir_entry_added = 0;
    uint32_t remaining_char_to_copy = lfn_len;
    char* p_filename = &file_entry->filename[lfn_len];
    fat32_set_short_name(file_entry);
    int32_t res_numtail = fat32_set_numeric_tail(meta, iter, file_entry);
    if(res_numtail < 0) {
        return -ENOSPC;
    }
    fat32_direntry_short_t short_entry = file_entry->direntry;
    fat32_direntry_long_t long_entry = {.attr = FAT_ATTR_LFN, .csum = lfn_checksum(short_entry.nameext), .type=0x00, .reserved2=0x00};
    for(uint32_t idx = 0; idx < dir_entry_needed; idx++) {
        if(idx == dir_entry_needed - 1) {
            // only short entry left to write
            dir[first_free_entry_idx + idx].short_entry = short_entry;
        } else {
            // Add LFN entry
            fat32_direntry_long_t e = long_entry;

            e.seq = lfn_entry_needed - idx;
            if(idx == 0) {
                // Mark first lfn entry
                e.seq += 0x40; 
            }

            uint32_t char_to_copy;
            if(remaining_char_to_copy % FAT32_USC2_FILE_NAME_LEN_PER_LFN != 0) {
                char_to_copy = remaining_char_to_copy % FAT32_USC2_FILE_NAME_LEN_PER_LFN;
            } else {
                char_to_copy = FAT32_USC2_FILE_NAME_LEN_PER_LFN;
            }
            remaining_char_to_copy -= char_to_copy;
            p_filename -= char_to_copy;

            memset(e.name1, 0xFF, 5*2);
            memset(e.name2, 0xFF, 6*2);
            memset(e.name3, 0xFF, 2*2);
            assert(5+6+2 == FAT32_USC2_FILE_NAME_LEN_PER_LFN);
            for(uint32_t i=0; i<char_to_copy; i++) {
                if(p_filename[i] == 0) {
                    break;
                }
                if(i<5) {
                    e.name1[i] = (uint16_t) p_filename[i];
                } else if(i<5+6) {
                    e.name2[i-5] = (uint16_t) p_filename[i];
                } else {
                    e.name3[i-(5+6)] = (uint16_t) p_filename[i];
                }
            }

            if(char_to_copy < FAT32_USC2_FILE_NAME_LEN_PER_LFN) {
                // Add NULL termination
               if(char_to_copy < 5) {
                   e.name1[char_to_copy] = 0;
               } else if(char_to_copy < 5+6) {
                   e.name2[char_to_copy-5] = 0;
               } else {
                   e.name3[char_to_copy-(5+6)] = 0;
               }
            }
            dir[first_free_entry_idx + idx].long_entry = e;
        }
    }

    // Write the dir to disk
    uint32_t dir_entry_cluster = fat32_cluster_by_offset(meta, iter->first_cluster, first_free_entry_idx*sizeof(fat32_direntry_t));
    uint32_t dir_entry_cluster_first_idx = (first_free_entry_idx / iter->entry_per_cluster) * iter->entry_per_cluster;
    uint32_t clusters_to_write = 1 + ((first_free_entry_idx + dir_entry_needed - 1) / iter->entry_per_cluster) - (dir_entry_cluster_first_idx / iter->entry_per_cluster);
    int64_t res = fat32_write_clusters(meta, dir_entry_cluster, clusters_to_write, (uint8_t*) &dir[dir_entry_cluster_first_idx]);
    if(res < 0) {
        return res;
    }


    return dir_entry_needed;

}

//Return: dir entries removed
static int32_t fat32_rm_file_entry(fat32_meta_t* meta, fat_dir_iterator_t* iter, fat32_file_entry_t* file_entry)
{
    // Reuse iterator dir buffer, need to ensure the iter is initialized
    fat32_file_entry_t entry = {0};
    fat32_iterate_dir(meta, iter, &entry);
    fat32_direntry_t* dir = iter->dir_entries;

    // Write dir entries to the buffer
    for(uint32_t i = 0; i < file_entry->dir_entry_count; i++) {
        // Set dir entry as deleted
        dir[file_entry->first_dir_entry_idx + i].short_entry.name[0] = 0xE5;
    }

    // Write the dir to disk
    uint32_t dir_entry_cluster = fat32_cluster_by_offset(meta, iter->first_cluster, file_entry->first_dir_entry_idx*sizeof(fat32_direntry_t));
    uint32_t dir_entry_cluster_first_idx = (file_entry->first_dir_entry_idx / iter->entry_per_cluster) * iter->entry_per_cluster;
    uint32_t clusters_to_write = 1 + ((file_entry->first_dir_entry_idx + file_entry->dir_entry_count - 1) / iter->entry_per_cluster) - (dir_entry_cluster_first_idx / iter->entry_per_cluster);
    int64_t res = fat32_write_clusters(meta, dir_entry_cluster, clusters_to_write, (uint8_t*) &dir[dir_entry_cluster_first_idx]);
    if(res < 0) {
        return res;
    }

    return file_entry->dir_entry_count;
}

static int32_t fat32_create_new(const char *path, fat32_direntry_short_t short_dir_entry)
{
    // TODO: Test for illegal path (characters / length etc.)
    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_FOUND || status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EEXIST;
    }
    assert(status == FAT_PATH_RESOLVE_NOT_FOUND);
    // when resolve returns not found, the file entry is filled with last entry in the target dir
    // so we can use it to retrieve the dir cluster info 
    fat_dir_iterator_t iter = {.first_cluster = file_entry.dir_cluster};
    uint32_t path_len = strlen(path);
    assert(path_len > 1);
    char* filename = (char*) &path[path_len-1];
    while(*filename == '/') {
        // skip trailing '/'
        *filename = 0;
        filename--;
    }
    if(filename < path) {
        return -EPERM;
    }
    // Get file name from path
    while(*filename!='/' && filename>path) {
        filename--;
    }
    filename++;

    strcpy(file_entry.filename, filename);
    file_entry.direntry = short_dir_entry;
    uint16_t date, time;
    get_timestamp(&date, &time);
    file_entry.direntry.ctime_date = date;
    file_entry.direntry.ctime_time = time;
    file_entry.direntry.mtime_date = date;
    file_entry.direntry.mtime_time = time;

    int32_t res = fat32_add_file_entry(&global_fat_meta, &iter, &file_entry);
    fat_free_dir_iterator(&iter);
    if(res < 0) {
        return res;
    }
    return 0;
}

static int fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    (void) rdev;

    if(!S_ISREG(mode)) {
        // Only support creating regular file
        return -EPERM;
    }

    fat32_direntry_short_t short_dir_entry = {0};
    int32_t res = fat32_create_new(path, short_dir_entry);
    return res;
}

static int fs_mkdir(const char *path, mode_t mode)
{
    (void) mode;
    
    fat32_direntry_short_t short_dir_entry = {.attr = FAT_ATTR_DIRECTORY};
    uint32_t first_new_cluster = fat32_allocate_cluster(&global_fat_meta, 0, 1);
    if(first_new_cluster == 0) {
        return -EIO;
    }
    short_dir_entry.cluster_lo = first_new_cluster & 0x0000FFFF;
    short_dir_entry.cluster_hi = first_new_cluster >> 16;
    int32_t res = fat32_create_new(path, short_dir_entry);
    // TODO: Add dot entries

    return res;
}

static int fs_unlink(const char *path)
{

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND || status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        // not allow to unlink/delete root dir
        return -EPERM;
    }
    assert(status == FAT_PATH_RESOLVE_FOUND);    

    if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
        // Not allow to unlink directory
        return -EISDIR;
    }

    // Remove the dir entry
    fat_dir_iterator_t iter = {.first_cluster = file_entry.dir_cluster};
    int32_t res = fat32_rm_file_entry(&global_fat_meta, &iter, &file_entry);
    fat_free_dir_iterator(&iter);
    if(res < 0) {
        return res;
    }

    // Free data clusters
    uint32_t file_content_cluster_number = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    fat_cluster_t cluster = {0};
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(&global_fat_meta, file_content_cluster_number, &cluster);
    if(cluster_status == FAT_CLUSTER_EOC || FAT_CLUSTER_USED) {
        res = fat32_free_cluster(&global_fat_meta, 0, file_content_cluster_number, 0); // free the whole cluster chain
        if(res < 0) {
            return res;
        }
    }

    return 0;
}

static int fs_rmdir(const char *path)
{
    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND || status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        // not allow to unlink/delete root dir
        return -EPERM;
    }
    assert(status == FAT_PATH_RESOLVE_FOUND);

    if(!HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
        // Not allow to perform rmdir on file
        return -ENOTDIR;
    }

    uint32_t dir_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    fat_dir_iterator_t iter = {.first_cluster = dir_cluster};
    fat32_file_entry_t file_in_dir = {0};

    while(1) {
        fat_iterate_dir_status_t iter_status = fat32_iterate_dir(&global_fat_meta,&iter,&file_in_dir);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            fat_free_dir_iterator(&iter);
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_ITER_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            // Dir is empty
            break;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        if(HAS_ATTR(file_in_dir.direntry.attr, FAT_ATTR_VOLUME_ID)) {
            // Skip Volume label entry when listing directory
            continue;
        }
        // Dir is not empty
        fat_free_dir_iterator(&iter);
        return -EPERM;
    }

    fat_free_dir_iterator(&iter);
    iter.first_cluster = file_entry.dir_cluster;
    int32_t res = fat32_rm_file_entry(&global_fat_meta, &iter, &file_entry);
    fat_free_dir_iterator(&iter);
    if(res < 0) {
        return res;
    }

    // Free data clusters
    uint32_t file_content_cluster_number = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    fat_cluster_t cluster = {0};
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(&global_fat_meta, file_content_cluster_number, &cluster);
    if(cluster_status == FAT_CLUSTER_EOC || FAT_CLUSTER_USED) {
        res = fat32_free_cluster(&global_fat_meta, 0, file_content_cluster_number, 0); // free the whole cluster chain
        if(res < 0) {
            return res;
        }
    }

    return 0;
}


static int32_t fat32_write_to_offset(fat32_meta_t* meta, uint32_t first_cluster, uint32_t offset, uint32_t size, const uint8_t* buff)
{
    uint32_t bytes_per_cluster = meta->bootsector->sectors_per_cluster*meta->bootsector->bytes_per_sector;
    uint32_t cluster_start_writing = fat32_cluster_by_offset(meta, first_cluster, offset);
    uint32_t clusters_to_write = 1 + ((offset + size - 1) / bytes_per_cluster) - (offset / bytes_per_cluster);
    fat_cluster_t cluster = {.next = cluster_start_writing};

    uint8_t* cluster_buff = malloc(bytes_per_cluster);
    uint32_t start_offset_in_cluster, end_offset_in_cluster;
    for(uint32_t i=0; i < clusters_to_write; i++) {
        assert(cluster.next != 0);
        fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
        assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);
        int64_t read_res = fat32_read_clusters(meta, cluster.curr, 1, cluster_buff);
        if(read_res < 0) {
            free(cluster_buff);
            return read_res;
        }
        if(i == 0) {
            start_offset_in_cluster = offset % bytes_per_cluster;
        } else {
            start_offset_in_cluster = 0;
        }
        if(i == clusters_to_write - 1) {
            end_offset_in_cluster = (offset + size - 1) % bytes_per_cluster;
        } else {
            end_offset_in_cluster = bytes_per_cluster - 1;
        }
        memmove(cluster_buff + start_offset_in_cluster, buff, end_offset_in_cluster - start_offset_in_cluster + 1);
        int64_t write_res = fat32_write_clusters(meta, cluster.curr, 1, cluster_buff);
        if(write_res < 0) {
            free(cluster_buff);
            return write_res;
        }
        buff += end_offset_in_cluster - start_offset_in_cluster + 1;
    }
    free(cluster_buff);
    return 0;
}

static int fs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    (void) fi;
    
    if(offset < 0) {
        return -EINVAL;
    }

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EISDIR;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }

    assert(status == FAT_PATH_RESOLVE_FOUND);

    if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
        return -EISDIR;
    }

    uint32_t first_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    uint32_t cluster_count = first_cluster == 0 ? 0 : count_clusters(&global_fat_meta, first_cluster);
    uint32_t bytes_per_cluster = global_fat_meta.bootsector->sectors_per_cluster*global_fat_meta.bootsector->bytes_per_sector;
    uint32_t allocated_size = bytes_per_cluster * cluster_count;

    if(offset + size > allocated_size) {
        uint32_t clusters_to_allocate = ((offset + size) - allocated_size - 1) / bytes_per_cluster + 1;
        uint32_t first_allocated_cluster = fat32_allocate_cluster(&global_fat_meta, fat32_index_cluster_chain(&global_fat_meta, first_cluster, -1), clusters_to_allocate);
        if(first_allocated_cluster == 0) {
            return -EIO;
        }
        if(first_cluster == 0) {
            first_cluster = first_allocated_cluster;
            cluster_count += clusters_to_allocate;
            allocated_size = bytes_per_cluster * cluster_count;
            file_entry.direntry.cluster_lo = first_allocated_cluster & 0x0000FFFF;
            file_entry.direntry.cluster_hi = first_allocated_cluster >> 16;
        }
    }

    if(offset + size > file_entry.direntry.size) {
        file_entry.direntry.size = offset + size;
    }

    uint16_t date, time;
    get_timestamp(&date, &time);
    file_entry.direntry.mtime_time = time;
    file_entry.direntry.mtime_date = date;

    // Update dir entry
    fat_dir_iterator_t iter = {.first_cluster = file_entry.dir_cluster};
    int32_t dir_res = fat32_rm_file_entry(&global_fat_meta, &iter, &file_entry);
    if(dir_res<0) {
        return dir_res;
    }
    dir_res = fat32_add_file_entry(&global_fat_meta, &iter, &file_entry);
    if(dir_res<0) {
        return dir_res;
    }
    fat_free_dir_iterator(&iter);

    if(size == 0) {
        return 0;
    }

    int32_t write_res = fat32_write_to_offset(&global_fat_meta, first_cluster, offset, size, (uint8_t*) buf);
    if(write_res < 0) {
        return write_res;
    }

    return size;
}


static int fs_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void) fi;
    
    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EISDIR;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }

    assert(status == FAT_PATH_RESOLVE_FOUND);

    if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
        return -EISDIR;
    }

    if(size == file_entry.direntry.size) {
        // Same size, do nothing
        return 0;
    }

    uint32_t first_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    uint32_t cluster_count = first_cluster == 0 ? 0 : count_clusters(&global_fat_meta, first_cluster);
    uint32_t bytes_per_cluster = global_fat_meta.bootsector->sectors_per_cluster*global_fat_meta.bootsector->bytes_per_sector;
    uint32_t allocated_size = bytes_per_cluster * cluster_count;
    uint32_t orig_size = file_entry.direntry.size;

    if(size > allocated_size) {
        uint32_t clusters_to_allocate = (size - allocated_size - 1) / bytes_per_cluster + 1;
        uint32_t first_allocated_cluster = fat32_allocate_cluster(&global_fat_meta, fat32_index_cluster_chain(&global_fat_meta, first_cluster, -1), clusters_to_allocate);
        if(first_allocated_cluster == 0) {
            return -EIO;
        }
        if(first_cluster == 0) {
            first_cluster = first_allocated_cluster;
            cluster_count += clusters_to_allocate;
            allocated_size = bytes_per_cluster * cluster_count;
            file_entry.direntry.cluster_lo = first_allocated_cluster & 0x0000FFFF;
            file_entry.direntry.cluster_hi = first_allocated_cluster >> 16;
        }
    } else if(allocated_size - size >= bytes_per_cluster){
        int32_t clusters_to_free = (allocated_size - size) / bytes_per_cluster;
        uint32_t first_cluster_to_free = fat32_index_cluster_chain(&global_fat_meta, first_cluster, -clusters_to_free);
        uint32_t last_remaining_cluster;
        if(first_cluster_to_free == first_cluster) {
            last_remaining_cluster = 0;
        } else {
            last_remaining_cluster = fat32_index_cluster_chain(&global_fat_meta, first_cluster, -clusters_to_free - 1);
        }
        int32_t free_res = fat32_free_cluster(&global_fat_meta, last_remaining_cluster, first_cluster_to_free, 0);
        if(free_res < 0) {
            return free_res;
        }
        cluster_count -= clusters_to_free;
        allocated_size = bytes_per_cluster * cluster_count;
        if(cluster_count == 0) {
            file_entry.direntry.cluster_lo = 0;
            file_entry.direntry.cluster_hi = 0;
        }
    }
    file_entry.direntry.size = size;
    uint16_t date, time;
    get_timestamp(&date, &time);
    file_entry.direntry.mtime_time = time;
    file_entry.direntry.mtime_date = date;

    // Update dir entry
    fat_dir_iterator_t iter = {.first_cluster = file_entry.dir_cluster};
    int32_t dir_res = fat32_rm_file_entry(&global_fat_meta, &iter, &file_entry);
    if(dir_res<0) {
        return dir_res;
    }
    dir_res = fat32_add_file_entry(&global_fat_meta, &iter, &file_entry);
    if(dir_res<0) {
        return dir_res;
    }
    fat_free_dir_iterator(&iter);

    if(size == 0) {
        return 0;
    }

    if(size > orig_size) {
        uint8_t* zeros = malloc(size - orig_size);
        memset(zeros, 0, size - orig_size);
        int32_t write_res = fat32_write_to_offset(&global_fat_meta, first_cluster, orig_size, size - orig_size, zeros);
        if(write_res < 0) {
            return write_res;
        }
    }

    return 0;
}

static int fs_rename(const char *from, const char *to, unsigned int flags)
{
    (void) flags;
    
    if(strcmp(from, to) == 0) {
        return 0;
    }

    fat32_file_entry_t from_file_entry = {0};
    fat_resolve_path_status_t from_status = fat32_resolve_path(&global_fat_meta, from, &from_file_entry);

    if(from_status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EPERM;
    }
    if(from_status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(from_status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(from_status == FAT_PATH_RESOLVE_NOT_FOUND) {
        return -ENOENT;
    }

    assert(from_status == FAT_PATH_RESOLVE_FOUND);

    fat32_file_entry_t to_file_entry = {0};
    fat_resolve_path_status_t to_status = fat32_resolve_path(&global_fat_meta, to, &to_file_entry);

    if(to_status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EPERM;
    }
    if(to_status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(to_status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(to_status == FAT_PATH_RESOLVE_FOUND) {
        // Replace dir entry
        fat_dir_iterator_t iter = {.first_cluster = to_file_entry.dir_cluster};
        int32_t dir_res = fat32_rm_file_entry(&global_fat_meta, &iter, &to_file_entry);
        if(dir_res<0) {
            return dir_res;
        }
    }

    int32_t create_res = fat32_create_new(to, from_file_entry.direntry);
    if(create_res < 0) {
        return create_res;
    }

    // Remove old dir entry
    fat_dir_iterator_t iter = {.first_cluster = from_file_entry.dir_cluster};
    int32_t dir_res = fat32_rm_file_entry(&global_fat_meta, &iter, &from_file_entry);
    if(dir_res<0) {
        return dir_res;
    }

	return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
    (void) fi;

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(&global_fat_meta, path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        return -EISDIR;
    }
    if(status == FAT_PATH_RESOLVE_INVALID_PATH) {
        return -ENOENT;
    }
    if(status == FAT_PATH_RESOLVE_ERROR) {
        return -EIO;
    }
    if(status == FAT_PATH_RESOLVE_FOUND) {
        if(HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
            return -EISDIR;
        }
        if(HAS_ATTR(fi->flags, O_EXCL)) {
            // O_EXCL Ensure that this call creates the file
            return -EEXIST;
        }
        // Do nothing
        return 0;
    }
    assert(status == FAT_PATH_RESOLVE_NOT_FOUND);
    if(HAS_ATTR(fi->flags, O_CREAT)) {
        fat32_direntry_short_t short_dir_entry = {0};
        int32_t res = fat32_create_new(path, short_dir_entry);
        if(res < 0) {
            return res;
        }
    }
    if(HAS_ATTR(fi->flags, O_TRUNC)) {
        int32_t res = fs_truncate(path, 0, fi);
        if(res < 0) {
            return res;
        }
    }

	return 0;
}

static int fs_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
    (void) fi;
    // Do nothing

	return 0;
}



//Ref: https://libfuse.github.io/doxygen/structfuse__operations.html
static const struct fuse_operations fs_oper = {
	.init       = fs_init,
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
    .read       = fs_read,
    .unlink     = fs_unlink,
    .rmdir      = fs_rmdir,
    .mknod      = fs_mknod,
    .mkdir      = fs_mkdir,
    .write      = fs_write,
    .open       = fs_open,
    .release    = fs_release,
    .truncate   = fs_truncate,
    .rename     = fs_rename,
};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --image_path=<s>    Path to the file system disk image file\n"
	       "                        (default \"fat32_fs_image.bin\")\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.image_path = strdup("fat32_fs_image.bin");

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

    int res = initialize_block_storage(options.image_path);
    if(res < 0) {
        printf("Init image failed: %d\n", res);
        exit(1);
    }

    // Assume to use first block storage
    global_fat_meta.storage = get_block_storage(0);

    // res = create_fs();
    // if(res < 0) {
    //     printf("Create FS failed: %d\n", res);
    //     exit(1);
    // }

    // Read header
    res = fat32_get_meta(&global_fat_meta);
    if(res != 0) {
        printf("Fail to parse the file system, maybe not FAT32?\n");
        exit(1);
    }

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	ret = fuse_main(args.argc, args.argv, &fs_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}
