#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

#include "fat.h"
#include "block_io.h"

#define FUSE_USE_VERSION 31
#include <fuse.h>

#define HAS_ATTR(file,attr) (((file)&(attr)) == (attr))

static fat32_meta_t global_fat_meta;
static block_storage_t* global_storage;

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

int32_t fat32_get_meta(block_storage_t* storage, fat32_meta_t* meta)
{
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
    // Populate the doubly linned FAT list
    uint32_t fat_entry_count = fat_byte_size/sizeof(meta->fat[0]);
    meta->linked_fat = malloc(sizeof(fat_cluster_stripped_t) * fat_entry_count);
    memset(meta->linked_fat, 0, sizeof(fat_cluster_stripped_t) * fat_entry_count);
    uint32_t next_cluster_number;
    for(uint32_t i = 2; i < fat_entry_count; i++) {
        // next/prev of linked_fat is cluster number, not FAT entry raw value
        next_cluster_number = meta->fat[i] & 0x0FFFFFFF;
        if(next_cluster_number >= 0x00000002 && next_cluster_number <= 0x0FFFFFEF) {
            meta->linked_fat[i].next = next_cluster_number;
            meta->linked_fat[next_cluster_number].prev = i;
        }
    }
    // Ensure the linked_fat is populated correctly
    for(uint32_t i = 2; i < fat_entry_count; i++) {
        fat_cluster_status_t status = fat32_interpret_fat_entry(meta->fat[i]);
        if(status == FAT_CLUSTER_USED) {
            assert(meta->linked_fat[i].next != 0);
            assert(meta->linked_fat[meta->linked_fat[i].next].prev ==  i);
        } else if(status == FAT_CLUSTER_EOC) {
            assert(meta->linked_fat[i].next == 0);
        } else {
            assert(meta->linked_fat[i].next == 0);
            assert(meta->linked_fat[i].prev == 0);
        }
        if(meta->linked_fat[i].prev != 0) {
            assert(meta->linked_fat[meta->linked_fat[i].prev].next ==  i);
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

    cluster->next= meta->linked_fat[cluster_number].next;
    cluster->prev = meta->linked_fat[cluster_number].prev;
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

uint32_t fat32_read_cluster(block_storage_t* storage, fat32_meta_t* meta, uint32_t cluster_number, uint8_t* buff)
{
    assert(cluster_number >= 2);
    uint32_t sectors_to_read = meta->bootsector->sectors_per_cluster;
    // the cluster 0 and 1 are not of size sectors_per_cluster
    uint32_t lba = meta->bootsector->reserved_sector_count + meta->bootsector->table_sector_size_32*meta->bootsector->table_count + (cluster_number-2)*meta->bootsector->sectors_per_cluster;
    uint32_t bytes_read = storage->read_blocks(storage, buff, lba, sectors_to_read);
    return bytes_read;
}

uint32_t fat32_write_cluster(block_storage_t* storage, fat32_meta_t* meta, uint32_t cluster_number, uint8_t* buff)
{
    assert(cluster_number >= 2);
    uint32_t sectors_to_write = meta->bootsector->sectors_per_cluster;
    // the cluster 0 and 1 are not of size sectors_per_cluster
    uint32_t lba = meta->bootsector->reserved_sector_count + meta->bootsector->table_sector_size_32*meta->bootsector->table_count + (cluster_number-2)*meta->bootsector->sectors_per_cluster;
    uint32_t bytes_written = storage->write_blocks(storage, lba, sectors_to_write, buff);
    return bytes_written;
}

// trim staring and trailing spaces
void trim_space(char* str)
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
    while(str[end] == ' ' && end >= start) {
        end--;
    }
    memmove(str, &str[start], end - start + 1);
    str[end - start + 1] = 0;
}

fat_iterate_dir_status_t fat32_iterate_dir(block_storage_t* storage, fat32_meta_t* meta, fat_dir_iterator_t* iter, fat32_file_entry_t* file_entry)
{
    uint32_t cluster_size = meta->bootsector->sectors_per_cluster * meta->bootsector->bytes_per_sector;
    uint32_t max_dir_entry_per_cluster = cluster_size / sizeof(fat32_direntry_t);
    fat_cluster_t cluster;
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, iter->current_cluster, &cluster);
    if(!(cluster_status == FAT_CLUSTER_EOC || cluster_status == FAT_CLUSTER_USED)) {
        return FAT_DIR_ITER_ERROR;
    }
    if(iter->dir_entries == NULL) {
        // if iter not yet initialized, read the whole dir into memory
        uint32_t dir_total_cluster_count = count_clusters(meta, iter->current_cluster);
        iter->dir_entries = malloc(dir_total_cluster_count*cluster_size);
        for(uint32_t i = 0; i < dir_total_cluster_count; i++) {
            uint32_t bytes_read = fat32_read_cluster(storage, meta, iter->current_cluster, (uint8_t*) &iter->dir_entries[i*cluster_size]);
            if(bytes_read != cluster_size) {
                return FAT_DIR_ITER_ERROR;
            }
        }
        iter->current_dir_entry_idx = 0;
        iter->lfn_entry_buffered = 0;
    }

    while(1)
    {
        if(iter->current_dir_entry_idx >= max_dir_entry_per_cluster) {
            if(cluster_status != FAT_CLUSTER_USED) {
                return FAT_DIR_ITER_NO_MORE_ENTRY;
            }
            cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
            if(!(cluster_status == FAT_CLUSTER_EOC || cluster_status == FAT_CLUSTER_USED)) {
                return FAT_DIR_ITER_ERROR;
            }
            //TODO: how to access multi-cluster dir's cached memory?
            iter->current_dir_entry_idx = 0;
            iter->current_cluster = cluster.curr;
        }

        fat32_direntry_t* entry = &iter->dir_entries[iter->current_dir_entry_idx];
        // Algo Ref: https://wiki.osdev.org/FAT#Reading_Directories
        if(entry->short_entry.attr == FAT_ATTR_LFN){
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
                file_entry->dir_entry_cluster_start = iter->current_cluster;
                file_entry->dir_entry_idx_start = iter->current_dir_entry_idx;
                iter->lfn_checksum = entry->long_entry.csum;
                iter->lfn_entry_buffered = 1;
            } else if(iter->lfn_checksum != entry->long_entry.csum) {
                // skip this LFN entry if checksum doesn't match the last checksum
            } else {
                // not first LFN and checksum is consistent
                void* offset = ((void*) file_entry->filename) + sizeof(file_entry->filename) - FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*(iter->lfn_entry_buffered);
                memmove(offset-=sizeof(entry->long_entry.name3), entry->long_entry.name3, sizeof(entry->long_entry.name3));
                memmove(offset-=sizeof(entry->long_entry.name2), entry->long_entry.name2, sizeof(entry->long_entry.name2));
                memmove(offset-=sizeof(entry->long_entry.name1), entry->long_entry.name1, sizeof(entry->long_entry.name1));
                iter->lfn_entry_buffered++;
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
            if(iter->lfn_entry_buffered > 0 && iter->lfn_checksum == lfn_checksum(file_entry->direntry.nameext)) {
                // We do not support USC-2 UNICODE character, any non US-ASCII character will be replaced by '_'
                // as per Microsoft's documentation "Microsoft Extensible Firmware Initiative FAT32 File System Specification" 
                // https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
                uint32_t lfn_name_byte_len =  FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*iter->lfn_entry_buffered;
                uint8_t* start_of_filename = &file_entry->filename[sizeof(file_entry->filename)] - lfn_name_byte_len;
                for(uint32_t i=0; i<lfn_name_byte_len/2; i++) {
                    uint8_t usc2_first = start_of_filename[i*2];
                    uint8_t usc2_second = start_of_filename[i*2+1];
                    // Unicode (and UCS-2) is compatible with 7-bit ASCII / US-ASCII
                    if(usc2_first > 127 || usc2_second != 0) {
                        // if not US-ASCII
                        file_entry->filename[i] = '_';
                    } else {
                        file_entry->filename[i] = usc2_first;
                    }
                }
                file_entry->filename[lfn_name_byte_len] = 0;
                trim_space((char*)file_entry->filename);
            } else {
                // if not LFN buffered, use the 8.3 short name
                file_entry->dir_entry_idx_start = iter->current_dir_entry_idx;
                file_entry->dir_entry_cluster_start = iter->current_cluster;
                memmove(file_entry->filename, file_entry->direntry.name, sizeof( file_entry->direntry.name));
                file_entry->filename[sizeof(file_entry->direntry.name)] = 0;
                trim_space((char*)file_entry->filename);
                uint32_t name_len = strlen((char*)file_entry->filename);
                file_entry->filename[name_len] = '.';
                memmove(&file_entry->filename[name_len+1],  file_entry->direntry.ext, sizeof(file_entry->direntry.ext));
                file_entry->filename[name_len+1+sizeof(file_entry->direntry.ext)] = 0;
                trim_space((char*)file_entry->filename);
                if(strlen((char*)file_entry->filename)==name_len+1){
                    // if no extension, remove the '.' added
                    file_entry->filename[name_len] = 0;
                }
                if(file_entry->filename[0] == 0x05) {
                    // If DIR_Name[0] == 0x05, then the actual file name character for this byte is 0xE5
                    file_entry->filename[0] = 0xE5;
                }
            }
            
            // Increment pointers and/or counters and check the next entry. (goto number 1)
            iter->current_dir_entry_idx++;

            if(entry->short_entry.nameext[0] == 0) {
                // If the first byte of the entry is equal to 0 then there are no more files/directories in this directory. FirstByte==0, finish.
                return FAT_DIR_ITER_FREE_ENTRY;
            }
            if(entry->short_entry.nameext[0] == 0x2E) {
                // Entry for either "." or ".."
                return FAT_DIR_DOT_ENTRY;
            }
            if(entry->short_entry.nameext[0] == 0xE5) {
                // If the first byte of the entry is equal to 0xE5 then the entry is unused. FirstByte==0xE5, goto 8
                return FAT_DIR_ITER_DELETED;
            }
            return FAT_DIR_ITER_VALID_ENTRY;
        }
    }


}

static void fat_free_dir_iterator(fat_dir_iterator_t* iter)
{
    free(iter->dir_entries);
}

static fat_resolve_path_status_t fat32_resolve_path(block_storage_t* storage, fat32_meta_t* meta, const char *path, fat32_file_entry_t* file_entry)
{

    char filename[FAT32_FILENAME_SIZE] = {0};
    char* remainding_path = split_path((char*) path, filename);

    fat_dir_iterator_t iter = {0};
    iter.current_cluster = meta->bootsector->root_cluster;
    fat_iterate_dir_status_t iter_status; 

    if(strlen(path) == 0) {
        return FAT_PATH_RESOLVE_INVALID_PATH;
    }
    if(remainding_path == NULL) {
        return FAT_PATH_RESOLVE_ROOT_DIR;
    }

    while(1) {
        iter_status = fat32_iterate_dir(storage, meta,&iter, file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            fat_free_dir_iterator(&iter);
            return FAT_PATH_RESOLVE_ERROR;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            fat_free_dir_iterator(&iter);
            return FAT_PATH_RESOLVE_NOT_FOUND;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        if(remainding_path == NULL || *remainding_path==0) {
            if(strcmp((char*) file_entry->filename, filename) == 0) {
                fat_free_dir_iterator(&iter);
                return FAT_PATH_RESOLVE_FOUND;
            }
        } else {
            if(strcmp((char*) file_entry->filename, filename) == 0) {
                if(!HAS_ATTR(file_entry->direntry.attr,FAT_ATTR_DIRECTORY)) {
                    // not a dir
                    fat_free_dir_iterator(&iter);
                    return FAT_PATH_RESOLVE_INVALID_PATH;
                }
                memset(&iter, 0, sizeof(iter));
                iter.current_cluster =file_entry->direntry.cluster_lo + (file_entry->direntry.cluster_hi << 16);
                remainding_path = split_path(remainding_path, filename);
            }
        }
    }
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(global_storage, &global_fat_meta, path, &file_entry);

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
        iter.current_cluster = global_fat_meta.bootsector->root_cluster;
    }
    if(status == FAT_PATH_RESOLVE_FOUND) {
        if(!HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
            return -ENOTDIR;
        }
        iter.current_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    }

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

    while(1) {
        iter_status = fat32_iterate_dir(global_storage, &global_fat_meta, &iter,&file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            fat_free_dir_iterator(&iter);
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_DOT_ENTRY) {
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
	time_info->tm_sec = (time_entry & 0x1f) << 1;
	time_info->tm_min = (time_entry & 0x7E0) >> 5;
	time_info->tm_hour = (time_entry & 0xF800) >> 11;
	time_info->tm_mday = date_entry & 0x1F;
	time_info->tm_mon = ((date_entry & 0x1E0) >> 5) - 1;
	time_info->tm_year = ((date_entry & 0xFE00) >> 9) + 80;
	return mktime(time_info);
}

static int fs_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;

	memset(stbuf, 0, sizeof(struct stat));

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(global_storage, &global_fat_meta, path, &file_entry);

    uint32_t bytes_per_cluster = global_fat_meta.bootsector->bytes_per_sector*global_fat_meta.bootsector->sectors_per_cluster;

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        // For root dir
        stbuf->st_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
        stbuf->st_nlink = 2;
        uint32_t cluster_number = global_fat_meta.bootsector->root_cluster;
        stbuf->st_size = count_clusters(&global_fat_meta, cluster_number)*bytes_per_cluster;
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
            stbuf->st_mode = S_IRUSR | S_IRGRP | S_IROTH;
        } else {
            stbuf->st_mode = S_IRWXU | S_IRWXG | S_IRWXO;
        }
        if (HAS_ATTR(file_entry.direntry.attr, FAT_ATTR_DIRECTORY)) {
            stbuf->st_mode |= S_IFDIR;
            stbuf->st_nlink = 2;
            uint32_t cluster_number = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
            stbuf->st_size = count_clusters(&global_fat_meta, cluster_number)*bytes_per_cluster;
        } else {
            stbuf->st_mode |= S_IFREG;
            stbuf->st_nlink = 1;
            stbuf->st_size = file_entry.direntry.size;
        }
    }
	stbuf->st_mtime = convert_datetime(file_entry.direntry.mtime_date, file_entry.direntry.mtime_time);
	stbuf->st_ctime = convert_datetime(file_entry.direntry.ctime_date, file_entry.direntry.ctime_time);

    return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

    if(offset < 0) {
        return -EINVAL;
    }
    size_t unsigned_offset = offset;

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(global_storage, &global_fat_meta, path, &file_entry);

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
    uint64_t total_bytes_read = 0;
    while(1) {
        fat_cluster_status_t cluster_status = fat32_get_cluster_info(&global_fat_meta, cluster.next, &cluster);

        if(cluster_status == FAT_CLUSTER_BAD || cluster_status == FAT_CLUSTER_FREE || cluster_status == FAT_CLUSTER_RESERVED) {
            free(cluster_buffer);
            return -EIO;
        }
        assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);

        if(unsigned_offset < bytes_per_cluster) {
            uint32_t bytes_read = fat32_read_cluster(global_storage, &global_fat_meta, cluster.curr, cluster_buffer);
            if(bytes_read != bytes_per_cluster) {
                free(cluster_buffer);
                return -EIO;
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


// Change a FAT entry value, update other affected entry and the doubly linked FAT simultaneously
void fat32_modify_fat_cache(fat32_meta_t* meta, uint32_t cluster_number, uint32_t new_value)
{

    uint32_t* fat =  meta->fat;
    fat_cluster_stripped_t* linked_fat = meta->linked_fat;

    if(cluster_number < 2) {
        // for the two starting entry, set as is
        fat[cluster_number] = new_value;
        return;
    }
    uint32_t old_value = fat[cluster_number];
    fat_cluster_status_t status = fat32_interpret_fat_entry(new_value);
    // preserve the upper 4 bits
    fat[cluster_number] = (fat[cluster_number] & 0xF0000000) | (new_value & 0x0FFFFFFF);
    if(status == FAT_CLUSTER_BAD || status == FAT_CLUSTER_RESERVED || status == FAT_CLUSTER_FREE) {
        if(linked_fat[cluster_number].next != 0 && linked_fat[cluster_number].prev != 0) {
            // if was in the middle of the chain, connect prev and next
            assert(linked_fat[linked_fat[cluster_number].next].prev == cluster_number);
            assert(linked_fat[linked_fat[cluster_number].prev].next == cluster_number);
            linked_fat[linked_fat[cluster_number].next].prev = linked_fat[cluster_number].prev;
            linked_fat[linked_fat[cluster_number].prev].next = linked_fat[cluster_number].next;
        }
        else if(linked_fat[cluster_number].next != 0) {
            // if was start of the chain, set next to be start of the chain
            assert(linked_fat[linked_fat[cluster_number].next].prev == cluster_number);
            linked_fat[linked_fat[cluster_number].next].prev = 0;
        }
        else if(linked_fat[cluster_number].prev != 0) {
            // if was end of the chain, set prev to be end of the chain 
            assert(linked_fat[linked_fat[cluster_number].prev].next == cluster_number);
            fat32_modify_fat_cache(meta, linked_fat[cluster_number].prev, FAT_CLUSTER_EOC);
        }

        linked_fat[cluster_number].next = 0;
        linked_fat[cluster_number].prev = 0;

        return;
    }
    if(linked_fat[cluster_number].next != 0) {
        // set next to be start of the chain
        assert(linked_fat[linked_fat[cluster_number].next].prev == cluster_number);
        linked_fat[linked_fat[cluster_number].next].prev = 0;
        linked_fat[cluster_number].next = 0;
    }
    if(status == FAT_CLUSTER_EOC) {
        return;
    }
    assert(status == FAT_CLUSTER_USED);
    uint32_t next_cluster_number = new_value & 0x0FFFFFFF;
    // shall not point to the two starting reserved clusters
    assert(next_cluster_number > 1);
    linked_fat[cluster_number].next = next_cluster_number;
    // the next cluster must not be already pointed by others
    assert(linked_fat[next_cluster_number].prev == 0);
    linked_fat[next_cluster_number].prev = cluster_number;
    return;
}

int32_t fat32_write_fs_info(block_storage_t* storage, fat32_meta_t* meta)
{
    uint32_t sectors_to_read = 1 + (sizeof(fat32_fsinfo_t) - 1) / storage->block_size;
    uint32_t bytes_written = storage->write_blocks(storage, meta->bootsector->fs_info_sector, sectors_to_read, (uint8_t*) meta->fs_info);
    if(bytes_written != storage->block_size*sectors_to_read) {
        return -1;
    } else {
        return 0;
    }
}

int32_t fat32_write_fat(block_storage_t* storage, fat32_meta_t* meta, uint32_t* new_fat)
{
    uint32_t fat_byte_size = meta->bootsector->table_sector_size_32*meta->bootsector->bytes_per_sector;
    // Write new FAT to main FAT and backups
    uint32_t fat_idx;
    uint32_t bytes_written;
    for(fat_idx = 0; fat_idx < meta->bootsector->table_count; fat_idx++){
        bytes_written = storage->write_blocks(storage, meta->bootsector->reserved_sector_count + fat_idx*meta->bootsector->table_sector_size_32, meta->bootsector->table_sector_size_32, (uint8_t*) new_fat);
        if(bytes_written != fat_byte_size) {
            break;
        }
    }
    // If failed
    if(fat_idx != meta->bootsector->table_count) {
        // FAT corrupted!
        // Try restore back to the original FAT
        for(uint32_t fat_idx_recover = 0; fat_idx_recover <= fat_idx; fat_idx_recover++){
            bytes_written = storage->write_blocks(storage, meta->bootsector->reserved_sector_count + fat_idx_recover*meta->bootsector->table_sector_size_32, meta->bootsector->table_sector_size_32, (uint8_t*) meta->fat);
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

    uint32_t linked_fat_size = sizeof(fat_cluster_stripped_t) * fat_byte_size/sizeof(new_meta->fat[0]);
    if(new_meta->linked_fat == NULL) {
        new_meta->linked_fat = malloc(linked_fat_size);
    }
    memmove(new_meta->linked_fat, meta->linked_fat, linked_fat_size);

    if(new_meta->fs_info == NULL) {
        new_meta->fs_info = malloc(sizeof(fat32_fsinfo_t));
    }
    memmove(new_meta->fs_info, meta->fs_info, sizeof(fat32_fsinfo_t));

    if(new_meta->bootsector == NULL) {
        new_meta->bootsector = malloc(sizeof(fat32_bootsector_t));
    }
    memmove(new_meta->bootsector, meta->bootsector, sizeof(*meta->bootsector));

    return new_meta;

}

static fat32_free_meta(fat32_meta_t* meta)
{
    free(meta->bootsector);
    free(meta->fs_info);
    free(meta->fat);
    free(meta->linked_fat);
}


int32_t fat32_allocate_cluster(block_storage_t* storage, fat32_meta_t* meta, uint32_t prev_cluster_number, uint32_t cluster_count_to_allocate)
{
    uint32_t cluster_number = meta->fs_info->next_free_cluster;
    if(cluster_number == 0xFFFFFFFF) {
        cluster_number = 2;
    }
    uint32_t cluster_number_first_tried = cluster_number;
    uint32_t max_cluster_number = meta->bootsector->total_sectors_32 / meta->bootsector->sectors_per_cluster - 1;
    int32_t allocated = 0;
    
    fat32_meta_t new_meta = {0};
    fat32_copy_meta(&new_meta, meta);
    
    while(allocated < cluster_count_to_allocate) {
        fat_cluster_status_t status = fat32_interpret_fat_entry(meta->fat[cluster_number]);
        if(status == FAT_CLUSTER_FREE) {
            if(prev_cluster_number != 0) {
                fat32_modify_fat_cache(&new_meta, prev_cluster_number, cluster_number);
            }
            fat32_modify_fat_cache(&new_meta, cluster_number, FAT_CLUSTER_EOC);
            allocated++;
        }
        if(cluster_number == max_cluster_number) {
            cluster_number = 2;
        } else {
            cluster_number++;
        }
        if(cluster_number == cluster_number_first_tried && allocated < cluster_count_to_allocate) {
            // all entry tested, no free entry, disk is full
            return -ENOSPC;
        }
    }

    int32_t res = fat32_write_fat(storage, meta, new_meta.fat);
    if(res == 0) {
        // Update memory cache
        // Update memory cache
        fat32_copy_meta(meta, &new_meta);
        fat32_free_meta(&new_meta);

        // FS info is for information only, so even if the I/O failed, we still return success status
        // And the cached fs_info will always be the latest version, even though it may be written to disk successfully
        meta->fs_info->free_cluster_count -= allocated;
        meta->fs_info->next_free_cluster = cluster_number; // not necessary a free cluster, but a good place to start looking for one
        res = fat32_write_fs_info(storage, meta);

        return allocated;
    } else {
        fat32_free_meta(&new_meta);
        return -EIO;
    }
}


// Return how many clusters had been freed
// cluster_count_to_free = 0 means free to the end of the chain
static int32_t fat32_free_cluster(block_storage_t* storage, fat32_meta_t* meta, uint32_t cluster_number, uint32_t cluster_count_to_free)
{
    fat_cluster_t cluster;
    cluster.curr = cluster_number;
    fat_cluster_status_t status = fat32_get_cluster_info(meta, cluster.curr, &cluster);
    if(!(status == FAT_CLUSTER_USED || status == FAT_CLUSTER_EOC)) {
        return -EIO;
    }

    fat32_meta_t new_meta = {0};
    fat32_copy_meta(&new_meta, meta);

    fat32_modify_fat_cache(&new_meta, cluster.curr, FAT_CLUSTER_FREE);
    int32_t cluster_freed = 1;
    while(cluster.next && (cluster_freed <= cluster_count_to_free || cluster_count_to_free == 0)) {
        status = fat32_get_cluster_info(meta, cluster.next, &cluster);
        // set as free cluster
        fat32_modify_fat_cache(&new_meta, cluster.curr, FAT_CLUSTER_FREE);
        cluster_freed++;
    }
    assert(status == FAT_CLUSTER_EOC);

    int32_t res = fat32_write_fat(storage, meta, new_meta.fat);
    if(res == 0) {
        // Update memory cache
        fat32_copy_meta(meta, &new_meta);
        fat32_free_meta(&new_meta);

        // FS info is for information only, so even if the I/O failed, we still return success status
        // And the cached fs_info will always be the latest version, even though it may be written to disk successfully
        meta->fs_info->free_cluster_count += cluster_freed;
        res = fat32_write_fs_info(storage, meta);

        return cluster_freed;
    } else {
        fat32_free_meta(&new_meta);
        return -EIO;
    }

}

// Free non-used clusters for a directory
static int32_t fat32_trim_directory(block_storage_t* storage, fat32_meta_t* meta, uint32_t start_cluster_number, uint32_t end_cluster_number)
{
    fat_cluster_t cluster;
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, start_cluster_number, &cluster);

    if(cluster.prev == 0 && start_cluster_number == end_cluster_number) {
        // do no trim if only first cluster is affected
        return 0;
    }
    if(cluster.prev == 0) {
        // start trimming from at least the second cluster
        cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
    }

    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;
    fat32_direntry_t* dir =  malloc(cluster_byte_size);
    uint32_t max_dir_entry_count = cluster_byte_size / sizeof(fat32_direntry_t);
    
    int32_t freed = 0; 
    while(1) {
        uint32_t bytes_read = fat32_read_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
        if(bytes_read != cluster_byte_size) {
            free(dir);
            return -1;
        }
        // Check if all entries are unused
        uint32_t idx;
        for(idx = 0; idx <= max_dir_entry_count; idx++) {
            if(dir[idx].short_entry.name[0] != 0xE5 && dir[idx].short_entry.name[0] != 0) {
                // If an entry is used
                break;
            }
        }

        if(idx == max_dir_entry_count) {
            // all entries are unused
            int32_t res = fat32_free_cluster(storage, meta, cluster.curr, 1);
            if(res < 0) {
                free(dir);
                return -1;
            }
            freed++;
        }

        if(cluster.curr == end_cluster_number) {
            free(dir);
            return freed;
        }
        assert(cluster.next != 0);
        cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
    }


}

static int32_t fat32_add_file_entry(block_storage_t* storage, fat32_meta_t* meta, fat32_file_entry_t* file_entry, fat_dir_iterator_t* iter)
{
    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;
    uint32_t max_dir_entry_idx = cluster_byte_size / sizeof(fat32_direntry_t) - 1;

    fat32_file_entry_t candidate_entry;
    // filename are US-ASCII characters, each will take a USC-2 char space in LFN
    uint32_t lfn_entry_needed = strlen(file_entry->filename);
    lfn_entry_needed = lfn_entry_needed == 0? 0: (lfn_entry_needed - 1)/FAT32_USC2_FILE_NAME_LEN_PER_LFN + 1;
    uint32_t dir_entry_needed = lfn_entry_needed + 1;

    while(1) {
        fat_iterate_dir_status_t iter_status = fat32_iterate_dir(storage, meta, iter, &candidate_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_VALID_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_DELETED) {
            if(candidate_entry.dir_entry_count >= dir_entry_needed) {
                break;
            }
        }
        if(iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            break;
        }
        assert(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY);
        int32_t allocated = fat32_allocate_cluster(storage, meta, iter->current_cluster, 1);
        if(allocated != 1) {
            return -EIO;
        }
    }

    fat32_direntry_t* dir =  malloc(cluster_byte_size);
    fat_cluster_t cluster;
    cluster.curr = candidate_entry.dir_entry_cluster_start;
    uint32_t idx, idx_start, dir_entry_added = 0;
    uint32_t bytes_read;

    while(1) {
        uint32_t bytes_read = fat32_read_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
        if(bytes_read != cluster_byte_size) {
            free(dir);
            return -EIO;
        }
        if(cluster.curr == candidate_entry.dir_entry_cluster_start) {
            idx_start = candidate_entry.dir_entry_idx_start;
        } else {
            idx_start = 0;
        }
        for(idx = idx_start; idx <= max_dir_entry_idx; idx++) {
            if(dir_entry_added == file_entry->dir_entry_count) {
                break;
            }
            // Set dir entry as deleted
            dir[idx].short_entry.name[0] = 0xE5;
            dir_entry_freed++;
        }
        uint32_t bytes_written = fat32_write_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
        if(bytes_written != cluster_byte_size) {
            free(dir);
            return -EIO;
        }
        if(dir_entry_freed == file_entry->dir_entry_count) {
            break;
        } else {
            assert(cluster.next != 0);
            cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
            assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);
        }
    }

    free(dir);

}

static int32_t fat32_rm_file_entry(block_storage_t* storage, fat32_meta_t* meta, fat32_file_entry_t* file_entry)
{

    uint32_t cluster_byte_size = meta->bootsector->bytes_per_sector*meta->bootsector->sectors_per_cluster;
    fat32_direntry_t* dir =  malloc(cluster_byte_size);
    uint32_t max_dir_entry_idx = cluster_byte_size / sizeof(fat32_direntry_t) - 1;

    fat_cluster_t cluster;
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, file_entry->dir_entry_cluster_start, &cluster);
    uint32_t idx, idx_start;
    int32_t dir_entry_freed = 0;
    while(1) {
        uint32_t bytes_read = fat32_read_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
        if(bytes_read != cluster_byte_size) {
            free(dir);
            return -EIO;
        }
        if(cluster.curr == file_entry->dir_entry_cluster_start) {
            idx_start = file_entry->dir_entry_idx_start;
        } else {
            idx_start = 0;
        }
        for(idx = idx_start; idx <= max_dir_entry_idx; idx++) {
            if(dir_entry_freed == file_entry->dir_entry_count) {
                break;
            }
            // Set dir entry as deleted
            dir[idx].short_entry.name[0] = 0xE5;
            dir_entry_freed++;
        }
        uint32_t bytes_written = fat32_write_cluster(storage, meta, cluster.curr, (uint8_t*) dir);
        if(bytes_written != cluster_byte_size) {
            free(dir);
            return -EIO;
        }
        if(dir_entry_freed == file_entry->dir_entry_count) {
            break;
        } else {
            assert(cluster.next != 0);
            cluster_status = fat32_get_cluster_info(meta, cluster.next, &cluster);
            assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);
        }
    }

    free(dir);

    // Free data clusters
    uint32_t file_content_cluster_number = file_entry->direntry.cluster_lo + (file_entry->direntry.cluster_hi << 16);
    cluster_status = fat32_get_cluster_info(meta, file_content_cluster_number, &cluster);
    if(cluster_status == FAT_CLUSTER_EOC || FAT_CLUSTER_USED) {
        int32_t res = fat32_free_cluster(storage, meta, file_content_cluster_number, 0); // free the whole cluster chain
        if(res < 0) {
            return res;
        }
    }

    return dir_entry_freed;
}


static int fs_unlink(const char *path)
{

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(global_storage, &global_fat_meta, path, &file_entry);

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
    int32_t res_rm = fat32_rm_file_entry(global_storage, &global_fat_meta, &file_entry);

    return res_rm;
}

static int fs_rmdir(const char *path)
{
    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(global_storage, &global_fat_meta, path, &file_entry);

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

    fat_dir_iterator_t iter = {0};
    iter.current_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    fat32_file_entry_t file_in_dir = {0};

    while(1) {
        fat_iterate_dir_status_t iter_status = fat32_iterate_dir(global_storage, &global_fat_meta,&iter,&file_in_dir);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            fat_free_dir_iterator(&iter);
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY || iter_status == FAT_DIR_ITER_FREE_ENTRY) {
            // Dir is empty
            fat_free_dir_iterator(&iter);
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

    int32_t res = fat32_rm_file_entry(global_storage, &global_fat_meta, &file_entry);

    return res;
}


//Ref: https://libfuse.github.io/doxygen/structfuse__operations.html
static const struct fuse_operations fs_oper = {
	.init       = fs_init,
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
    .read       = fs_read,
    .unlink     = fs_unlink,
    .rmdir      = fs_rmdir,
};

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --image_path=<s>    Path to the file system disk image file\n"
	       "                        (default \"testfs.fat\")\n"
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
    global_storage = get_block_storage(0);

    // res = create_fs();
    // if(res < 0) {
    //     printf("Create FS failed: %d\n", res);
    //     exit(1);
    // }

    // Read header
    res = fat32_get_meta(global_storage, &global_fat_meta);
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
