#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>

#include "fat.h"
#include "block_io.h"

#define FUSE_USE_VERSION 31
#include <fuse.h>

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
    meta->fat = malloc(meta->bootsector->table_sector_size_32 * meta->bootsector->bytes_per_sector);
    bytes_read = storage->read_blocks(storage, (uint8_t*) meta->fat, meta->bootsector->reserved_sector_count, meta->bootsector->table_sector_size_32);
    if(bytes_read != meta->bootsector->table_sector_size_32 *meta->bootsector->bytes_per_sector) {
        return -1;
    }
    good = good & ((meta->fat[0] & 0x0FFFFFFF) >= 0x0FFFFFF0) & ((meta->fat[0] & 0x0FFFFFFF) <= 0x0FFFFFFF); // check cluster 0 (FAT ID)
    good = good & ((meta->fat[1] & 0x0FFFFFFF) == 0x0FFFFFFF); // check cluster 1 (End of Cluster Mark)
    if(!good){
        return -1;
    }

    return 0;
}

fat_cluster_status_t fat32_get_cluster_info(fat32_meta_t* meta, uint32_t cluster_number, uint32_t* next_cluster)
{
    // Return next_cluster as zero by default
    *next_cluster = 0;
    // First&second cluster are reserved for FAT ID and End of Cluster Mark 
    if(cluster_number <= 1) {
        return FAT_CLUSTER_RESERVED;
    }
    uint32_t entry = meta->fat[cluster_number] & 0x0FFFFFFF;
    // Cluster value ref: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#Cluster_values
    if(entry == 0x00000000) {
        return FAT_CLUSTER_FREE;
    }
    if(entry >= 0x00000002 && entry <= 0x0FFFFFEF) {
        *next_cluster = entry;
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

uint32_t fat32_read_cluster(block_storage_t* storage, fat32_meta_t* meta, uint32_t cluster_number, uint8_t* buff)
{
    assert(cluster_number >= 2);
    uint32_t sectors_to_read = meta->bootsector->sectors_per_cluster;
    // the cluster 0 and 1 are not of size sectors_per_cluster
    uint32_t lba = meta->bootsector->reserved_sector_count + meta->bootsector->table_sector_size_32*meta->bootsector->table_count + (cluster_number-2)*meta->bootsector->sectors_per_cluster;
    uint32_t bytes_read_in = storage->read_blocks(storage, buff, lba, sectors_to_read);
    return bytes_read_in;
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
    uint32_t max_dir_entry_idx = cluster_size / sizeof(fat32_direntry_t) - 1;
    uint32_t next_cluster = 0;
    fat_cluster_status_t cluster_status = fat32_get_cluster_info(meta, iter->current_cluster, &next_cluster);
    if(iter->dir_entries == NULL) {
        iter->dir_entries = malloc(cluster_size);
        if(!(cluster_status == FAT_CLUSTER_EOC || cluster_status == FAT_CLUSTER_USED)) {
            return FAT_DIR_ITER_ERROR;
        }
        uint32_t bytes_read = fat32_read_cluster(storage, meta, iter->current_cluster, (uint8_t*) iter->dir_entries);
        if(bytes_read != cluster_size) {
            return FAT_DIR_ITER_ERROR;
        }
        iter->current_dir_entry_idx = 0;
        iter->lfn_entry_buffered = 0;
    }
    if(cluster_status != FAT_CLUSTER_USED && iter->current_dir_entry_idx >= max_dir_entry_idx) {
        return FAT_DIR_ITER_NO_MORE_ENTRY;
    }
    if(iter->current_dir_entry_idx >= max_dir_entry_idx) {
        uint32_t next_next_cluster = 0;
        fat_cluster_status_t next_cluster_status = fat32_get_cluster_info(meta, next_cluster, &next_next_cluster);
        if(!(next_cluster_status == FAT_CLUSTER_EOC || next_cluster_status == FAT_CLUSTER_USED)) {
            return FAT_DIR_ITER_ERROR;
        }
        uint32_t bytes_read = fat32_read_cluster(storage, meta, next_cluster, (uint8_t*) iter->dir_entries);
        if(bytes_read != cluster_size) {
            return FAT_DIR_ITER_ERROR;
        }
        iter->current_dir_entry_idx = 0;
        iter->lfn_entry_buffered = 0;
        iter->current_cluster = next_cluster;
    }

    fat32_direntry_t* entry = &iter->dir_entries[iter->current_dir_entry_idx];
    // Algo Ref: https://wiki.osdev.org/FAT#Reading_Directories
    if(entry->short_entry.nameext[0] == 0) {
        // 1. If the first byte of the entry is equal to 0 then there are no more files/directories in this directory. FirstByte==0, finish.
        iter->current_dir_entry_idx++;
        return FAT_DIR_ITER_NO_MORE_ENTRY;
    }
    if(entry->short_entry.nameext[0] == 0x0F) {
        // 2. If the first byte of the entry is equal to 0xE5 then the entry is unused. FirstByte==0xE5, goto 8
        iter->current_dir_entry_idx++;
        return FAT_DIR_ITER_UNUSED_ENTRY;
    }
    if(entry->short_entry.nameext[0] == 0x2E) {
        // 2. If the first byte of the entry is equal to 0xE5 then the entry is unused. FirstByte==0xE5, goto 8
        iter->current_dir_entry_idx++;
        return FAT_DIR_DOT_ENTRY;
    }
    if(entry->short_entry.nameext[0] == 0xE5) {
        // 2. If the first byte of the entry is equal to 0xE5 then the entry is unused. FirstByte==0xE5, goto 8
        iter->current_dir_entry_idx++;
        return FAT_DIR_ITER_DELETED;
    }
    if(entry->short_entry.attr == 0x0F){
        // 3. Is this entry a long file name entry? If the 11'th byte of the entry equals 0x0F, then it is a long file name entry. Otherwise, it is not.
        // 4. Read the portion of the long filename into a temporary buffer. Goto 8.
        if((entry->long_entry.seq & 0x40) == 0x40) {
            // first LFN entry
            
            // if some entries are already buffered, they will be overritten
            iter->lfn_checksum = entry->long_entry.csum;
            memset(file_entry->filename, 0, sizeof(file_entry->filename));
            void* end_of_filename = ((void*) file_entry->filename) + sizeof(file_entry->filename);
            memmove(end_of_filename-=sizeof(entry->long_entry.name3), entry->long_entry.name3, sizeof(entry->long_entry.name3));
            memmove(end_of_filename-=sizeof(entry->long_entry.name2), entry->long_entry.name2, sizeof(entry->long_entry.name2));
            memmove(end_of_filename-=sizeof(entry->long_entry.name1), entry->long_entry.name1, sizeof(entry->long_entry.name1));
            iter->lfn_entry_buffered = 1;
            iter->current_dir_entry_idx++;
            return fat32_iterate_dir(storage, meta, iter, file_entry);
		} else if(iter->lfn_checksum != entry->long_entry.csum) {
            // discard LFN if checksum doesn't match the last checksum
            iter->lfn_entry_buffered = 0;
            iter->lfn_checksum = 0;
            memset(file_entry->filename, 0, sizeof(file_entry->filename));
            iter->current_dir_entry_idx++;
            return fat32_iterate_dir(storage, meta, iter, file_entry);
        } else {
            // not first LFN and checksum is consistent
            void* offset = ((void*) file_entry->filename) + sizeof(file_entry->filename) - FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*(iter->lfn_entry_buffered);
            memmove(offset-=sizeof(entry->long_entry.name3), entry->long_entry.name3, sizeof(entry->long_entry.name3));
            memmove(offset-=sizeof(entry->long_entry.name2), entry->long_entry.name2, sizeof(entry->long_entry.name2));
            memmove(offset-=sizeof(entry->long_entry.name1), entry->long_entry.name1, sizeof(entry->long_entry.name1));
            iter->lfn_entry_buffered++;
            iter->current_dir_entry_idx++;
            return fat32_iterate_dir(storage, meta, iter, file_entry);
        }
    } else {
        // 5. Parse the data for this entry using the table from further up on this page. It would be a good idea to save the data for later. Possibly in a virtual file system structure. goto 6
        file_entry->direntry = iter->dir_entries[iter->current_dir_entry_idx].short_entry;
        // 6. Is there a long file name in the temporary buffer? Yes, goto 7. No, goto 8
        // 7. Apply the long file name to the entry that you just read and clear the temporary buffer. goto 8
        if(iter->lfn_entry_buffered > 0 && iter->lfn_checksum == lfn_checksum(file_entry->direntry.nameext)) {
            // We do not support USC-2 UNICODE character, any non US-ASCII character will be replaced by '?'
            // since '?' itself is not allowed in normal FAT file name
            uint32_t lfn_name_byte_len =  FAT32_USC2_FILE_NAME_LEN_PER_LFN*2*iter->lfn_entry_buffered;
            uint8_t* start_of_filename = &file_entry->filename[sizeof(file_entry->filename)] - lfn_name_byte_len;
            for(uint32_t i=0; i<lfn_name_byte_len/2; i++) {
                uint8_t usc2_first = start_of_filename[i*2];
                uint8_t usc2_second = start_of_filename[i*2+1];
                if(usc2_first > 127 || usc2_second != 0) {
                    // if not US-ASCII
                    file_entry->filename[i] = '?';
                } else {
                    file_entry->filename[i] = usc2_first;
                }
            }
            file_entry->filename[lfn_name_byte_len] = 0;
            trim_space((char*)file_entry->filename);
        } else {
            // if not LFN buffered, use the 8.3 short name
            memmove(file_entry->filename, file_entry->direntry.name, sizeof( file_entry->direntry.name));
            file_entry->filename[sizeof(file_entry->direntry.name)] = 0;
            trim_space((char*)file_entry->filename);
            uint32_t name_len = strlen((char*)file_entry->filename);
            file_entry->filename[name_len] = '.';
            memmove(&file_entry->filename[name_len+1],  file_entry->direntry.ext, sizeof(file_entry->direntry.ext));
            file_entry->filename[name_len+1+sizeof(file_entry->direntry.ext)] = 0;
            trim_space((char*)file_entry->filename);
            if(strlen((char*)file_entry->filename)==name_len+1){
                file_entry->filename[name_len] = 0;
            }
        }
        // 8. Increment pointers and/or counters and check the next entry. (goto number 1)
        iter->current_dir_entry_idx++;
        return FAT_DIR_ITER_VALID_ENTRY;
    }
}

static fat_resolve_path_status_t fat32_resolve_path(const char *path, fat32_file_entry_t* file_entry)
{

    char filename[FAT32_FILENAME_SIZE] = {0};
    char* remainding_path = split_path((char*) path, filename);

    fat_dir_iterator_t iter = {0};
    iter.current_cluster = global_fat_meta.bootsector->root_cluster;
    fat_iterate_dir_status_t iter_status; 

    if(strlen(path) == 0) {
        return FAT_PATH_RESOLVE_INVALID_PATH;
    }
    if(remainding_path == NULL) {
        return FAT_PATH_RESOLVE_ROOT_DIR;
    }

    while(1) {
        iter_status = fat32_iterate_dir(global_storage, &global_fat_meta,&iter, file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            return FAT_PATH_RESOLVE_ERROR;
        }
        if(iter_status == FAT_DIR_ITER_UNUSED_ENTRY || iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY) {
            return FAT_PATH_RESOLVE_NOT_FOUND;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        if(remainding_path == NULL || *remainding_path==0) {
            if(strcmp((char*) file_entry->filename, filename) == 0) {
                return FAT_PATH_RESOLVE_FOUND;
            }
        } else {
            if(strcmp((char*) file_entry->filename, filename) == 0) {
                if((file_entry->direntry.attr & FAT_ATTR_DIRECTORY) != FAT_ATTR_DIRECTORY) {
                    // not a dir
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
    fat_resolve_path_status_t status = fat32_resolve_path(path, &file_entry);

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
        if((file_entry.direntry.attr & FAT_ATTR_DIRECTORY) != FAT_ATTR_DIRECTORY) {
            return -ENOTDIR;
        }
        iter.current_cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    }

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

    while(1) {
        iter_status = fat32_iterate_dir(global_storage, &global_fat_meta,&iter,&file_entry);
        if(iter_status == FAT_DIR_ITER_ERROR) {
            // Any error will discard all info we got
            return -EIO;
        }
        if(iter_status == FAT_DIR_ITER_UNUSED_ENTRY || iter_status == FAT_DIR_ITER_DELETED || iter_status == FAT_DIR_DOT_ENTRY) {
            continue;
        }
        if(iter_status == FAT_DIR_ITER_NO_MORE_ENTRY) {
            return 0;
        }
        assert(iter_status == FAT_DIR_ITER_VALID_ENTRY);
        if((file_entry.direntry.attr & FAT_ATTR_VOLUME_ID) == FAT_ATTR_VOLUME_ID) {
            // Skip Volume label entry when listing directory
            continue;
        }
        filler(buf, (char*) file_entry.filename, NULL, 0, 0);
    }
}

static int fs_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;

	memset(stbuf, 0, sizeof(struct stat));

    fat32_file_entry_t file_entry = {0};
    fat_resolve_path_status_t status = fat32_resolve_path(path, &file_entry);

    if(status == FAT_PATH_RESOLVE_ROOT_DIR) {
        // For root dir
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
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
        if ((file_entry.direntry.attr & FAT_ATTR_DIRECTORY) == FAT_ATTR_DIRECTORY) {
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
        } else {
            stbuf->st_mode = S_IFREG | 0444;
            stbuf->st_nlink = 1;
            stbuf->st_size = file_entry.direntry.size;
        }
    }

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
    fat_resolve_path_status_t status = fat32_resolve_path(path, &file_entry);

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

    if((file_entry.direntry.attr & FAT_ATTR_DIRECTORY) == FAT_ATTR_DIRECTORY) {
        return -EISDIR;
    }

    if(offset >= file_entry.direntry.size) {
        return 0;
    }

    if(offset + size > file_entry.direntry.size) {
        size = file_entry.direntry.size - offset;
    }

    uint32_t cluster = file_entry.direntry.cluster_lo + (file_entry.direntry.cluster_hi << 16);
    uint32_t next_cluster = 0;
    uint32_t bytes_per_cluster = global_fat_meta.
    bootsector->sectors_per_cluster*global_fat_meta.bootsector->bytes_per_sector;
    uint32_t bytes_read = 0;
    uint8_t* cluster_buffer = malloc(bytes_per_cluster);
    uint32_t size_in_this_cluster;
    uint64_t total_bytes_read = 0;
    while(1) {
        fat_cluster_status_t cluster_status = fat32_get_cluster_info(&global_fat_meta, cluster, &next_cluster);

        if(cluster_status == FAT_CLUSTER_BAD || cluster_status == FAT_CLUSTER_FREE || cluster_status == FAT_CLUSTER_RESERVED) {
            free(cluster_buffer);
            return -EIO;
        }
        assert(cluster_status == FAT_CLUSTER_USED || cluster_status == FAT_CLUSTER_EOC);

        if(unsigned_offset < bytes_per_cluster) {
            bytes_read = fat32_read_cluster(global_storage, &global_fat_meta, cluster, cluster_buffer);
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

        if(cluster_status == FAT_CLUSTER_EOC || size == 0) {
            free(cluster_buffer);
            return total_bytes_read;
        } else {
            cluster = next_cluster;
        }
    }
}

//Ref: https://libfuse.github.io/doxygen/structfuse__operations.html
static const struct fuse_operations fs_oper = {
	.init       = fs_init,
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
    .read       = fs_read,
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
	options.image_path = strdup("testfs.fat");

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
