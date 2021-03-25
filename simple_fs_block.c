// FUSE driver for a very simple file system on a single file

// Source: https://github.com/libfuse/libfuse/blob/master/example/passthrough.c
// Source: https://github.com/libfuse/libfuse/blob/master/example/hello.c

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define FUSE_USE_VERSION 31
#include <fuse.h>

#include "block_io.h"
#include "simple_fs.h"


// Global memory cache of the header (metadata) of our filesystem
static fs_header header;
// Storage object for block I/O
static block_storage* storage;

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

static uint32_t block_read_bytes(void* buff, uint32_t size, off_t offset) {
    uint32_t lba_begin = offset / storage->block_size;
    if(offset + size == 0) {
        return 0;
    }
    uint32_t lba_end = (offset + size - 1) / storage->block_size;
    uint32_t block_count = lba_end - lba_begin + 1;
    uint32_t block_buff_size = block_count*storage->block_size;
    void* block_buff = malloc(block_buff_size);
    memset(block_buff, 0, block_buff_size);
    uint32_t read_in = storage->read_blocks(storage, block_buff, lba_begin, block_count);

    if(read_in < block_buff_size) {
        return 0;
    } else {
        memmove(buff, block_buff + offset % storage->block_size, size);
        return size;
    }
}


static uint32_t block_write_bytes(const void* buff, uint32_t size, off_t offset) {
    uint32_t lba_begin = offset / storage->block_size;
    if(offset + size == 0) {
        return 0;
    }
    uint32_t lba_end = (offset + size - 1) / storage->block_size;
    uint32_t block_count = lba_end - lba_begin + 1;
    uint32_t block_buff_size = block_count*storage->block_size;
    const void* block_buff;
    if(offset % storage->block_size == 0 && size %storage->block_size == 0) {
        block_buff = buff;
    } else {
        void* block_buff_alloc = malloc(block_buff_size);
        memset(block_buff_alloc, 0, block_buff_size);
        uint32_t read_in = storage->read_blocks(storage, block_buff_alloc, lba_begin, block_count);
        if(read_in < block_buff_size) {
            return 0;
        }
        memmove(block_buff_alloc + offset % storage->block_size, buff, size);
        block_buff = block_buff_alloc;
    }
    uint32_t write_out = storage->write_blocks(storage, lba_begin, block_count, block_buff);
    if(write_out < block_buff_size) {
        return 0;
    } else {
        return size;
    }
}

static int write_header() {
    int written = block_write_bytes(&header, sizeof(header), 0);
    if(written != sizeof(header))
        return -1;
    return 0;
}


static int match_path(fs_header* header, const char* path, file_entry** entry) {
    for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
        if(strcmp(header->file_table[i].path, path) == 0) {
            *entry = &header->file_table[i];
            return i;
        }
    }
    return -1;
}

static int fs_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;

	memset(stbuf, 0, sizeof(struct stat));
    
    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

    if(file_idx < 0) {
        return -ENOENT;
    }

	if (entry->attr.is_dir) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = entry->size;
    }

    return 0;
}

// Get file name for a path under dir
static const char* get_filename(const char* dir, const char* path)
{
    size_t lendir = strlen(dir),
           lenpath = strlen(path);

    if(lendir >= lenpath) {
        return NULL;
    }

    if(memcmp(dir, path, lendir) != 0) {
        return NULL;
    }

    int offset = 1;
    if(dir[lendir-1]=='/') {
        offset = 0;
    }

    for(size_t i=lendir + offset; i<lenpath; i++) {
        // filter out files in sub-folders
        // offset: for case dir="/d", path="/d/a", skip the second '/'
        if(path[i] == '/') {
            return NULL;
        }
    }

    return &path[lendir+offset];
}


static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);
	if (file_idx < 0 || !entry->attr.is_dir)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

    for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
        const char* filename = get_filename(path, header.file_table[i].path);
        if(filename != NULL) {
            filler(buf, filename, NULL, 0, 0);
        }
    }

	return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
    (void) fi;

    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

	if (file_idx < 0)
		return -ENOENT;

    if(entry->attr.is_dir) {
        // Not allow to "open" a directory entry
        return -EPERM;
    }

    // Do nothing

	return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

	if (file_idx < 0)
		return -ENOENT;

    if(entry->attr.is_dir) {
        // Not allow to read content to a directory entry
        return -EPERM;
    }

    if(offset >= FS_DATA_BLOCK_LEN) {
        return 0;
    }

    if(offset + size > FS_DATA_BLOCK_LEN) {
        size = FS_DATA_BLOCK_LEN - offset;
    }

    int file_offset = sizeof(fs_header) + FS_DATA_BLOCK_LEN*file_idx;
    int read_in = block_read_bytes(buf, size, file_offset + offset);

	return read_in;

}

static int fs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    (void) fi;
    
    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

	if (file_idx < 0)
		return -ENOENT;

    if(entry->attr.is_dir) {
        // Not allow to write content to a directory entry
        return -EPERM;
    }

    if(offset + size > FS_DATA_BLOCK_LEN) {
        return -ENOSPC;
    }

    int file_offset = sizeof(fs_header) + FS_DATA_BLOCK_LEN*file_idx;
    uint32_t written = block_write_bytes(buf, size, file_offset + offset);
    if(written != size) {
        return 0;
    }

    if(offset + size > entry->size) {
        entry->size = offset + size;
        int r = write_header();
        if(r != 0) {
            return 0;
        }
    }

	return written;
}

static int fs_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
    (void) fi;
    
    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

	if (file_idx < 0)
		return -ENOENT;

    if(entry->attr.is_dir) {
        // Not allow to write content to a directory entry
        return -EPERM;
    }

    if(size > FS_DATA_BLOCK_LEN) {
        return -ENOSPC;
    }

    if(size == entry->size) {
        // Same size, do nothing
        return 0;
    }

    char buf[FS_DATA_BLOCK_LEN];
    memset(buf, 0, FS_DATA_BLOCK_LEN);
    int file_offset = sizeof(fs_header) + FS_DATA_BLOCK_LEN*file_idx;
    if(size > entry->size) {
        int written = block_write_bytes(buf, size - entry->size, file_offset + entry->size);
        if(written != size - entry->size) {
            return -1;
        }
    }

    entry->size = size;
    int r = write_header();

	return r;
}

static int get_parent(const char* path, file_entry** parent_entry) {
    int lenpath = strlen(path);

    if(strcmp(path, "/")==0) {
        *parent_entry = &header.file_table[0];
        return 0;
    }

    int i;
    for(i=lenpath-1;i>=0;i--) {
        if(path[i]=='/') {
            break;
        }
        if(i==0) {
            // not a valid absolute path
            return -1;
        }
    }

    char parent[FS_MAX_FILENAME_LEN];
    // char name[FS_MAX_FILENAME_LEN];
    if(i>0) {
        memmove(parent, path, i);
        parent[i] = 0;
    } else {
        parent[0] = '/';
        parent[1] = 0;
    }

    // memcpy(name, &path[i+1], lenpath - i - 1);

    int parent_idx = match_path(&header, parent, parent_entry);

    return parent_idx;
}

static int fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    (void) rdev;

    if(!(S_ISREG(mode) || S_ISDIR(mode))) {
        // Only support creating regular file or directory
        return -EPERM;
    }

    size_t lenpath = strlen(path);
    if(lenpath >= FS_MAX_FILENAME_LEN) {
        // equal sign: the max len include the terminal \0
        return -EPERM;
    }

    file_entry* parent_entry;
    int parent_idx = get_parent(path, &parent_entry);
    if(parent_idx < 0) {
        return -ENOENT;
    }

    for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
        file_entry* entry = &header.file_table[i];
        if(strlen(entry->path) == 0) {
            strcpy(entry->path, path);
            entry->attr.is_dir = S_ISDIR(mode);
            int r = write_header();
            return r;
        }
    }

    return -ENOSPC;
}

static int fs_mkdir(const char *path, mode_t mode)
{
    (void) mode;

    size_t lenpath = strlen(path);
    if(lenpath >= FS_MAX_FILENAME_LEN) {
        // equal sign: the max len include the terminal \0
        return -EPERM;
    }

    file_entry* parent_entry;
    int parent_idx = get_parent(path, &parent_entry);
    if(parent_idx < 0) {
        return -ENOENT;
    }

    for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
        file_entry* entry = &header.file_table[i];
        if(strlen(entry->path) == 0) {
            strcpy(entry->path, path);
            entry->attr.is_dir = 1;
            int r = write_header();
            return r;
        }
    }

	return 0;
}

static int fs_unlink(const char *path)
{

    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

    if(file_idx < 0) {
        return -ENOENT;
    }
    if(entry->attr.is_dir) {
        // Not allow to unlink directory
        return -EPERM;
    }

    memset(entry, 0, sizeof(file_entry));
    int r = write_header();
    return r;
}

static int fs_rmdir(const char *path)
{
    file_entry* entry;
    int file_idx = match_path(&header, path, &entry);

    if(file_idx < 0) {
        return -ENOENT;
    }
    if(file_idx == 0) {
        // Not allow removing root directory
        return -EPERM;
    }

    if(!entry->attr.is_dir) {
        // Not allow to perform rmdir on file
        return -EPERM;
    }

    for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
        const char* filename = get_filename(path, header.file_table[i].path);
        if(filename != NULL) {
            // Not allow removing non empty directory
            return -EPERM;
        }
    }

    memset(entry, 0, sizeof(file_entry));
    int r = write_header();
    return r;
}


static int fs_rename(const char *from, const char *to, unsigned int flags)
{
    (void) flags;

    file_entry* entry_from;
    int from_idx = match_path(&header, from, &entry_from);

    if(from_idx < 0) {
        return -ENOENT;
    }
    if(from_idx == 0) {
        // Not allow renaming root directory
        return -EPERM;
    }

    file_entry* entry_to;
    int to_idx = match_path(&header, to, &entry_to);
    if(to_idx >= 0) {
        // New name already exist
        return -EPERM;
    }

    int lento = strlen(to);
    if(lento >= FS_MAX_FILENAME_LEN) {
        return -EPERM;
    }

    file_entry* entry_new_parent;
    int new_parent_idx = get_parent(to, &entry_new_parent);
    if(new_parent_idx < 0 || !entry_new_parent->attr.is_dir) {
        // New dir not exist or is not dir
        return -EPERM;
    }

    fs_header backup;
    memmove(&backup, &header, sizeof(header));

    strcpy(entry_from->path, to);

    char name[FS_MAX_FILENAME_LEN];
    if(entry_from->attr.is_dir) {
        int err = 0;
        for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
            const char* filename = get_filename(from, header.file_table[i].path);
            if(filename != NULL) {
                int lenfile = strlen(filename);
                if(lento + 1 + lenfile >= FS_MAX_FILENAME_LEN) {
                    // new file name too long
                    err = 1;
                    break;
                }
                strcpy(name, to);
                name[lento] = '/';
                memmove(&name[lento+1], filename, lenfile);
                name[lento + 1 + lenfile] = 0;
                strcpy(header.file_table[i].path, name);
            }
        }
        if(err) {
            // Roll back
            memmove(&header, &backup, sizeof(header));
            return -EPERM;
        }
    }

    int res = write_header();

	return res;
}

//Ref: https://libfuse.github.io/doxygen/structfuse__operations.html
static const struct fuse_operations fs_oper = {
	.init       = fs_init,
	.getattr	= fs_getattr,
	.readdir	= fs_readdir,
	.open		= fs_open,
	.read		= fs_read,
    .write      = fs_write,
    .mknod      = fs_mknod,
    .mkdir      = fs_mkdir,
    .unlink     = fs_unlink,
	.rmdir		= fs_rmdir,
    .truncate   = fs_truncate,
    .rename     = fs_rename,
};

static int create_fs()
{
    fs_layout layout;
    memset(&layout, 0, sizeof(layout));
    file_entry* root_dir = &layout.header.file_table[0];
    strcpy(root_dir->path, "/");
    root_dir->attr.is_dir = 1;
    
    int written = block_write_bytes(&layout, sizeof(layout), 0);

    if(written != sizeof(layout)) {
        return -1;
    }

    return 0;
}

static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --image_path=<s>    Path to the file system disk image file\n"
	       "                        (default \"simple_fs_image.bin\")\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.image_path = strdup("simple_fs_image.bin");

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

    // 
    int res = initialize_block_storage(options.image_path);
    if(res < 0) {
        printf("Init image failed: %d\n", res);
        exit(1);
    }

    // Assume to use first block storage
    storage = get_block_storage(0);

    res = create_fs();
    if(res < 0) {
        printf("Create FS failed: %d\n", res);
        exit(1);
    }
    
    if(storage->block_size != sizeof(header)) {
        printf("Block size mismatch\n");
        exit(1);
    }

    // Read header
    block_read_bytes(&header, sizeof(header), 0);

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