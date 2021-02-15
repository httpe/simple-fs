#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>

#include "fat.h"

#define FUSE_USE_VERSION 31
#include <fuse.h>

fs_mount_point mount_point;
struct file_system fs;

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
	const char *image_path;
    int make_fs;
    const char *make_fs_bootloader_path;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }

static const struct fuse_opt option_spec[] = {
	OPTION("--image_path=%s", image_path),
    OPTION("--make_fs", make_fs),
    OPTION("--make_fs_bootloader_path=%s", make_fs_bootloader_path),
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

struct fs_dir_filler_info {
    void* buf;
    fuse_fill_dir_t filler;
};

time_t datetime2ts(date_time dt) {
	struct tm * time_info;
	time_t raw_time;

	time(&raw_time);
	time_info = localtime(&raw_time);
	time_info->tm_sec = dt.tm_sec;
	time_info->tm_min = dt.tm_min;
	time_info->tm_hour = dt.tm_hour;
	time_info->tm_mday = dt.tm_mday;
	time_info->tm_mon = dt.tm_mon;
	time_info->tm_year = dt.tm_year;
	return mktime(time_info);
}

void fs_stat2stat(const fs_stat* fs_st, struct stat* st)
{
    // memset(st, 0, sizeof(*st));
    st->st_nlink = fs_st->nlink; 
    st->st_size=fs_st->size; 
    st->st_mtim.tv_sec = datetime2ts(fs_st->mtime); 
    st->st_ctim.tv_sec = datetime2ts(fs_st->ctime);
    st->st_blocks = fs_st->blocks;
    st->st_mode = fs_st->mode;
}

static int dir_filler(fs_dir_filler_info* info, const char *name, const struct fs_stat* fs_st)
{
    if(fs_st == NULL) {
        return info->filler(info->buf, name, NULL, 0, 0);
    } else {
        struct stat st = {0};
        fs_stat2stat(fs_st, &st);
        return info->filler(info->buf, name, &st, 0, 0);
    }
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
    (void) fi;
    (void) flags;
    (void) offset;

    struct fs_dir_filler_info filler_info = {.buf = buf, .filler = filler};
    int res = mount_point.operations.readdir(&mount_point, path, &filler_info, dir_filler);
    return res;
}

fs_file_info* fuse_fi2fs_fi(struct fuse_file_info* fi, fs_file_info* fs_fi)
{
    // memset(fs_fi, 0, sizeof(*fs_fi));
    if(fi == NULL || fs_fi == NULL) {
        return NULL;
    }
    fs_fi->fh = fi->fh;
    fs_fi->flags = fi->flags;
    return fs_fi;
}
struct fuse_file_info* fs_fi2fuse_fi(fs_file_info* fs_fi, struct fuse_file_info* fi)
{
    // memset(fi, 0, sizeof(*fi));
    if(fi == NULL || fs_fi == NULL) {
        return NULL;
    }
    fi->fh = fs_fi->fh;
    fi->flags = fs_fi->flags;
    return fi;
}

static int fs_getattr(const char *path, struct stat *st,
			 struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    fs_stat fs_st = {0};
    int res = mount_point.operations.getattr(&mount_point, path, &fs_st, fuse_fi2fs_fi(fi, &fs_fi));
    fs_stat2stat(&fs_st, st);
    fs_fi2fuse_fi(&fs_fi, fi);
    return res;
}


static int fs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    int res = mount_point.operations.read(&mount_point, path, buf, size, offset, fuse_fi2fs_fi(fi, &fs_fi));
    fs_fi2fuse_fi(&fs_fi, fi);
    return res;
}


static int fs_mknod(const char *path, mode_t mode, dev_t rdev)
{
    (void) rdev;

    if(!S_ISREG(mode)) {
        // Only support creating regular file
        return -EPERM;
    }

    int res = mount_point.operations.mknod(&mount_point, path, mode);
    return res;
}

static int fs_mkdir(const char *path, mode_t mode)
{
    int res = mount_point.operations.mkdir(&mount_point, path, mode);
    return res;
}

static int fs_unlink(const char *path)
{
    int res = mount_point.operations.unlink(&mount_point, path);
    return res;
}

static int fs_rmdir(const char *path)
{
    int res = mount_point.operations.rmdir(&mount_point, path);
    return res;
}

static int fs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    int res = mount_point.operations.write(&mount_point, path, buf, size, offset, fuse_fi2fs_fi(fi, &fs_fi));
    fs_fi2fuse_fi(&fs_fi, fi);
    return res;
}


static int fs_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    int res = mount_point.operations.truncate(&mount_point, path, size, fuse_fi2fs_fi(fi, &fs_fi));
    fs_fi2fuse_fi(&fs_fi, fi);
    return res;
}

static int fs_rename(const char *from, const char *to, unsigned int flags)
{
    int res = mount_point.operations.rename(&mount_point, from, to, flags);
    return res;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    int res = mount_point.operations.open(&mount_point, path, fuse_fi2fs_fi(fi, &fs_fi));
    fs_fi2fuse_fi(&fs_fi, fi);
    return res;
}

static int fs_release(const char *path, struct fuse_file_info *fi)
{
    fs_file_info fs_fi = {0};
    int res = mount_point.operations.release(&mount_point, path, fuse_fi2fs_fi(fi, &fs_fi));
    fs_fi2fuse_fi(&fs_fi, fi);
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
	       "    --image_path=<s>                Path to the file system disk image file\n"
	       "                                    (default \"fs_image.bin\")\n"
	       "    --make_fs                       Format the disk image\n"
	       "    --make_fs_bootloader_path=<s>   Path to a bootloader, will be prepended before the formated partition\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.image_path = strdup("fs_image.bin");
    options.make_fs_bootloader_path = strdup("");

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

    int res = initialize_block_storage(options.image_path);
    if(res < 0) {
        printf("Disk image failed to initialize: %d\n", res);
        exit(1);
    }

    // Assume to use first block storage
    block_storage_t* storage = get_block_storage(0);

    if(options.make_fs) {
        printf("Formatting file system...\n");
        int32_t res = fat32_make_fs(storage, options.make_fs_bootloader_path);
        if(res < 0) {
            printf("Failed to format the file system: %d\n", res);
            exit(1);
        }
    }

    fs = (struct file_system) {.type = FILE_SYSTEM_FAT_32};
    res = fat32_init(&fs);
    if(res < 0) {
        printf("Fail to initialize the file system\n");
        exit(1);
    }

    fs_mount_option mount_option = {0};
    mount_point = (fs_mount_point) {
        .fs = &fs,
        .storage = storage,
        .mount_target=args.argv[args.argc-1], 
        .mount_option=mount_option, 
        .fs_option = NULL
    };
    res = fs.mount(&mount_point);
    if(res < 0) {
        printf("Fail to mount the file system, maybe the storage is not correctly formated?\n");
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
    //TODO: Free global structures
	return ret;
}
