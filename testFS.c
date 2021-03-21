#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#include <stdbool.h>

#include "testFS.h"

// 全局变量在这里定义
static fs_layout_t system_layout;
// 这些都是抄的hello.c
static struct options {
	const char *filename;
	const char *contents;
	int show_help;
} options;

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--name=%s", filename),
	OPTION("--contents=%s", contents),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

// Return 1: have such file; return 0: do not have such file
int find_file(fs_layout_t* system_layout, const char *path, file_entry_t** entry) {
    int arr_size = sizeof(system_layout->file) / sizeof(file_layout_t);
    for (int i = 0; i < arr_size; i++) {
        if (strcmp(system_layout->file[i].entry.path, path) == 0) {
            *entry = &system_layout->file[i].entry;
            return 1;
        }
    }
    return 0;
}

// 这里可以跟hello.c一模一样
static void *test_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static int test_open(const char *path, struct fuse_file_info *fi)
{
    printf("test_open: %s\n", path);
	file_entry_t* entry;
	// Only when the file exists,we return 0;
    int exist_file = find_file(&system_layout, path, &entry);
    if (exist_file == 0) {
		return -ENOENT;
    }
	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int test_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	file_entry_t* entry;
	int exist_file = find_file(&system_layout, path, &entry);
	if (exist_file == 0) {
		return -ENOENT;
	}
	(void) fi;
	size_t len = strlen(options.contents);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, options.contents + offset, size);
	} else
		size = 0;

	return size;
}

static int test_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res = 0;
	memset(stbuf, 0, sizeof(struct stat));

	file_entry_t* entry;
	int exist_file = find_file(&system_layout, path, &entry);
	if (exist_file == 0) {
		return -ENOENT;
	}

	if (entry->is_dir) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = entry->size;
    }

	return res;
}

static int test_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	file_entry_t* entry;
    int file_idx = find_file(&system_layout, path, &entry);
	if (file_idx == 0 || !entry->is_dir)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

	// add all files in this dictory into filler() func
	for(int i=0; i<FS_MAX_FILE_COUNT; i++) {
		if (strcmp(system_layout.file[i].entry.parent_path, path) == 0) {
			filter(buf, system_layout.file[i].entry.path, NULL, 0, 0);
		}
    }
	return 0;
}

static const struct fuse_operations test_oper = {
	.init       = test_init,
	.getattr	= test_getattr,
	.readdir	= test_readdir,
	.open		= test_open,
	.read		= test_read,
};

int main(int argc, char *argv[])
{
	// 抄的
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options.filename = strdup("hello");   // 产生一个 hello 的文件
	options.contents = strdup("Hello World!\n"); // hello 里面的东西是Hello World！

	/* Parse options */
	// 抄的
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	// 	抄的
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	ret = fuse_main(args.argc, args.argv, &test_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}