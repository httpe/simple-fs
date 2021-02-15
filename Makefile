
CFLAGS:=-g -Wall -Wextra
INCLUDEDIR:=$(INCLUDEDIR) -I/usr/include/fuse3
LIBS:=$(LIBS) -lfuse3 -lpthread

SHARED_OBJS=\
block_io.o \

SIMPLE_FS_OBJS=\
simple_fs_block.o \

FAT_OBJS=\
fat.o \
fuse_fs.o \


.PHONY: all clean

all: simple_fs_block fuse_fs

# Ref: https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html#Automatic-Variables
simple_fs_block: $(SIMPLE_FS_OBJS) $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

fuse_fs: $(FAT_OBJS) $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# compile and generate dependency info (*.d) by -MD
# Ref:
# https://gcc.gnu.org/onlinedocs/gcc/Preprocessor-Options.html#Preprocessor-Options
# https://www.gnu.org/software/make/manual/html_node/Automatic-Prerequisites.html#Automatic-Prerequisites
# http://scottmcpeak.com/autodepend/autodepend.html
# http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
%.o: %.c
	$(CC) -MD -c $< -o $@ $(INCLUDEDIR) $(CFLAGS) 

clean:
	rm -f *.o
	rm -f simple_fs_block
	rm -f fuse_fs
	rm -f *.d

# include make rules from *.d files, which dictate the dependency of c files on header
-include $(OBJS:.o=.d)
