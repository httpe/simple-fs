
CFLAGS:=-g -Wall
INCLUDEDIR:=$(INCLUDEDIR) -I/usr/include/fuse3
LIBS:=$(LIBS) -lfuse3 -lpthread

OBJS=\
block_io.o \
simple_fs_block.o \

.PHONY: all clean

all: simple_fs_block

# Ref: https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html#Automatic-Variables
simple_fs_block: $(OBJS)
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
	rm -f *.d

# include make rules from *.d files, which dictate the dependency of c files on header
-include $(OBJS:.o=.d)
