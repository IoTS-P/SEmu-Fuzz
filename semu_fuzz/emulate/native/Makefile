# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

include ./config.mk

UNAME_S := $(shell uname -s)

LIBDIR = .
BIN_EXT = .so
AR_EXT = a

# Verbose output?
V ?= 1

CFLAGS += -shared -fpic -Wall -Werror

LDFLAGS += -shared -L$(LIBDIR) -lunicorn -lpthread -lm -DDEBUG
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt
endif

LDLIBS += -lpthread -lunicorn -lm

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang 
CXX = clang++
AR = llvm-ar
CFLAGS += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

# Cygwin?
ifneq ($(filter CYGWIN%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
LDLIBS += -lssp
BIN_EXT = .exe
AR_EXT = a
# mingw?
else ifneq ($(filter MINGW%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = a
endif

ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/unicorn.$(AR_EXT)
else ifneq ($(filter CYGWIN%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
endif
endif

.PHONY: all clean

SOURCES = nvic.c

BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

nvic.so: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

all: nvic.so

$(BINS): $(OBJS)

clean:
	rm -rf *.o $(BINS)
