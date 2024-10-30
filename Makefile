# SPDX-License-Identifier: GPL-2.0-only

# CC = gcc
# CXX = g++
# LD = g++

CC = clang
CXX = clang++
LD = clang++

OPTIMIZATION = -O2
INCLUDE_FLAGS = -I./src
DEFFLAGS = -D_GNU_SOURCE
CFLAGS = -Wall -Wextra -ggdb3 $(OPTIMIZATION) $(INCLUDE_FLAGS) $(DEFFLAGS)
CXXFLAGS = -Wall -Wextra -ggdb3 $(OPTIMIZATION) $(INCLUDE_FLAGS) $(DEFFLAGS)
LDFLAGS = -Wall -Wextra -ggdb3 $(OPTIMIZATION)
DEPFLAGS = -MT "$@" -MMD -MP -MF $(@:.o=.d)
LIBS = -lpthread -lssl -lcrypto
TARGET_PM = proxmasterd
TARGET_SS = socks52socks5

C_PM_SOURCES = \
	src/proxmasterd/http.c \
	src/proxmasterd/net_tcp_ssl.c \
	src/proxmasterd/net_tcp.c

CXX_PM_SOURCES = \
	src/proxmasterd/entry.cpp \
	src/proxmasterd/proxmaster.cpp \
	src/proxmasterd/web.cpp

PM_OBJECTS = $(C_PM_SOURCES:.c=.c.o) $(CXX_PM_SOURCES:.cpp=.cpp.o)
PM_SHARED_LIBS = \
	/lib/x86_64-linux-gnu/libssl.so.3 \
	/lib/x86_64-linux-gnu/libcrypto.so.3 \
	/lib/x86_64-linux-gnu/libstdc++.so.6 \
	/lib/x86_64-linux-gnu/libm.so.6 \
	/lib/x86_64-linux-gnu/libgcc_s.so.1 \
	/lib/x86_64-linux-gnu/libc.so.6 \
	/lib64/ld-linux-x86-64.so.2

C_SS_SOURCES = \
	speedmgr/speedmgr.c

CXX_SS_SOURCES = \
	speedmgr/ht.cpp

SS_OBJECTS = $(C_SS_SOURCES:.c=.c.o) $(CXX_SS_SOURCES:.cpp=.cpp.o)
SS_SHARED_LIBS = \
	/lib/x86_64-linux-gnu/libssl.so.3 \
	/lib/x86_64-linux-gnu/libcrypto.so.3 \
	/lib/x86_64-linux-gnu/libstdc++.so.6 \
	/lib/x86_64-linux-gnu/libm.so.6 \
	/lib/x86_64-linux-gnu/libgcc_s.so.1 \
	/lib/x86_64-linux-gnu/libc.so.6 \
	/lib64/ld-linux-x86-64.so.2

DEPS = $(OBJECTS:.o=.d)

all: $(TARGET_PM) $(TARGET_SS)

$(TARGET_PM): $(PM_OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

$(TARGET_SS): $(SS_OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

-include $(DEPS)

%.c.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

%.cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<

clean:
	rm -rf $(TARGET_PM) $(TARGET_SS) $(PM_OBJECTS) $(SS_OBJECTS) $(DEPS) bin

pack: $(TARGET_PM) $(TARGET_SS)
	mkdir -pv bin
	cp -v $(TARGET_PM) bin/
	cp -v $(TARGET_SS) bin/
	cp -vf $(PM_SHARED_LIBS) bin/
	cp -vf $(SS_SHARED_LIBS) bin/
	chmod -vR 755 bin

.PHONY: all clean pack
