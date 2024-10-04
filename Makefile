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
CFLAGS = -Wall -Wextra -O2 -ggdb3 $(OPTIMIZATION) $(INCLUDE_FLAGS) $(DEFFLAGS)
CXXFLAGS = -Wall -Wextra -O2 -ggdb3 $(OPTIMIZATION) $(INCLUDE_FLAGS) $(DEFFLAGS)
LDFLAGS = -Wall -Wextra -O2 -ggdb3 $(OPTIMIZATION)
DEPFLAGS = -MT "$@" -MMD -MP -MF $(@:.o=.d)
LIBS = -lpthread -lssl -lcrypto
TARGET = proxmasterd

C_SOURCES = \
	src/proxmasterd/entry.c \
	src/proxmasterd/http.c \
	src/proxmasterd/net_tcp_ssl.c \
	src/proxmasterd/net_tcp.c

CXX_SOURCES =

OBJECTS = $(C_SOURCES:.c=.c.o) $(CXX_SOURCES:.cpp=.cpp.o)
DEPS = $(OBJECTS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

-include $(DEPS)

%.c.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

%.cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS) $(DEPS)

.PHONY: all clean
