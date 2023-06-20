TARGETS = ul udl

LDFLAGS = -L /usr/local/lib
LNK_OPT = -lpbc -lgmp -lpthread
INCLUDE_COMMON = -I /usr/local/include/pbc -I ./network/

NETWORK = ./network/network.cpp
UDL = $(NETWORK) $(wildcard ./udl/*.cpp)
UL = $(NETWORK) $(wildcard ./ul/*.cpp)
obj_udl = $(patsubst %.cpp, %.o, $(UDL))
obj_ul = $(patsubst %.cpp, %.o, $(UL))
CC = g++

CFLAGS=$(CFLAG)
CFLAGS += -Wall -c

all: $(TARGETS)
ul: $(obj_ul)
	@mkdir -p output/
	$(CC) $(obj_ul) $(LDFLAGS) $(LNK_OPT) -o output/ul
udl: $(obj_udl)
	@mkdir -p output/
	$(CC) $(obj_udl) $(LDFLAGS) $(LNK_OPT) -o output/udl

%.o: %.cpp
	$(CC) $(INCLUDE_COMMON) $(CFLAGS) $< -o $@
.PHONY: clean
clean:
	rm -rf $(obj_udl) $(obj_ul) output