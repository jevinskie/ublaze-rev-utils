TARGETS := bflt2elf

CXXFLAGS := -Wall -Wextra -g -std=gnu++2b

all: $(TARGETS)
.PHONY: clean

clean:
	rm -f $(TARGETS)

bflt2elf: bflt2elf.cpp
	$(CXX) -o $@ $^ $(CXXFLAGS) -I 3rdparty/elfio -I 3rdparty/byteswap/include
