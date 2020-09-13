CC=g++
BIN=scanner mystery raw

all: $(BIN)

scanner: scanner.cpp 
	$(CC) --std=c++11 -pthread scanner.cpp -o scanner

mystery: mystery.cpp 
	$(CC) --std=c++11 mystery.cpp -o mystery

raw: raw.cpp 
	$(CC) --std=c++11 raw.cpp -o raw -O3

.PHONY: clean

clean: ; rm -f $(BIN)
