CC=g++
BIN=scanner

scanner: scanner.cpp 
	$(CC) --std=c++11 -pthread scanner.cpp -o scanner
all: $(BIN)

.PHONY: clean

clean: ; rm -f $(BIN)
