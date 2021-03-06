CC=g++
BIN=scanner mystery raw evil knock

all: $(BIN)

scanner: scanner.cpp 
	$(CC) --std=c++11 -pthread scanner.cpp -o scanner

mystery: mystery.cpp 
	$(CC) --std=c++11 mystery.cpp -o mystery

raw: raw.cpp 
	$(CC) --std=c++11 raw.cpp -o raw -O3

evil: evil.cpp
	$(CC) --std=c++11 evil.cpp -o evil -O3

knock: knock.cpp
	$(CC) --std=c++11 knock.cpp -o knock -O3

.PHONY: clean

clean: ; rm -f $(BIN)
