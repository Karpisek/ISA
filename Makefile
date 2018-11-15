CC=g++
FLAGS=-std=c++11 -Wall -Wextra -pedantic -lpcap
PROJ_NAME=dns-export

all:
	$(CC) $(FLAGS) *cpp -o $(PROJ_NAME)

clean:
	rm $(PROJ_NAME)
