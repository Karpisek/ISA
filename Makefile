CC=g++
FLAGS=-std=c++11 -Wall -Wextra -pedantic -lpcap
PROJ_NAME=dns-export

all:
	$(CC) $(FLAGS) *cpp -o $(PROJ_NAME)

zip:
	zip -q xkarpi05.zip *.cpp *.h Makefile manual.pdf dns-export.1 -x "*.DS_Store"

clean:
	rm $(PROJ_NAME)
