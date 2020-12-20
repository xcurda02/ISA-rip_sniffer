FLAGS = -std=c++11 -pedantic -Wall -Wextra
EXEC = myripsniffer myripresponse myriprequest
SRC = myripsniffer.cpp myripresponse.cpp myriprequest.cpp rip_defs.h

all: $(EXEC)

myripsniffer: myripsniffer.cpp rip_defs.h
	g++ $(FLAGS) -o myripsniffer myripsniffer.cpp -lpcap

myripresponse: myripresponse.cpp rip_defs.h
	g++ $(FLAGS) -o myripresponse myripresponse.cpp

myriprequest: myriprequest.cpp rip_defs.h
	g++ $(FLAGS) -o myriprequest myriprequest.cpp

clean:
	rm -rf $(EXEC) *.o

tar:
	tar -zcvf xcurda02.tar $(SRC) manual.pdf README Makefile
