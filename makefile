LDLIBS=-lpcap

all: swapArpTable

main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

getMyMac.o : getMyMac.h getMyMac.cpp

swapArpTable: main.o arphdr.o ethhdr.o ip.o mac.o getMyMac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
