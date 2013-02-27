
progs := example_mon pcap_dump session

CFLAGS := -I../include
LDLIBS := -lpcap

all: $(progs)

$(progs): ../user/pna.o

session: ../user/session_dump.o ../user/proc_dump.o

clean:
	rm -f $(progs) *.o
