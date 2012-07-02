PROGRAM := pna_pcap
PROGRAM_DEPS:=sniffer.o
HASHMAP_DEPS := pna_hashmap.o murmur3.o monitor.o
CFLAGS := -I../include
LDLIBS := -lpcap

all: ${PROGRAM}

debug: CFLAGS += -ggdb
debug: ${PROGRAM}

${PROGRAM}: ${HASHMAP_DEPS} ${PROGRAM_DEPS}

clean:
	rm -f ${PROGRAM} *.o
