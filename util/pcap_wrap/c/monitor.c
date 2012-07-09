/*
 * This C file should allow for prototyping potential PNA hooks.
 * You are free to use this file however you want.
 *
 *  - monitor_init() is called once when the program first starts
 *  - monitor_hook() is called once for every packet in a PCAP trace
 */

#include <stdio.h>
#include "pna_hashmap.h"
#include "pna.h"


/* constants */
#define HASHMAP_SIZE (1 << 10) /* = 2^10 = 1024 entries */

/* monitor structs */
struct monitor_entry {
    uint32_t bytes_in;
    uint32_t bytes_out;
};

/* hashmap_{get,put} returns a pointer to the key-value mapping, this
 * mimics the structure using your own type(s) */
struct hash_pair {
    struct session_key key;
    struct monitor_entry value;
};

/* monitor global variables */
static struct pna_hashmap *map;
/* empty value for first insertion to hashmap */
static struct monitor_entry value = { 0, 0 };

uint64_t max_in, max_out;

/* initialization called during startup */
void monitor_init(void)
{
    max_in = max_out = 0;
    map = hashmap_create(
            HASHMAP_SIZE,                /* number of entries for the hashmap */
            sizeof(struct session_key),  /* size of the indexing key structure */
            sizeof(struct monitor_entry) /* size of the data associated with a key */
          );
}

void monitor_release(void)
{
    hashmap_destroy(map);
    printf("----\n");
    printf("max_in: %d\n", max_in);
    printf("max_out: %d\n", max_out);
}

/**
 * Hook is called once per packet.
 * @param *key pointer to the session key data, good for hashing
 * @param direction direction of packet (into our network or out of)
 * @param *pkt pointer to packet length and packet data
 * @param *data arbitrary data passed from previous monitors
 */
void monitor_hook(struct session_key *key, int direction,
                  struct packet *pkt, unsigned long *data)
{
    int i;
    struct hash_pair *entry;

    /* print the session_key info */
    printf("----\n");
    printf("{l3_protocol: %d, l4_protocol: %d, ", key->l3_protocol,
           key->l4_protocol);
    printf("local_ip: 0x%08x, remote_ip: 0x%08x, ", key->local_ip,
           key->remote_ip);
    printf("local_port: %d, remote_port: %d}\n", key->local_port,
           key->remote_port);

    printf("direction: %d\n", direction);

    /* print the number of bytes in this packet */
    printf("length: %lu\n", pkt->length);
	packet_reader(pkt->payload);
}

