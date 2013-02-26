/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* main PNA initialization (where the kernel module starts) */
/* functions: pna_init, pna_cleanup, pna_hook */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/if.h>

#include <linux/jiffies.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/sctp.h>

#include "pna.h"
#include "pna_module.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
# error "Module does not support linux kernel < 2.6.34"
#endif

extern unsigned int pna_net_lookup(unsigned int ip);
extern int pna_net_init(void);
extern int pna_net_deinit(void);

static void pna_perflog(struct sk_buff *skb, int monitored);
static int pna_localize(struct session_key *key, int *direction);
static int pna_done(struct sk_buff *skb);
int pna_hook(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev);
static int __init pna_init(void);
static void pna_cleanup(void);

/* define a new packet type to hook on */
#define PNA_MAXIF 4
static struct packet_type pna_packet_type[PNA_MAXIF] = {
    { .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
    { .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
    { .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
    { .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
};

/* for performance measurement */
#define PNA_UNMONITORED 0
#define PNA_MONITORED 1
struct pna_perf {
    __u64 t_jiffies; /* 8 */
    struct timeval currtime; /* 8 */
    struct timeval prevtime; /* 8 */
    __u64 p_interval[2]; /* 16 */
    __u64 B_interval[2]; /* 16 */
    __u64 dev_last_rx[PNA_MAXIF];
    __u64 dev_last_drop[PNA_MAXIF];
    __u64 dev_last_fifo[PNA_MAXIF];
};

DEFINE_PER_CPU(struct pna_perf, perf_data);

/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
# define time_after_eq64(a,b) \
   (typecheck(__u64,a) && typecheck(__u64,b) && ((__s64)(a)-(__s64)(b)>=0))
#endif
#define PERF_INTERVAL      10

/* general non-kernel hash function for double hashing */
/* XXX: this will be depricated once hashmap is integrated */
unsigned int pna_hash(unsigned int key, int bits)
{
    unsigned int hash = key;

    /* lets take the highest bits */
    hash = key >> (sizeof(unsigned int) - bits);

    /* divide by 2 and make it odd */
    hash = (hash >> 1) | 0x01;

    return hash;
}
EXPORT_SYMBOL(pna_hash);

//swap remote and local in the session_key
static inline void pna_key_swap(struct session_key *key)
{
    unsigned int temp;

    /* network swap */
    temp = key->local_net;
    key->local_net = key->remote_net;
    key->remote_net = temp;

    /* ip swap */
    temp = key->local_ip;
    key->local_ip = key->remote_ip;
    key->remote_ip = temp;

    /* port swap */
    temp = key->local_port;
    key->local_port = key->remote_port;
    key->remote_port = temp;
}


/**
 * Receive Packet Hook (and helpers)
 */
/* make sure the local and remote values are correct in the key */
static int pna_localize(struct session_key *key, int *direction)
{
    /* trie stores stuff in network byte order */
    key->local_net = pna_net_lookup((key->local_ip));
    key->remote_net = pna_net_lookup((key->remote_ip));

    if (key->local_net == PNA_NET_NONE && key->remote_net == PNA_NET_NONE) {
        /* local and remote IPs are not IPs we are supposed to monitor */
        return 0;
    }

    /* the lowest network is treated as local */
    if (key->local_net < key->remote_net) {
        /* local network is local! */
        *direction = PNA_DIR_OUTBOUND;
        return 1;
    }
    else if (key->remote_net < key->local_net) {
        /* remote network is smaller, swap! */
        *direction = PNA_DIR_INBOUND;
        pna_key_swap(key);
        return 1;
    }

    /* IPs are in same network, smaller port is local */
    if (key->local_port < key->remote_port) {
        *direction = PNA_DIR_OUTBOUND;
            return 1;
    }
    else if (key->remote_port < key->local_port) {
        /* remote port is smaller, swap! */
        *direction = PNA_DIR_INBOUND;
        pna_key_swap(key);
        return 1;
    }

    /* IPs are in same network and port is same, smaller IP is local */
    if (key->local_ip < key->remote_ip) {
        *direction = PNA_DIR_OUTBOUND;
        return 1;
    }
    else if (key->remote_ip < key->local_ip) {
        /* remote port is smaller, swap! */
        *direction = PNA_DIR_INBOUND;
        pna_key_swap(key);
        return 1;
    }

    /* At this point, src_ip==dst_ip and src_port==dst_port so drop this
     * packet */

    return 0;
}

/* free all te resources we've used */
static int pna_done(struct sk_buff *skb)
{
    kfree_skb(skb);
    return NET_RX_DROP;
}

/* per-packet hook that begins pna processing */
int pna_hook(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev)
{
    struct session_key key;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    struct sctphdr *sctphdr;
    struct icmphdr *icmphdr;
    int direction = -1;
    int flags = 0;
    int ret = 0;

    /* we don't care about outgoing packets */
    if (skb->pkt_type == PACKET_OUTGOING) {
        return pna_done(skb);
    }

    /* only our software deals with *dev, no one else should care about skb */
    /* (also greatly imrpoves performance since ip_input doesn't do much) */
    skb->pkt_type = PACKET_OTHERHOST;
    
    /* make sure we have the skb exclusively */
    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
        /* non-exclusive and couldn't clone, must drop */ 
        return NET_RX_DROP;
    }

	/* make sure the key is all zeros before we start */
	memset(&key, 0, sizeof(key));
    
    /* we now have exclusive access, so let's decode the skb */
    ethhdr = eth_hdr(skb);
    key.l3_protocol = ntohs(ethhdr->h_proto);
    
    switch (key.l3_protocol) {
    case ETH_P_IP:
        /* this is a supported type, continue */
        iphdr = ip_hdr(skb);
        /* assume for now that src is local */
        key.local_ip = ntohl(iphdr->saddr);
        key.remote_ip = ntohl(iphdr->daddr);
        key.l4_protocol = iphdr->protocol;

        skb_set_transport_header(skb, ip_hdrlen(skb));
        switch (key.l4_protocol) {
        case IPPROTO_TCP:
            tcphdr = tcp_hdr(skb);
            key.local_port = ntohs(tcphdr->source);
            key.remote_port = ntohs(tcphdr->dest);
            /* only pass ECE through if not SYN packet (ignore otherwise) */
            if (!tcphdr->syn && tcphdr->ece)
                flags |= TCP_FLAG_ECE;
            /* pass through other TCP flags as they happen */
            if (tcphdr->cwr) flags |= TCP_FLAG_CWR;
            if (tcphdr->urg) flags |= TCP_FLAG_URG;
            if (tcphdr->ack) flags |= TCP_FLAG_ACK;
            if (tcphdr->psh) flags |= TCP_FLAG_PSH;
            if (tcphdr->rst) flags |= TCP_FLAG_RST;
            if (tcphdr->syn) flags |= TCP_FLAG_SYN;
            if (tcphdr->fin) flags |= TCP_FLAG_FIN;
            break;
        case IPPROTO_UDP:
            udphdr = udp_hdr(skb);
            key.local_port = ntohs(udphdr->source);
            key.remote_port = ntohs(udphdr->dest);
            break;
        case IPPROTO_SCTP:
            sctphdr = sctp_hdr(skb);
            key.local_port = ntohs(sctphdr->source);
            key.remote_port = ntohs(sctphdr->dest);
        case IPPROTO_ICMP:
            icmphdr = icmp_hdr(skb);
            /* ICMP doesn't have ports, set to 0s */
            /* Abuse the `flags` field to encode the type,
             * the code itself will be ignored */
            key.local_port = 0;
            key.remote_port = 0;
            flags = icmphdr->type;
        default:
            return pna_done(skb);
        }
        break;
    default:
        return pna_done(skb);
    }

    /* log performance data */

    /* entire key should now be filled in and we have a session, localize it */
    if (!pna_localize(&key, &direction)) {
        /* couldn't localize the IP (neither source nor dest in prefix) */
        pna_perflog(skb, PNA_UNMONITORED);
        return pna_done(skb);
    }

    pna_perflog(skb, PNA_MONITORED);

    /* insert into session table */
    if (pna_session_mon == true) {
        ret = session_hook(&key, direction, skb, flags);
        if (ret < 0) {
            /* failed to insert -- cleanup */
            return pna_done(skb);
        }
    }

    /* run real-time hooks (if any are loaded.) */
    rtmon_hook(&key, direction, skb, (unsigned long)ret);

    /* free our skb */
    return pna_done(skb);
}

/**
 * Performance Monitoring
 */
static void pna_perflog(struct sk_buff *skb, int monitored)
{
    __u64 t_interval;
    __u64 fps_mon, bps_mon, avg_mon;
    __u64 fps_unmon, bps_unmon, avg_unmon;
    struct rtnl_link_stats64 stats;
    int i;
    struct net_device *dev;
    struct pna_perf *perf = &get_cpu_var(perf_data);

    /* don't want monitoring? */
    if (!pna_perfmon) {
        return;
    }

    /* time_after_eq64(a,b) returns true if time a >= time b. */
    if ( time_after_eq64(get_jiffies_64(), perf->t_jiffies) ) {

        /* get sampling interval time */
        do_gettimeofday(&perf->currtime);
        t_interval = perf->currtime.tv_sec - perf->prevtime.tv_sec;
        /* update for next round */
        perf->prevtime = perf->currtime;

        /* calculate the numbers */
        fps_mon = perf->p_interval[PNA_MONITORED] / t_interval;
        bps_mon = perf->B_interval[PNA_MONITORED] * 8 / t_interval;
        avg_mon = 0;
        if (perf->p_interval[PNA_MONITORED] != 0) {
            avg_mon = perf->B_interval[PNA_MONITORED];
            avg_mon /= perf->p_interval[PNA_MONITORED];
            /* take away non-Ethernet packet measured */
            avg_mon -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }

        fps_unmon = perf->p_interval[PNA_UNMONITORED] / t_interval;
        bps_unmon = perf->B_interval[PNA_UNMONITORED] * 8 / t_interval;
        avg_unmon = 0;
        if (perf->p_interval[PNA_UNMONITORED] != 0) {
            avg_unmon = perf->B_interval[PNA_UNMONITORED];
            avg_unmon /= perf->p_interval[PNA_UNMONITORED];
            /* take away non-Ethernet packet measured */
            avg_unmon -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }

        /* report the numbers */
        if (fps_mon + fps_unmon > 1) {
            pna_info("pna smpid:%d,mon:{fps:%llu,bps:%llu,avg:%llu},"
                     "unmon:{fps:%llu,bps:%llu,avg:%llu}\n",
                     smp_processor_id(), fps_mon, bps_mon, avg_mon,
                     fps_unmon, bps_unmon, avg_unmon);

            for (i = 0; i < PNA_MAXIF; i++) {
                dev = pna_packet_type[i].dev;
                if (dev == NULL) {
                    break;
                }
                /* numbers from the NIC */
                dev_get_stats(dev, &stats);
                pna_info("pna %s:{packets:%llu,overruns:%llu,missed:%lli}\n",
                        dev->name, stats.rx_packets - perf->dev_last_rx[i],
                        stats.rx_fifo_errors - perf->dev_last_fifo[i],
                        stats.rx_missed_errors - perf->dev_last_drop[i]);
                perf->dev_last_rx[i] = stats.rx_packets;
                perf->dev_last_drop[i] = stats.rx_missed_errors;
                perf->dev_last_fifo[i] = stats.rx_fifo_errors;
            }
        }

        /* set updated counters */
        perf->p_interval[PNA_MONITORED] = 0;
        perf->B_interval[PNA_MONITORED] = 0;
        perf->p_interval[PNA_UNMONITORED] = 0;
        perf->B_interval[PNA_UNMONITORED] = 0;
        perf->t_jiffies = msecs_to_jiffies(PERF_INTERVAL*MSEC_PER_SEC);
        perf->t_jiffies += get_jiffies_64();
    }

    /* increment packets seen in this interval */
    perf->p_interval[monitored]++;
    perf->B_interval[monitored] += skb->len + ETH_OVERHEAD;
}

/*
 * Module oriented code
 */
/* Initialization hook */
int __init pna_init(void)
{
    char *next = pna_iface;
    int i;
    int ret = 0;

    /* set up the session table(s) */
    if ((ret = session_init()) < 0) {
        return ret;
    }

    /* init the network mappings (depends on /proc entry) */
    pna_net_init();

    if (rtmon_init() < 0) {
        pna_cleanup();
        return -1;
    }

    /* set up the message system */
    if (pna_message_init() < 0) {
        pna_cleanup();
        return -1;
    }

    /* everything is set up, register the packet hook */
    for (i = 0; (i < PNA_MAXIF) && (next != NULL); i++) {
        next = strnchr(pna_iface, IFNAMSIZ, ',');
        if (NULL != next) {
            *next = '\0';
        }
        pna_packet_type[i].dev = dev_get_by_name(&init_net, pna_iface);
        if (pna_packet_type[i].dev == NULL) {
            pna_err("pna: no device named '%s'", pna_iface);
            pna_cleanup();
            return -1;
        }
        pna_info("pna: capturing on %s", pna_iface);
        dev_add_pack(&pna_packet_type[i]);
        pna_iface = next + 1;
    }

#ifdef PIPELINE_MODE
    next = "(in pipeline mode)";
#else
    next = "";
#endif /* PIPELINE_MODE */

    pna_info("pna: module is initialized %s\n", next);

    return ret;
}

/* Destruction hook */
void pna_cleanup(void)
{
    int i;

    for (i = 0 ; (i < PNA_MAXIF) && (pna_packet_type[i].dev != NULL); i++) {
        dev_remove_pack(&pna_packet_type[i]);
        pna_info("pna: released %s\n", pna_packet_type[i].dev->name);
    }
    rtmon_cleanup();
    pna_message_cleanup();
    pna_net_deinit();
    session_cleanup();
    pna_info("pna: module is inactive\n");
}

module_init(pna_init);
module_exit(pna_cleanup);
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
