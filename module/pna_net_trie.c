/*
 * Peform longest prefix match on an IP and return the network priority to
 * which it belongs.    All inputs are in network byte order.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "pna_module.h"

struct pna_net_entry {
    int isprefix;
    unsigned short net_id;
    struct pna_net_entry* children[2];
};

struct pna_net_entry* pna_net_head;

struct pna_net_entry* pna_net_entry_alloc(void)
{
    struct pna_net_entry* entry = (struct pna_net_entry*)kmalloc(sizeof(struct pna_net_entry), GFP_KERNEL);
    if(!entry)
        return NULL;
    entry->net_id = PNA_NET_NONE;
    entry->isprefix = 0;
    memset(entry->children, 0, 2 * sizeof(struct pna_net_entry*)); 
    return entry;
}

unsigned int pna_net_lookup(unsigned int ip)
{
    int cur_bit, cur_bit_pos;
    struct pna_net_entry* next_entry;
    struct pna_net_entry* entry = pna_net_head;
    unsigned short curnet = PNA_NET_NONE;
    //assume network byte order
    cur_bit_pos = 0;
    cur_bit = (ip >> (31 - cur_bit_pos)) & 0x1;
    next_entry = entry->children[cur_bit];
    while (next_entry) {
        entry = next_entry;
        if (entry->isprefix) {
            curnet = entry->net_id;
        }
        cur_bit_pos ++;
        cur_bit = (ip >> (31 - cur_bit_pos)) & 1;
        next_entry = entry->children[cur_bit]; 
    }
    return curnet;
}

int pna_net_add(unsigned int prefix, unsigned int max_bit_pos, unsigned int net_id)
{
    unsigned int cur_bit_pos;
    unsigned int cur_bit;
    struct pna_net_entry* next;
    struct pna_net_entry* cur = pna_net_head;

    pna_info("monitoring 0x%08x %i %i\n", prefix, max_bit_pos, net_id);
    
    cur_bit_pos = 0;
    while (cur_bit_pos < max_bit_pos) {
        cur_bit = (prefix >> (31 - cur_bit_pos)) & 0x1;
        next = cur->children[cur_bit];
        if (!next) {
            cur->children[cur_bit] = next = pna_net_entry_alloc();
            if (!next) {
                printk("Failed to alloc net entry\n");
                return -1;
            }
        } 
        cur_bit_pos++;
        cur = next;
    }
    cur->isprefix = 1;
    cur->net_id = net_id;
    return 0;
}

int net_proc_write(struct file* file, const char* buffer, unsigned long count, void* data)
{
    //reads in 3 unsigned ints, in the order prefix, prefix len, netid
    unsigned int mybuf[3];
    if (count < (sizeof(unsigned int) * 3)){
        printk("net write too small\n");
        return -EFAULT;
    }
    if (copy_from_user(mybuf, buffer, sizeof(unsigned int) * 3)) {
        printk("net write fail");
        return -EFAULT;
    }
    pna_net_add(mybuf[0], mybuf[1], mybuf[2]);
    return count;
}

int pna_net_rm_node(struct pna_net_entry *entry)
{
    if (!entry)
        return 0;
    pna_net_rm_node(entry->children[0]);
    pna_net_rm_node(entry->children[1]);
    kfree(entry);
    return 0;
}

int pna_net_deinit(void)
{
    remove_proc_entry(PNA_NETFILE, proc_parent);
    pna_net_rm_node(pna_net_head);
    printk("pna net freed\n");
    return 0;
}

int pna_net_init(void)
{
    struct proc_dir_entry *net_proc_node;
    pna_net_head = pna_net_entry_alloc();
    if (!pna_net_head) {
        pr_err("failed to init net head\n");
        return -1;
    } 

    net_proc_node = create_proc_entry(PNA_NETFILE, 0644, proc_parent);
    if (!net_proc_node) {
        pr_err("failed to make proc entry for %s\n", PNA_NETFILE);
        return -ENOMEM;
    }

    net_proc_node->write_proc = net_proc_write;
    net_proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
    net_proc_node->uid = 0;
    net_proc_node->gid = 0;
    net_proc_node->size = sizeof(unsigned int)*3;
    
    return 0;
}


