#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>

#include "pna.h"
#include "pna_module.h"

void port80mon_init(void);
int port80mon_hook(struct session_key *key, int direction, struct sk_buff *skb,
                unsigned long *data);
void port80mon_clean(void);
void port80mon_release(void);

struct pna_rtmon port80mon = {
    .name = "Port 80 monitor",
    .hook = port80mon_hook,
    .init = port80mon_init,
    .clean = port80mon_clean,
    .release = port80mon_release,
};

MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Anthony Adams <acadams@mit.edu>");
PNA_MONITOR(&port80mon);


/* This is the difference from the other monitors. Does not need to get
detailed information from the packet, only needs to grab the port number
and if that port number is 80, then emits log message */

void port80mon_init(void)
{
    return 0;
}

void port80mon_clean(void)
{
    return 0;
}

void port80mon_release(void)
{
    return 0;
}

int port80mon_hook(struct session_key *key, int direction, struct sk_buff *skb, unsigned long *data)
{	
	
	
	/* if the port is 80, print the IP address that connects */
	if(key->remote_port == 80 && direction == pna_dir_inbound) {
		pr_info("%u is connecting to Port %u\n", key->local_ip, key->remote_port);		
	}
	
	return 0;
}



