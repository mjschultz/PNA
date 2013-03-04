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

/* real-time hook system */
/* @functions: rtmon_init, rtmon_hook, rtmon_clean, rtmon_release */

#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "pna.h"
#include "pna_module.h"

/* in-file prototypes */
static void rtmon_clean(unsigned long data);

/* real-time monitor list and timer declarations */
struct pna_rtmon rtmon_list;
DEFINE_TIMER(timer_copy, rtmon_clean, 0, 0);

/* reset each rtmon for next round of processing -- once per */
/* timer ticker, occurs in interrupt context */
static void rtmon_clean(unsigned long data)
{
    unsigned long next_tick;
    struct pna_rtmon *monitor = (struct pna_rtmon *)data;

    read_lock(&monitor->lock);
    if (monitor->clean) {
        monitor->clean();
    }
    read_unlock(&monitor->lock);

    /* update the timer for the next round */
    next_tick = jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL);
    mod_timer(&monitor->timer, next_tick);
}

/* hook from main on packet to start real-time monitoring */
/* runs in soft irq context */
int rtmon_hook(struct session_key *key, int direction, struct sk_buff *skb,
               unsigned long data)
{
    struct pna_rtmon *monitor;
    int ret = 0;

    list_for_each_entry(monitor, &rtmon_list.list, list) {
        read_lock(&monitor->lock);
        if (monitor->hook) {
            ret += monitor->hook(key, direction, skb, &data);
        }
        read_unlock(&monitor->lock);
    }

    return ret;
}

/* simple pna module init routines for dynamic rtmon support */
int rtmon_init(void)
{
    INIT_LIST_HEAD(&rtmon_list.list);

    return 0;
}

/* go through any rtmons and call their cleanup routine */
void rtmon_cleanup(void)
{
    struct list_head *pos, *q;
    struct pna_rtmon *m;

    pna_info("rtmon_cleanup()\n");

    list_for_each_safe(pos, q, &rtmon_list.list) {
        m = list_entry(pos, struct pna_rtmon, list);
        pna_info("cleanup of '%s'\n", m->name);
        rtmon_unload(m);
    }
}

/* initialize all the resources needed for an rtmon */
int rtmon_load(struct pna_rtmon *monitor)
{
    int ret = 0;
    int idx = 0;
    unsigned long flags;

    /* kernel prevents same rtmon from being loaded twice so this is safe */
    rwlock_init(&monitor->lock);
    write_lock_irqsave(&monitor->lock, flags);

    if (monitor->init) {
        ret = monitor->init();
    }

    /* initialize/correct timer */
    memcpy(&monitor->timer, &timer_copy, sizeof(timer_copy));
    monitor->timer.data = (unsigned long)monitor;
    init_timer(&monitor->timer);
    monitor->timer.expires = jiffies + msecs_to_jiffies(RTMON_CLEAN_INTERVAL);
    add_timer(&monitor->timer);

    /* safe to go, unlock */
    write_unlock_irqrestore(&monitor->lock, flags);

    /* insert new monitor to tail of monitor list */
    list_add_tail(&monitor->list, &rtmon_list.list);
    pna_info("rtmon '%s' loaded\n", monitor->name);

    monitor = NULL;
    list_for_each_entry(monitor, &rtmon_list.list, list) {
        pna_info("rtmon%d: %s\n", idx, monitor->name);
        idx++;
    }

    return ret;
}
EXPORT_SYMBOL(rtmon_load);

/* unload and release the resources for an rtmon */
void rtmon_unload(struct pna_rtmon *monitor)
{
    int idx = 0;
    unsigned long flags;

    /* remove the monitor from the table */
    list_del(&monitor->list);

    /* remove the timer */
    del_timer(&monitor->timer);

    /* clean up the monitor */
    /* there is a potential that .hook() or .cleanup() is executing */
    write_lock_irqsave(&monitor->lock, flags);
    if (monitor->release) {
        monitor->release();
    }
    write_unlock_irqrestore(&monitor->lock, flags);

    /* show currently active monitors */
    list_for_each_entry(monitor, &rtmon_list.list, list) {
        pna_info("rtmon%d: %s\n", idx, monitor->name);
        idx++;
    }
}
EXPORT_SYMBOL(rtmon_unload);
