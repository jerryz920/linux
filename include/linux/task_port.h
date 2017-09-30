#ifndef _LINUX_TASK_PORT_H
#define _LINUX_TASK_PORT_H

#include <linux/list.h>
#include <linux/slab.h>

struct task_reserved_port_pair {
	struct list_head list;
	int low;
	int high;
};

struct task_struct;

static inline struct task_reserved_port_pair *alloc_task_port_pair(void)
{
	return kmalloc(sizeof(struct task_reserved_port_pair), GFP_KERNEL);
}
static inline void free_task_port_pair(struct task_reserved_port_pair *p)
{
	kfree(p);
}


/* task reserved port management */
#ifdef CONFIG_IP_PER_PROCESS_LOCAL_PORT
void finalize_task_reserved_port_list(struct task_struct*);
#else
static inline void finalize_task_reserved_port_list(struct task_struct*) { }
#endif

#endif
