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
void clear_task_reserved_port_list(struct task_struct*);
int copy_reserved_ports_from_parent(struct task_struct *parent, struct task_struct *child);
#else
static inline void clear_task_reserved_port_list(struct task_struct*) { }
static inline int copy_reserved_ports_from_parent(struct task_struct*, struct task_struct*)
{
	return 0;
}
#endif

#endif
