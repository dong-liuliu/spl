
#ifndef _SPL_MULBUF_THDPOOL_H
#define	_SPL_MULBUF_THDPOOL_H

#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/rwlock.h>

// TODO
#define DEBU
#ifdef DEBUG
#define dprintk(format, ...)    printk(KERN_ERR format, ##__VA_ARGS__)
#else
#define dprintk(format, ...)
#endif


typedef void (*threadp_func_t)(void *);
typedef struct mulbuf_thdpool mulbuf_thdpool_t;	/* thread pool for multi-buffer crypto */
typedef struct mbtp_thread mbtp_thread_t;	/* thread for multi-buffer thread pool */
typedef struct mbtp_queue mbtp_queue_t;		/* task queue for mb thread pool */

typedef enum mbtp_thd_state {
	THREAD_SETUP,
	THREAD_READY,
	THREAD_RUNNING,
	THREAD_EXIT
} mbtp_thd_state_t;


struct mbtp_thread {
	struct list_head pool_entry;
	mulbuf_thdpool_t *pool;
	struct list_head queue_entry;
	mbtp_queue_t *queue;

	spinlock_t thd_lock;
	unsigned long tpt_lock_flags; /* interrupt state */
	wait_queue_head_t thread_waitq;

	struct task_struct	*tp_thread;
	mbtp_thd_state_t curr_state;
	mbtp_thd_state_t next_state;

	threadp_func_t fn;
	void *arg;
};

struct mulbuf_thdpool {
	char *pool_name;		/* thread pool name */
	int curr_threadcnt;	/* current thread count */
	int max_threadcnt;	/* max thread count, if 0, then unlimited */
	int idle_threadcnt;	/* idle thread count */

	spinlock_t pool_lock;
	unsigned long pool_lock_flags; /* interrupt state */
	wait_queue_head_t pool_waitq;

	struct list_head plthread_idle_list;
	struct list_head plthread_busy_list;
};

/* Initialize thread pool */
int mulbuf_thdpool_create(mulbuf_thdpool_t **pool_r, const char *name, int threadcnt, int max_threadcnt);

/* Destroy thread pool */
void mulbuf_thdpool_destroy(mulbuf_thdpool_t *pool);

/* Get a valid thread from pool */
/* return 0 if success */
int mulbuf_thdpool_get_thread(mulbuf_thdpool_t *pool, mbtp_thread_t **tpt_r);

/* Get a valid thread from pool */
void mbtp_thread_run_fn(mbtp_thread_t *tpt, threadp_func_t fn, void *arg);

/* Return a valid thread to its pool */
void mulbuf_thdpool_put_thread(mbtp_thread_t *tpt);

#endif  /* _SPL_MULBUF_THDPOOL_H */
