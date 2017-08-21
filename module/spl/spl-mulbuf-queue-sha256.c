
#if defined(__x86_64) && defined(__KERNEL__) && defined(HAVE_HASH_MB)

#include <sys/mulbuf_queue_sha256.h>
// TODO isa-l header location
//#include <isa-l.h>
#include <sys/sha256_mb.h>
// TODO fpu header judge
#include <asm/fpu/api.h>

#define STACK_ALIGNCALL16(x)  \
{ \
    asm("push %rdi"); \
    asm("mov %rsp, %rdi"); \
    asm("and $0xfffffffffffffff0, %rsp"); \
    asm("push %rdi"); \
    asm("sub $8, %rsp"); \
    asm("mov (%rdi), %rdi"); \
    x; \
    asm("add $8, %rsp"); \
    asm("pop %rsp"); \
    asm("add $8, %rsp"); \
}

int sha256_mb_concurrent_lanes(void)
{
	// TODO multi-binary check
	return 8;
}

int spl_mulbuf_snoop_size_threshold = 128 * 1024;
module_param(spl_mulbuf_snoop_size_threshold, int, 0644);
MODULE_PARM_DESC(spl_mulbuf_snoop_size_threshold,
		"Size threshold for sha256_mb to snoop new tasks");

/*
 * @brief Get first usable ctx from a ctx array
 *
 * @params sidx: start index for this search
 *
 * @return int: >=0, the index we find in this ctx array
 * 				-1, not found
 */
static int get_unused_hash_ctx(SHA256_HASH_CTX ctxpool[], int sidx,
		int concurrent_num)
{
	int i;
	for (i = sidx; i < concurrent_num; i++){
		if(hash_ctx_complete(&ctxpool[i]))
			return i;
	}

	return -1;
}
static int get_used_hash_ctx(SHA256_HASH_CTX ctxpool[], int sidx,
		int concurrent_num)
{
	int i;
	for (i = sidx; i < concurrent_num; i++){
		/* completed ctx has user_data */
		if(ctxpool[i].user_data && hash_ctx_complete(&ctxpool[i]))
			return i;
	}

	return -1;
}
static int get_using_hash_ctx(SHA256_HASH_CTX ctxpool[], int sidx,
		int concurrent_num)
{
	int i;
	for (i = sidx; i < concurrent_num; i++){
		if(!hash_ctx_complete(&ctxpool[i]))
			return i;
	}

	return -1;
}


/* @brief snoop mb-hash function with length threshold
 *
 */
void sha256_mb_length_thd(SHA256_HASH_CTX_MGR *mgr, SHA256_HASH_CTX ctxpool[],
		mbtp_task_t *ta[], int take_num, int concurrent_num, int thd)
{
	int i;
	int sidx;
	unsigned char *buffer;
	size_t gap, size;
	mbtp_task_t *job;
	SHA256_HASH_CTX *tmp;


	kernel_fpu_begin();
    /* process previous processing jobs */
	sidx = -1;
	while((sidx = get_using_hash_ctx(ctxpool, sidx+1, concurrent_num)) != -1){
		job = (mbtp_task_t *)ctxpool[sidx].user_data;

		buffer = (unsigned char *)job->buffer + ctxpool[sidx].total_length;
		gap = job->size - ctxpool[sidx].total_length;
		/* check whether this is last round */
		if(thd <= gap){
			size = thd;
			STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], (void *)buffer, size, HASH_UPDATE));
		}else{
			size = gap;
			STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], (void *)buffer, size, HASH_LAST));
		}
	}

	/* process new taken jobs */
	sidx = -1;
    if (take_num > 0){
    	for (i = 0; i < take_num; i++) {
    		sidx = get_unused_hash_ctx(ctxpool, sidx+1, concurrent_num);
    		job = ta[i];
    		/* link job with ctx */
    		ctxpool[sidx].user_data = (void*)job;
    		if(ta[i]->size <= thd){
    			STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], ta[i]->buffer, ta[i]->size, HASH_ENTIRE));
    		}else{
    			STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], ta[i]->buffer, thd, HASH_FIRST));
    		}
    	}
    }

    STACK_ALIGNCALL16(tmp = sha256_ctx_mgr_flush(mgr));
	while (tmp)
		STACK_ALIGNCALL16(tmp = sha256_ctx_mgr_flush(mgr));

	kernel_fpu_end();

	return;
}
/* @brief full mb-hash function with origin threshold
 *
 */
void sha256_mb_length_full(SHA256_HASH_CTX_MGR *mgr, SHA256_HASH_CTX ctxpool[],
		mbtp_task_t *ta[], int take_num, int concurrent_num)
{
	int i;
	int sidx;
	unsigned char *buffer;
	size_t gap;
	mbtp_task_t *job;
	SHA256_HASH_CTX *tmp;

	kernel_fpu_begin();
    /* process previous processing jobs */
	sidx = -1;
	while((sidx = get_using_hash_ctx(ctxpool, sidx+1, concurrent_num)) != -1){
		job = (mbtp_task_t *)ctxpool[sidx].user_data;

		buffer = (unsigned char *)job->buffer + ctxpool[sidx].total_length;
		gap = job->size - ctxpool[sidx].total_length;
		STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], (void *)buffer, gap, HASH_LAST));
	}

	/* process new taken jobs */
	sidx = -1;
    if (take_num > 0){
    	for (i = 0; i < take_num; i++) {
    		sidx = get_unused_hash_ctx(ctxpool, sidx+1, concurrent_num);
    		/* link job with ctx */
    		ctxpool[sidx].user_data = (void*)ta[i];

    		STACK_ALIGNCALL16(sha256_ctx_mgr_submit(mgr, &ctxpool[sidx], ta[i]->buffer, ta[i]->size, HASH_ENTIRE));
    	}
    }

    STACK_ALIGNCALL16(tmp = sha256_ctx_mgr_flush(mgr));
	while (tmp)
		STACK_ALIGNCALL16(tmp = sha256_ctx_mgr_flush(mgr));

	kernel_fpu_end();

	return;
}


inline uint32_t byteswap32(uint32_t x)
{
	return (x >> 24) | (x >> 8 & 0xff00) | (x << 8 & 0xff0000) | (x << 24);
}

/* @brief process completed jobs
 *
 * @returns int number of completed jobs
 * */
int sha256_mb_count_complete(SHA256_HASH_CTX ctxpool[], int concurrent_num)
{
	int sidx;
	int count = 0;
	mbtp_task_t *job;
	uint32_t *H;

    /* completed ctx */
	sidx = -1;
	while((sidx = get_used_hash_ctx(ctxpool, sidx+1, concurrent_num)) != -1){
		job = (mbtp_task_t *)ctxpool[sidx].user_data;

	  /* sha256 digest: sha256-mb is A62F007C C6848756 ...                                                                                                                                        V..Æ|./¦
	   *				sha256-zfs is C6848756 A62F007C ...
	   *				sha256-ossl is 7C002FA6 568784C6 ...
	   */
#ifndef OPENSSL-SHA256
	    // change sha256-mb to sha256-zfs
		H = (uint32_t *)ctxpool[sidx].job.result_digest;
		*(uint64_t *)&job->digest[0] = (uint64_t)H[0] << 32 | H[1];
		*(uint64_t *)&job->digest[8] = (uint64_t)H[2] << 32 | H[3];
		*(uint64_t *)&job->digest[16] = (uint64_t)H[4] << 32 | H[5];
		*(uint64_t *)&job->digest[24] = (uint64_t)H[6] << 32 | H[7];

#else
		// change sha256-mb to sha256-ossl
		H = (uint32_t *)ctxpool[sidx].job.result_digest;
		*(uint32_t *)&job->digest[0] = byteswap32(H[0]);
		*(uint32_t *)&job->digest[4] = byteswap32(H[1]);
		*(uint32_t *)&job->digest[8] = byteswap32(H[2]);
		*(uint32_t *)&job->digest[12] = byteswap32(H[3]);
		*(uint32_t *)&job->digest[16] = byteswap32(H[4]);
		*(uint32_t *)&job->digest[20] = byteswap32(H[5]);
		*(uint32_t *)&job->digest[24] = byteswap32(H[6]);
		*(uint32_t *)&job->digest[28] = byteswap32(H[7]);
#endif

		job->processsed = 1;
		if (job->cb_fn)
			job->cb_fn(job, job->cb_arg);

		hash_ctx_init(&ctxpool[sidx]);
		/* user_data is used to judge just now completed ctxpool */
		ctxpool[sidx].user_data = NULL;
		count++;
	}

	return count;
}


/********** auxiliary structure and functions *************/
typedef struct sha256_aux{
	SHA256_HASH_CTX_MGR *mgr;
	SHA256_HASH_CTX ctxpool[16];
	int concurrent_num;
}sha256_aux_t;

int sha256_mb_auxiliary_init(sha256_aux_t **aux_r)
{
	sha256_aux_t *aux;
	SHA256_HASH_CTX_MGR *mgr;
	int i;

	aux = (sha256_aux_t *)kmem_alloc(sizeof(*aux), KM_PUSHPAGE | KM_ZERO);
	*aux_r = aux;
	if(aux == NULL)
		return 1;

	// TODO memalign allocation
	//posix_memalign((void *)&mgr, 16, sizeof(SHA256_HASH_CTX_MGR));
	mgr =( SHA256_HASH_CTX_MGR *)kmem_alloc(sizeof(*mgr), KM_PUSHPAGE | KM_ZERO);
	aux->mgr = mgr;
	sha256_ctx_mgr_init(mgr);

	aux->concurrent_num = sha256_mb_concurrent_lanes();
	for (i = 0; i < aux->concurrent_num; i++){
		hash_ctx_init(&aux->ctxpool[i]);
	}

	return 0;
}

void sha256_mb_auxiliary_fini(sha256_aux_t *aux)
{
	kmem_free(aux->mgr, sizeof(*aux->mgr));
	kmem_free(aux, sizeof(*aux));

	return;
}


unsigned long sha256_mb_snoop_proc(mbtp_thread_t *tqt, sha256_aux_t *aux, int thd, unsigned long flags)
{
	mbtp_queue_t *queue = tqt->queue;
	mbtp_task_t *jobs[32];
	mbtp_task_t *job;

	SHA256_HASH_CTX_MGR *mgr = aux->mgr;
	SHA256_HASH_CTX *ctxpool = aux->ctxpool;
	int concurrent_num = aux->concurrent_num;

	int take_num, complete_num, process_num;
	int i;
	int snoop = 0;
	int rc;

	if (queue->idle_threadcnt <= 0) {
		printk(KERN_ERR "idles thread is should at least one, queue is %p ", queue);
		*(int *)0 = 010101010101;
	}
	ASSERT(queue->idle_threadcnt > 0);
	/* get tasks from queue's job list*/
	process_num = complete_num = 0;
	while((take_num = mbtp_queue_assign_taskjobcnt(queue, process_num, concurrent_num)) || process_num) {
		queue->curr_taskcnt -= take_num;
		queue->proc_taskcnt += take_num;
		queue->idle_threadcnt--;
		// take tasks out
		for (i = 0; i < take_num && !list_empty(&queue->task_list); i++) {
			job = list_entry(queue->task_list.next, mbtp_task_t, queue_entry);
			list_del(&job->queue_entry);
			jobs[i] = job;
		}

		if(i != take_num){
			printk(KERN_ERR "takenum is more than list have, i is %d, takenum is %d ", i, take_num);
			printk(KERN_ERR "idlethd is %d+1, cyrr_jbcnt is %d+takenum, process_num is %d ",
					queue->idle_threadcnt, queue->curr_taskcnt, process_num);
		}
		ASSERT(i == take_num);

		/* start snoop loop */
		if(queue->idle_threadcnt == 0){
		/* Last idle thread should do snoop operations */
			if(take_num + process_num < concurrent_num){
			/* snoop if this thread is not full */
				snoop = 1;
			}else if(queue->max_threadcnt == queue->curr_threadcnt){
			/* all threads are working, not snoop since this thread is full of jobs */
				snoop = 0;
			}else{
				/* release lock before add thread */
				spin_unlock_irqrestore(&queue->queue_lock, flags);

			//	printk(KERN_ERR "thd %p goes to add thread; processnum %d, takenum %d", tqt, process_num, take_num);
				/* no snoop if this thread is full and can add an extra thread into queue */
				rc = mbtp_queue_add_thread(queue);

			//	printk(KERN_ERR "thd %p goes to add thread  done ", tqt);


				spin_lock_irqsave(&queue->queue_lock, flags);

				/* check whether need to signal next thread */
				if(queue->curr_taskcnt > 0 && queue->idle_threadcnt > 0)
					wake_up(&queue->queue_waitq);
				snoop = 0;
			}
		}else {
		/* extra idle thread needn't do snoop operations */
			/* check whether need to signal next thread */
			if(queue->curr_taskcnt > 0 && queue->idle_threadcnt > 0)
				wake_up(&queue->queue_waitq);
			snoop = 0;
		}

		spin_unlock_irqrestore(&queue->queue_lock, flags);
		if (snoop){
			sha256_mb_length_thd(mgr, ctxpool, jobs, take_num, concurrent_num, thd);
		}else{
			sha256_mb_length_full(mgr, ctxpool, jobs, take_num, concurrent_num);
		}
		complete_num = sha256_mb_count_complete(ctxpool, concurrent_num);
		process_num = take_num + process_num - complete_num;

		spin_lock_irqsave(&queue->queue_lock, flags);

		queue->idle_threadcnt++;
		queue->proc_taskcnt -= complete_num;

		if (snoop) {
			continue; // continue snoop loop
		}else {
			break; // leave snoop loop
		}
	}

	if(get_using_hash_ctx(ctxpool, 0, concurrent_num) != -1)
		printk(KERN_ERR "snoop %d! ctxpool %p;current take_num %d; process_num %d; complete %d ",
						snoop, ctxpool, take_num, process_num, complete_num);
	//if(queue->proc_taskcnt = 1 && snoop == 1)
	//		printk(KERN_ERR "snoop %d! ctxpool %p;current take_num %d; process_num %d; complete %d ",
	//			snoop, ctxpool, take_num, process_num, complete_num);
	return flags;
}



/*
 * @brief taskqueue function in which thread will run
 */
typedef enum hash_fn_state{
	HASH_WAIT,
	HASH_PROCESS,
	HASH_EXIT
}hash_fn_state_t;
void mulbuf_sha256_fn(void *arg)
{
	DECLARE_WAITQUEUE(thd_wait, current);
	hash_fn_state_t state;
	mbtp_thread_t *tpt = (mbtp_thread_t *)arg;
	mbtp_queue_t *queue = tpt->queue;

	unsigned long flags;

	int concurrent_num;

	sha256_aux_t *aux;

	sha256_mb_auxiliary_init(&aux);
	concurrent_num = aux->concurrent_num;

	state = HASH_WAIT;

	dprintk("sha256-tpt %p is trying lock queue\n", tpt);
	spin_lock_irqsave(&queue->queue_lock, flags);

	while(state != HASH_EXIT){

		dprintk("sha256-queue tpt %p is in hash state %d\n", tpt, state);
		switch(state){
		case HASH_WAIT:
			/* if queue is leaving, start to leave at first */
			if(queue->leave > 0){
				state = HASH_EXIT;
				break;
			}
			/* shrink thread */
			if(mbtp_queue_check_shrink_thread(queue, concurrent_num) == 0){
				state = HASH_EXIT;
				break;
			}
			/* if there are tasks, directly process them */
			if(queue->curr_taskcnt > 0){
				state = HASH_PROCESS;
				break;
			}

			/* wait for task coming or exit notice*/
			add_wait_queue_exclusive(&queue->queue_waitq, &thd_wait);
			set_current_state(TASK_INTERRUPTIBLE);

			spin_unlock_irqrestore(&queue->queue_lock, flags);

			schedule();

			spin_lock_irqsave(&queue->queue_lock, flags);
			__set_current_state(TASK_RUNNING);

			remove_wait_queue(&queue->queue_waitq, &thd_wait);

			if(queue->curr_taskcnt == 0){
				state = HASH_EXIT;
			}else{
				state = HASH_PROCESS;
			}

			break;
		case HASH_PROCESS:
		/* get tasks from queue's job list*/
			flags = sha256_mb_snoop_proc(tpt, aux, spl_mulbuf_snoop_size_threshold, flags);

			state = HASH_WAIT;
			break;

		case HASH_EXIT:
		default:
			break;
		}
	}

	if(queue->leave){
	/* queue is leaving, queue will detach them */

		spin_unlock_irqrestore(&queue->queue_lock, flags);

		/* let queue know, this thread is left now */
		spin_lock_irqsave(&tpt->thd_lock, flags);
		tpt->next_state = THREAD_READY;
		wake_up(&tpt->thread_waitq);
		spin_unlock_irqrestore(&tpt->thd_lock, flags);
	}else{
	/* queue is not leaving, thread detaches itself from queue */
		/* after shrink, this thread has no relationship with queue, its owner becomes pool */
		spin_unlock_irqrestore(&queue->queue_lock, flags);

		/* let queue know, this thread is left now */
		spin_lock_irqsave(&tpt->thd_lock, flags);
		tpt->next_state = THREAD_READY;
		wake_up(&tpt->thread_waitq);
		spin_unlock_irqrestore(&tpt->thd_lock, flags);

		spin_lock_irqsave(&queue->queue_lock, flags);
		mbtp_queue_shrink_thread(queue, tpt);
		spin_unlock_irqrestore(&queue->queue_lock, flags);
	}

	sha256_mb_auxiliary_fini(aux);

	return;
}

#endif /* __KERNEL__ && __x86_64 && HAVE_HASH_MB */
