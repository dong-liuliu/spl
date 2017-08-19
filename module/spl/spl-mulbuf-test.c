#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <sys/kmem.h>
#include <unistd.h>
#include <linux/delay.h>

#include <sys/mulbuf_test.h>

void pool_init_fini_test(void)
{
	mulbuf_thdpool_t *pool;
	int threadcnt = 10;
	int max_threadcnt = 20;
	char namep[] = "sha256mb-pool";
	int rc;


	printk(KERN_ERR "spl: pool_init_fini_test");
	printk(KERN_ERR "sha256-pool create");
	rc = mulbuf_thdpool_create(&pool, namep, threadcnt, max_threadcnt);


	printk(KERN_ERR "sha256-pool destroy");
	mulbuf_thdpool_destroy(pool);

	printk(KERN_ERR "spl: pool_init_fini_test passed");

	return;
}

void pool_queue_init_fini_test()
{
	int threadcnt = 10;
	int max_threadcnt = 20;
	char namep[] = "sha256mb-pool";
	char nameq[] = "sha256mb-queue";
	int rc, i;

	mulbuf_thdpool_t *pool;
	int nqueue = 5;
	mbtp_queue_t **queue_array;

	queue_array = kmem_alloc(sizeof(mbtp_queue_t *) * nqueue, KM_PUSHPAGE);

	printk(KERN_ERR "spl: pool_queue_init_fini_test");
	printk(KERN_ERR "sha256-pool create");
	rc = mulbuf_thdpool_create(&pool, namep, threadcnt, max_threadcnt);

	for (i = 0; i < nqueue; i++) {
		mbtp_queue_create(&queue_array[i], nameq, pool,
				2, 10, mulbuf_sha256_fn);
		printk(KERN_ERR "sha256-queue %d %p create", i, queue_array[i]);
	}


	for (i = 0; i < nqueue; i++) {
		printk(KERN_ERR "sha256-queue %d %p destroy", i, queue_array[i]);
		mbtp_queue_destroy(queue_array[i]);
	}


	kmem_free(queue_array, sizeof(mbtp_queue_t *) * nqueue);

	printk(KERN_ERR "sha256-pool destroy");
	mulbuf_thdpool_destroy(pool);

	printk(KERN_ERR "spl: pool_queue_init_fini_test passed");

	return;
}


/******************************************************************************
 *
 * test suite facility for multi tasks
 *
 *****************************************************************************/

typedef struct testcase{
	int jobnum;
	int pool_threadcnt;
	int pool_maxthreadcnt;
	int queue_minthreadcnt;
}testcase_t;

static inline void printf_tcase(testcase_t *tcase)
{
	printk(KERN_ERR "jobnum %d; maxthd %d; pool_min %d; queue_min %d\n",
			tcase->jobnum, tcase->pool_maxthreadcnt,
			tcase->pool_threadcnt, tcase->queue_minthreadcnt);

}

static inline void rand_buffer_sampling(unsigned char *buf, const long buffer_size)
{
	long i;
	int interval = 111;

	interval = buffer_size / interval;

	for (i = 0; i < buffer_size; i += interval + 1)
		buf[i] = i * 11 % 256;
}

static inline void printf_digest(unsigned char *digest, int len)
{
	char *buffer;
	int i, j = 0;
	int buf_len;

	buf_len = len * 3 + 1;
	buffer = kmem_alloc(buf_len, KM_SLEEP);
	for (i = 0; i < len; i++){
		j += snprintf(buffer + j, buf_len - j, "%3x", digest[i]);
	}
	//snprintf(buffer + j, buf_len -j, 0);
	printk(KERN_ERR "digest: %s", buffer);

	kmem_free(buffer, len * 3 + 1);
}

static inline int digest_compare(unsigned char *digestA, unsigned char *digestB, int len)
{
	int i;

	for(i = 0; i < len; i++){
		if(digestA[i] != digestB[i]){
			printf_digest(digestA, len);
			printf_digest(digestB, len);
			return 1;
		}
	}

	return 0;
}

typedef struct inform{
	spinlock_t lock;
	struct completion cmpt;
	int count;
	int threshold;
}inform_t;

void inform_init(inform_t **ifm_r, int threshold)
{
	inform_t *ifm;

	ifm = (inform_t *)kmem_alloc(sizeof(*ifm), KM_SLEEP);
	*ifm_r = ifm;

	spin_lock_init(&ifm->lock);
	init_completion(&ifm->cmpt);
	ifm->count = 0;
	ifm->threshold = threshold;
}

void inform_fini(inform_t *ifm)
{
	kmem_free(ifm, sizeof(*ifm));
}

void sha256_multi_task_cb(mbtp_task_t *tj, void *arg)
{
	inform_t *ifm = (inform_t*) arg;
	unsigned long flags;

	spin_lock_irqsave(&ifm->lock, flags);
	ifm->count++;
	if(ifm->count >= ifm->threshold && !(ifm->count % ifm->threshold)) {
		printk(KERN_ERR "this is count %d\n", ifm->count);
		complete(&ifm->cmpt);
	}
	spin_unlock_irqrestore(&ifm->lock, flags);
}

void zfs_SHA256(const void *buf, uint64_t size, unsigned char *digest);


#include <linux/time.h>

/*
 * time measurement and performance computation
 */
struct perf{
        struct timeval tv;
};


inline int perf_start(struct perf *p)
{
        do_gettimeofday(&(p->tv));
        return 0;
}
inline int perf_stop(struct perf *p)
{
    do_gettimeofday(&(p->tv));
        return 0;
}

inline void perf_print(struct perf stop, struct perf start, long long dsize)
{
        long long secs = stop.tv.tv_sec - start.tv.tv_sec;
        long long usecs = secs * 1000000 + stop.tv.tv_usec - start.tv.tv_usec;

        if (dsize != 0) {
                printk(KERN_ERR "runtime = %10lld usecs, bandwidth %lld MB"
                        " in %lld msec = %lld MB/s\n", usecs, dsize/(1024*1024),
                        usecs/1000,  dsize/usecs);
        }
}


/******************************************************************************
 *
 * task test cases
 *
 *****************************************************************************/

void one_task_test()
{
	int threadcnt = 2;
	int max_threadcnt = 5;
	char namep[] = "sha256mb-pool";
	char nameq[] = "sha256mb-queue";
	int rc, i;

	unsigned char digests[8 * 4];
	unsigned char digests_ref[8 * 4];
	unsigned char msg1[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	size_t size = strlen(msg1);

	mulbuf_thdpool_t *pool;
	int nqueue = 1;
	mbtp_queue_t **queue_array;

	queue_array = kmem_alloc(sizeof(mbtp_queue_t *) * nqueue, KM_PUSHPAGE);

	printk(KERN_ERR "spl: pool_queue_init_fini_test");
	printk(KERN_ERR "sha256-pool create");
	rc = mulbuf_thdpool_create(&pool, namep, threadcnt, max_threadcnt);

	for (i = 0; i < nqueue; i++) {
		mbtp_queue_create(&queue_array[i], nameq, pool,
				6, 10, mulbuf_sha256_fn);
		printk(KERN_ERR "sha256-queue %d %p create", i, queue_array[i]);
	}

	zfs_SHA256(msg1, size, digests_ref);
	rc = mulbuf_sha256_queue_choose(msg1, size, digests, queue_array[0]);
	 printf_digest(digests, 32);
	 digest_compare(digests, digests_ref, 32);


	for (i = 0; i < nqueue; i++) {
		printk(KERN_ERR "sha256-queue %d %p destroy", i, queue_array[i]);
		mbtp_queue_destroy(queue_array[i]);
	}

	kmem_free(queue_array, sizeof(mbtp_queue_t *) * nqueue);

	printk(KERN_ERR "sha256-pool destroy");
	mulbuf_thdpool_destroy(pool);

	printk(KERN_ERR "spl: pool_init_fini_test passed");

	return;
}


void tases_test(testcase_t *tcase)
{
	int threadcnt = tcase->pool_threadcnt;
	int max_threadcnt = tcase->pool_maxthreadcnt;
	int min_threadcnt = tcase->queue_minthreadcnt;
	int tasknum = tcase->jobnum;

	char namep[] = "sha256mb-pool";
	char nameq[] = "sha256mb-queue";
	int rc, i;

	unsigned char **digests_array;
	unsigned char **digests_ref_array;
	unsigned char **msgs_array;
	size_t size;

	mulbuf_thdpool_t *pool;
	int nqueue = 1;
	mbtp_queue_t **queue_array;
	mbtp_task_t *tj_array;

	inform_t *ifm;

	inform_init(&ifm, tasknum);


	digests_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);
	digests_ref_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);
	msgs_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);

	tj_array = kmem_alloc(sizeof(mbtp_task_t) * tasknum, KM_SLEEP);

	queue_array = kmem_alloc(sizeof(mbtp_queue_t *) * nqueue, KM_SLEEP);

	printk(KERN_ERR "sha256-pool create");
	rc = mulbuf_thdpool_create(&pool, namep, threadcnt, max_threadcnt);

	for (i = 0; i < nqueue; i++) {
		mbtp_queue_create(&queue_array[i], nameq, pool,
				6, 10, mulbuf_sha256_fn);
		printk(KERN_ERR "sha256-queue %d %p create", i, queue_array[i]);
	}

	for (i = 0; i < tasknum; i++) {
		digests_array[i] = kmem_alloc(sizeof(unsigned char) * 32, KM_SLEEP);
		digests_ref_array[i] = kmem_alloc(sizeof(unsigned char) * 32, KM_SLEEP);

		size = (i + 1) * 64 * 1024;
		msgs_array[i] = vmalloc(size);
		rand_buffer_sampling(msgs_array[i], size);

		zfs_SHA256(msgs_array[i], size, digests_ref_array[i]);

		tj_array[i].buffer = msgs_array[i];
		tj_array[i].size = size;
		tj_array[i].digest = digests_array[i];
		tj_array[i].processsed = 0;

		tj_array[i].cb_fn = sha256_multi_task_cb;
		tj_array[i].cb_arg = ifm;

		mbtp_queue_submit_job(&tj_array[i], queue_array[0]);
	}

	wait_for_completion(&ifm->cmpt);

	for (i = 0; i < tasknum; i++) {
		digest_compare(digests_array[i], digests_ref_array[i], 32);

		kmem_free(digests_array[i], sizeof(unsigned char) * 32);
		kmem_free(digests_ref_array[i], sizeof(unsigned char) * 32);

		size = (i+1) * 64 * 1024;
		vfree(msgs_array[i]);
	}

	kmem_free(digests_array , sizeof(void *) * tasknum);
	kmem_free(digests_ref_array, sizeof(void *) * tasknum);
	kmem_free(msgs_array, sizeof(void *) * tasknum);

	kmem_free(tj_array, sizeof(mbtp_task_t) * tasknum);

	inform_fini(ifm);

	for (i = 0; i < nqueue; i++) {
		printk(KERN_ERR "sha256-queue %d %p destroy", i, queue_array[i]);
		mbtp_queue_destroy(queue_array[i]);
	}

	kmem_free(queue_array, sizeof(mbtp_queue_t *) * nqueue);

	printk(KERN_ERR "sha256-pool destroy");
	mulbuf_thdpool_destroy(pool);


	return;
}


void tasks_test(void)
{
	int i;
	testcase_t *tcase;
	//testcase_t tcase_a[]={{1,1,1,1}};
	testcase_t tcase_a[] = {
			/* single thread test */
			{1, 1, 1, 1}, {2, 1, 1, 1}, {7, 1, 1, 1}, {8, 1, 1, 1},
			{9, 1, 1, 1}, {10, 1, 1, 1}, {16, 1, 1, 1}, {17, 1, 1, 1},
			{11, 1, 1, 1}, {20, 1, 1, 1}, {201, 1, 1, 1}, {201, 1, 1, 1},
			/* multi pool thread test */
			{1, 1, 4, 1}, {2, 1, 4, 1}, {7, 1, 4, 1}, {8, 1, 4, 1},
			{9, 1, 4, 1}, {10, 1, 4, 1}, {16, 1, 4, 1}, {17, 1, 4, 1},
			{11, 1, 4, 1}, {20, 1, 4, 1}, {201, 1, 4, 1}, {201, 1, 4, 1},
			/* multi pool thread test */
			{1, 3, 8, 4}, {2, 3, 8, 4}, {7, 3, 8, 4}, {8, 3, 8, 4},
			{9, 3, 8, 4}, {10, 3, 8, 4}, {16, 3, 8, 4}, {17, 3, 8, 4},
			{11, 3, 8, 4}, {20, 3, 8, 4}, {201, 3, 8, 4}, {201, 3, 8, 4}

	};

	for(i = 0; i < sizeof(tcase_a)/sizeof(tcase_a[0]) ; i++){
		tcase = &tcase_a[i];
		printf_tcase(tcase);
		tases_test(tcase);
	}

	printk(KERN_ERR "tasks_test is passed\n");
	return;
}

int thread_task(void *arg)
{
	unsigned char digests[32];
	unsigned char *msg;
	int size = (int)arg;

	while(!kthread_should_stop()){
		msg = vmalloc(size);
		if(!msg){
			printk(KERN_ERR "thread test mem allocation error");
		}else {
			//printk(KERN_ERR "msg %p, size %d ", msg, size);
			mulbuf_sha256(msg, size, digests);

			vfree(msg);
		}
	}

	return 0;
}
#define Nthread	40
void threads_task_test()
{

	struct task_struct	*threads[Nthread];

	int size = 128 * 1024;
	int i;


	printk(KERN_ERR "sha256-pool threads_task_test");


	printk(KERN_ERR "sha256-pool threads create");
	for (i = 0; i < Nthread; i++){
		threads[i] = spl_kthread_create(thread_task, size,
		    "%s", "mulbuf-test-thread");
	}


	printk(KERN_ERR "sha256-pool threads wakeup");
	for (i = 0; i < Nthread; i++){
		wake_up_process(threads[i]);
	}

	msleep(1000);

	printk(KERN_ERR "sha256-pool threads stop");
	for (i = 0; i < Nthread; i++){

		kthread_stop(threads[i]);
	}

}

void tases_perf(testcase_t *tcase)
{
	int threadcnt = tcase->pool_threadcnt;
	int max_threadcnt = tcase->pool_maxthreadcnt;
	int min_threadcnt = tcase->queue_minthreadcnt;
	int tasknum = tcase->jobnum;

	char namep[] = "sha256mb-pool";
	char nameq[] = "sha256mb-queue";
	int rc, i;

	unsigned char **digests_array;
	unsigned char **digests_ref_array;
	unsigned char **msgs_array;
	size_t size;

	struct perf start, stop;

	mulbuf_thdpool_t *pool;
	int nqueue = 1;
	mbtp_queue_t **queue_array;
	mbtp_task_t *tj_array;

	inform_t *ifm;

	inform_init(&ifm, tasknum);


	digests_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);
	digests_ref_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);
	msgs_array = kmem_alloc(sizeof(void *) * tasknum, KM_SLEEP);

	tj_array = kmem_alloc(sizeof(mbtp_task_t) * tasknum, KM_SLEEP);

	queue_array = kmem_alloc(sizeof(mbtp_queue_t *) * nqueue, KM_SLEEP);

	printk(KERN_ERR "sha256-pool create");
	rc = mulbuf_thdpool_create(&pool, namep, threadcnt, max_threadcnt);

	for (i = 0; i < nqueue; i++) {
		mbtp_queue_create(&queue_array[i], nameq, pool,
				6, 10, mulbuf_sha256_fn);
		printk(KERN_ERR "sha256-queue %d %p create", i, queue_array[i]);
	}

	for (i = 0; i < tasknum; i++) {
		digests_array[i] = kmem_alloc(sizeof(unsigned char) * 32, KM_SLEEP);
		digests_ref_array[i] = kmem_alloc(sizeof(unsigned char) * 32, KM_SLEEP);

		size = (7+1) * 64 * 1024;
		msgs_array[i] = vmalloc(size);
		rand_buffer_sampling(msgs_array[i], size);
	}

	perf_start(&start);
	for (i = 0; i < tasknum; i++) {
		zfs_SHA256(msgs_array[i], size, digests_ref_array[i]);
	}
	perf_stop(&stop);
    printk(KERN_INFO "sha256 ori" ": ");
    perf_print(stop, start, size * i);


	perf_start(&start);
	for (i = 0; i < tasknum; i++) {

		tj_array[i].buffer = msgs_array[i];
		tj_array[i].size = size;
		tj_array[i].digest = digests_array[i];
		tj_array[i].processsed = 0;

		tj_array[i].cb_fn = sha256_multi_task_cb;
		tj_array[i].cb_arg = ifm;

		mbtp_queue_submit_job(&tj_array[i], queue_array[0]);
	}
	wait_for_completion(&ifm->cmpt);

	perf_stop(&stop);
    printk(KERN_INFO "sha256 mb" ": ");
    perf_print(stop, start, size * i);

	for (i = 0; i < tasknum; i++) {
		digest_compare(digests_array[i], digests_ref_array[i], 32);

		kmem_free(digests_array[i], sizeof(unsigned char) * 32);
		kmem_free(digests_ref_array[i], sizeof(unsigned char) * 32);

		size = (i+1) * 64 * 1024;
		vfree(msgs_array[i]);
	}

	kmem_free(digests_array , sizeof(void *) * tasknum);
	kmem_free(digests_ref_array, sizeof(void *) * tasknum);
	kmem_free(msgs_array, sizeof(void *) * tasknum);

	kmem_free(tj_array, sizeof(mbtp_task_t) * tasknum);

	inform_fini(ifm);

	for (i = 0; i < nqueue; i++) {
		printk(KERN_ERR "sha256-queue %d %p destroy", i, queue_array[i]);
		mbtp_queue_destroy(queue_array[i]);
	}

	kmem_free(queue_array, sizeof(mbtp_queue_t *) * nqueue);

	printk(KERN_ERR "sha256-pool destroy");
	mulbuf_thdpool_destroy(pool);


	return;
}

void tasks_perf(void)
{
	int i;
	testcase_t *tcase;
	testcase_t tcase_a[] = {
			/* single thread test */
			{11, 1, 1, 1}, {20, 1, 1, 1}, {201, 1, 1, 1}, {201, 1, 1, 1},
			/* multi pool thread test */
			{11, 1, 4, 1}, {20, 1, 4, 1}, {201, 1, 4, 1}, {201, 1, 4, 1},

	};

	for(i = 0; i < sizeof(tcase_a)/sizeof(tcase_a[0]) ; i++){
		tcase = &tcase_a[i];
		printf_tcase(tcase);
		tases_perf(tcase);
	}

	printk(KERN_ERR "tasks_perf is passed\n");
	return;
}

/*
 * SHA-256 checksum, as specified in FIPS 180-3, available at:
 * http://csrc.nist.gov/publications/PubsFIPS.html
 *
 * This is a very compact implementation of SHA-256.
 * It is designed to be simple and portable, not to be fast.
 */

/*
 * The literal definitions of Ch() and Maj() according to FIPS 180-3 are:
 *
 * 	Ch(x, y, z)     (x & y) ^ (~x & z)
 * 	Maj(x, y, z)    (x & y) ^ (x & z) ^ (y & z)
 *
 * We use equivalent logical reductions here that require one less op.
 */
#define	Ch(x, y, z)	((z) ^ ((x) & ((y) ^ (z))))
#define	Maj(x, y, z)	(((x) & (y)) ^ ((z) & ((x) ^ (y))))
#define	Rot32(x, s)	(((x) >> s) | ((x) << (32 - s)))
#define	SIGMA0(x)	(Rot32(x, 2) ^ Rot32(x, 13) ^ Rot32(x, 22))
#define	SIGMA1(x)	(Rot32(x, 6) ^ Rot32(x, 11) ^ Rot32(x, 25))
#define	sigma0(x)	(Rot32(x, 7) ^ Rot32(x, 18) ^ ((x) >> 3))
#define	sigma1(x)	(Rot32(x, 17) ^ Rot32(x, 19) ^ ((x) >> 10))

static const uint32_t SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
SHA256Transform(uint32_t *H, const uint8_t *cp)
{
	uint32_t a, b, c, d, e, f, g, h, t, T1, T2, W[64];

	for (t = 0; t < 16; t++, cp += 4)
		W[t] = (cp[0] << 24) | (cp[1] << 16) | (cp[2] << 8) | cp[3];

	for (t = 16; t < 64; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] +
		    sigma0(W[t - 15]) + W[t - 16];

	a = H[0]; b = H[1]; c = H[2]; d = H[3];
	e = H[4]; f = H[5]; g = H[6]; h = H[7];

	for (t = 0; t < 64; t++) {
		T1 = h + SIGMA1(e) + Ch(e, f, g) + SHA256_K[t] + W[t];
		T2 = SIGMA0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
	}

	H[0] += a; H[1] += b; H[2] += c; H[3] += d;
	H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

void zfs_SHA256(const void *buf, uint64_t size, unsigned char *digest)
{
	uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	uint8_t pad[128];
	int i, padsize;

	for (i = 0; i < (size & ~63ULL); i += 64)
		SHA256Transform(H, (uint8_t *)buf + i);

	for (padsize = 0; i < size; i++)
		pad[padsize++] = *((uint8_t *)buf + i);

	for (pad[padsize++] = 0x80; (padsize & 63) != 56; padsize++)
		pad[padsize] = 0;

	for (i = 56; i >= 0; i -= 8)
		pad[padsize++] = (size << 3) >> i;

	for (i = 0; i < padsize; i += 64)
		SHA256Transform(H, pad + i);

	*(uint64_t *)&digest[0] = (uint64_t)H[0] << 32 | H[1];
	*(uint64_t *)&digest[8] = (uint64_t)H[2] << 32 | H[3];
	*(uint64_t *)&digest[16] = (uint64_t)H[4] << 32 | H[5];
	*(uint64_t *)&digest[24] = (uint64_t)H[6] << 32 | H[7];
}
