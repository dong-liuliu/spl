/*
 * mulbuf_queue_sha256.h
 *
 *  Created on: Aug 14, 2017
 *      Author: root
 */

#ifndef MULBUF_QUEUE_SHA256_H_
#define MULBUF_QUEUE_SHA256_H_

#if defined(__x86_64) && defined(__KERNEL__) && defined(HAVE_HASH_MB)

#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <sys/kmem.h>

#include <sys/mulbuf_queue.h>

void mulbuf_sha256_fn(void *args);

int mulbuf_suite_sha256_init(void);
void mulbuf_suite_sha256_fini(void);

int mulbuf_sha256_queue_choose(void *buffer, size_t size,
		unsigned char *digest, mbtp_queue_t *queue);
int mulbuf_sha256(void *buffer, size_t size, unsigned char *digest);

#else

#define mulbuf_suite_sha256_init	0
#define mulbuf_suite_sha256_fini	0

#endif /* __KERNEL__ && __x86_64 && HAVE_HASH_MB */

#endif /* MULBUF_QUEUE_SHA256_H_ */
