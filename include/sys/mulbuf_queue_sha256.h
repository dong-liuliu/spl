/*
 * mulbuf_queue_sha256.h
 *
 *  Created on: Aug 14, 2017
 *      Author: root
 */

#ifndef MULBUF_QUEUE_SHA256_H_
#define MULBUF_QUEUE_SHA256_H_

#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <sys/kmem.h>

#include <sys/mulbuf_queue.h>

void mulbuf_sha256_fn(void *args);

int mulbuf_queue_sha256_init(void);
void mulbuf_queue_sha256_fini(void);

int mulbuf_sha256(void *buffer, size_t size, unsigned char *digest, mbtp_queue_t *queue);

#endif /* MULBUF_QUEUE_SHA256_H_ */
