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

#endif /* MULBUF_QUEUE_SHA256_H_ */
