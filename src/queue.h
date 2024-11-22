#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "queueing_common.h"

typedef struct queue_t {
	node_t *nodes;
	int head, tail;
	int size, capacity;
} queue_t;

queue_t* queue_alloc(uint32_t capacity);
void queue_free(queue_t *queue);

node_t* queue_enqueue(queue_t *queue, int key, data_t data);
void queue_dequeue_head(queue_t *queue);
void queue_dequeue_tail(queue_t *queue);
void queue_drop(queue_t* queue);

static inline int queue_size(queue_t *queue) { return queue->size; }
static inline int queue_capacity(queue_t *queue) { return queue->capacity; }
static inline node_t* queue_head(queue_t *queue) { return (!queue->size) ? NULL : &queue->nodes[queue->head]; }
static inline node_t* queue_tail(queue_t *queue) { return (!queue->size) ? NULL : &queue->nodes[queue->tail]; }

static inline data_t queue_node_data(node_t *node) { return node->data; }
static inline int queue_node_key(node_t *node) { return node->key; }

#endif /* __QUEUE_H__ */
