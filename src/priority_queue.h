#ifndef __PRIORTITY_QUEUE_H__
#define __PRIORTITY_QUEUE_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "queueing_common.h"

typedef struct pqueue_t {
	node_t *nodes;
	uint32_t *heap;
	uint32_t *stack;
	int size, capacity;
} pqueue_t;

pqueue_t* pqueue_alloc(uint32_t capacity);
void pqueue_free(pqueue_t *queue);

node_t* pqueue_insert(pqueue_t *queue, int key, data_t data);
void pqueue_remove(pqueue_t *queue, node_t *node);
void pqueue_pop(pqueue_t *queue);

static inline int pqueue_size(pqueue_t *queue) { return queue->size; }
static inline int pqueue_capacity(pqueue_t *queue) { return queue->capacity; }
static inline node_t* pqueue_top(pqueue_t *queue) { return (!queue->size) ? NULL : &queue->nodes[queue->heap[0]]; }

static inline data_t pqueue_node_data(node_t *node) { return node->data; }
static inline int pqueue_node_key(node_t *node) { return node->key; }

#endif /* __PRIORITY_QUEUE_H__ */
