#ifndef PRIORTITY_QUEUE_H
#define PRIORTITY_QUEUE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

typedef union {
	int fd;
	uint64_t value;
	void *ptr;
} data_t;

struct pqueue_node_t;
struct pqueue_t;

typedef struct pqueue_node_t pqueue_node_t;
typedef struct pqueue_t pqueue_t;

pqueue_t* pqueue_alloc(uint32_t container_size);
void pqueue_free(pqueue_t *queue);

pqueue_node_t* pqueue_insert(pqueue_t *queue, int key, data_t data);
void pqueue_remove(pqueue_t *queue, pqueue_node_t *node);
void pqueue_pop(pqueue_t *queue);

int pqueue_size(pqueue_t *queue);
pqueue_node_t* pqueue_top(pqueue_t *queue);

data_t pqueue_node_data(pqueue_node_t *node);
int pqueue_node_key(pqueue_node_t *node);

#endif