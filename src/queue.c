#include "queue.h"

queue_t* queue_alloc(uint32_t capacity) {
	queue_t *res = (queue_t*) malloc(sizeof(queue_t));
	res->nodes = (node_t*) malloc(capacity * sizeof(node_t));
	res->head = 0;
	res->tail = -1;

	res->size = 0;
	res->capacity = capacity;

	return res;
}

void queue_free(queue_t *queue) {
	free(queue->nodes);
	free(queue);
}

node_t* queue_enqueue(queue_t *queue, int key, data_t data) {
	if (queue->size == queue->capacity) // overflow
		return NULL;
	queue->tail = (queue->tail + 1) % queue->capacity;

	node_t *node = &(queue->nodes[queue->tail]);
	node->data = data;
	node->key = key;
	
	queue->size++;

	return node;
}

void queue_dequeue_head(queue_t *queue) {
	if (queue->size == 0)
		return;

	queue->size--;
	queue->head = (queue->head + 1) % queue->capacity;
}

void queue_dequeue_tail(queue_t *queue) {
	if (queue->size == 0)
		return;

	queue->size--;
	queue->tail = (queue->tail - 1) % queue->capacity;
}

void queue_drop(queue_t* queue) {
	queue->head = 0;
	queue->tail = -1;

	queue->size = 0;
}