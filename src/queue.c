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

void queue_log(queue_t *queue) {
	int itr = queue_itr_begin(queue);

	while (queue_itr_has_next(queue, itr)) {
		node_t *node = queue_itr_next(queue, &itr);
		printf("(%d)->", node->key);
	}
	printf("x\n");
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

node_t* queue_itr_next(queue_t* queue, int* itr) {
	if (!queue_itr_has_next(queue, *itr))
		return NULL;

	int prev = *itr;
	*itr = (*itr + 1) % queue->capacity;

	if (queue_node(queue, *itr) == queue_head(queue))
		*itr = -1;
	return queue_node(queue, prev);
}