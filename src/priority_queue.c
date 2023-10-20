#include "priority_queue.h"

struct pqueue_node_t{
	uint32_t heap_id;
	int key;
	data_t data;
};

struct pqueue_t{
	pqueue_node_t *nodes;
	uint32_t *heap;
	uint32_t *stack;
	int size, container_size;
};

pqueue_t* pqueue_alloc(uint32_t container_size){
	pqueue_t *res = (pqueue_t*) malloc(sizeof(pqueue_t));
	res->nodes = (pqueue_node_t*) malloc(container_size * sizeof(pqueue_node_t));
	res->heap  = (uint32_t*) malloc(container_size * sizeof(uint32_t));
	res->stack = (uint32_t*) malloc(container_size * sizeof(uint32_t));
	res->size = 0;
	res->container_size = container_size;

	for(int i = 0; i < container_size; i++) {
		res->stack[i] = i;
	}

	return res;
}

void pqueue_free(pqueue_t *queue){
	free(queue->nodes);
	free(queue->heap);
	free(queue->stack);
}

static void swap_node(pqueue_t *queue, pqueue_node_t *node0, pqueue_node_t *node1){
	uint32_t i0 = node0->heap_id, i1 = node1->heap_id;

	uint32_t temp = queue->heap[i0];
	queue->heap[i0] = queue->heap[i1];
	queue->heap[i1] = temp;

	node0->heap_id = i1;
	node1->heap_id = i0;
}

static pqueue_node_t* get_parent_node(pqueue_t *queue, pqueue_node_t* node){
	if(node->heap_id == 0)
		return NULL;
	uint32_t parent_idx = (node->heap_id - 1) / 2;
	return &queue->nodes[queue->heap[parent_idx]];
}

static pqueue_node_t* get_child_node(pqueue_t *queue, pqueue_node_t* node){
	uint32_t child1_idx, child2_idx;
	child1_idx = 2 * node->heap_id + 1;
	child2_idx = 2 * node->heap_id + 2;
	if(child1_idx >= queue->size)
		return NULL;
	if(child2_idx >= queue->size)
		return &queue->nodes[queue->heap[child1_idx]];
	pqueue_node_t *child1, *child2;
	child1 = &queue->nodes[queue->heap[child1_idx]];
	child2 = &queue->nodes[queue->heap[child2_idx]];
	return child1->key < child2->key ? child1 : child2;
}

static uint32_t get_node_id(pqueue_t *queue, pqueue_node_t *node){
	return (node - queue->nodes);
}

static void up(pqueue_t *queue, pqueue_node_t *node){
	pqueue_node_t *curr_node, *parent_node;

	curr_node = node;
	parent_node = get_parent_node(queue, curr_node);

	while(parent_node && parent_node->key > curr_node->key){
		swap_node(queue, parent_node, curr_node);

		parent_node = get_parent_node(queue, curr_node);
	}
}

static void down(pqueue_t *queue, pqueue_node_t *node){
	pqueue_node_t *curr_node, *child_node;

	curr_node = node;
	child_node = get_child_node(queue, node);

	while(child_node && child_node->key < curr_node->key){
		swap_node(queue, child_node, curr_node);

		child_node = get_child_node(queue, curr_node);
	}
}

pqueue_node_t* pqueue_insert(pqueue_t *queue, int key, data_t data){
	int node_id = queue->stack[queue->container_size - queue->size - 1];
	pqueue_node_t *node = &(queue->nodes[node_id]);

	node->data = data;
	node->key = key;
	node->heap_id = queue->size;
	queue->heap[queue->size] = node_id;
	queue->size++;

	up(queue, node);

	return node;
}

void pqueue_remove(pqueue_t *queue, pqueue_node_t *node){
	queue->size--;
	queue->heap[node->heap_id] = queue->heap[queue->size];
	queue->nodes[queue->heap[node->heap_id]].heap_id = node->heap_id;

	queue->stack[queue->container_size - queue->size - 1] = get_node_id(queue, node);

	pqueue_node_t *curr_node = &queue->nodes[queue->heap[node->heap_id]];
	up(queue, curr_node);
	down(queue, curr_node);
}

void pqueue_pop(pqueue_t *queue){
	pqueue_node_t *node = pqueue_top(queue);
	queue->size--;
	queue->heap[node->heap_id] = queue->heap[queue->size];
	queue->nodes[queue->heap[node->heap_id]].heap_id = node->heap_id;

	queue->stack[queue->container_size - queue->size - 1] = get_node_id(queue, node);

	pqueue_node_t *curr_node = &queue->nodes[queue->heap[node->heap_id]];
	down(queue, curr_node);
}

int pqueue_size(pqueue_t *queue){
	return queue->size;
}

pqueue_node_t* pqueue_top(pqueue_t *queue){
	return (!queue->size) ? NULL : &queue->nodes[queue->heap[0]];
}

data_t pqueue_node_data(pqueue_node_t *node){
	return node->data;
}

int pqueue_node_key(pqueue_node_t *node){
	return node->key;
}