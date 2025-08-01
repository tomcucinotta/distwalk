#include <stdio.h>
#include <stdbool.h>

#include "queue.h"
#include "dw_debug.h"
#include "ccmd.h"
#include "distrib.h"

#define N 100


bool test_queue_insert() {
	queue_t *queue = queue_alloc(N);

	data_t data = {.value=10};
	queue_enqueue(queue, 0, data);
	
	data_t data2 = {.value=20};
	queue_enqueue(queue, 1, data2);

	node_t *top = queue_head(queue);
	if (queue_node_key(top) != 0 || queue_node_data(top).value != 10)
		goto err;

	node_t *bottom = queue_tail(queue);
	if (queue_node_key(bottom) != 1 || queue_node_data(bottom).value != 20)
		goto err;

	if (queue_size(queue) != 2)
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_insert_complex() {
	queue_t *queue = queue_alloc(N);

	ccmd_node_t* ccmd_node = calloc(1, sizeof(ccmd_node_t));
	pd_spec_t val = pd_build_fixed(1000);

	ccmd_node->cmd = STORE;
	ccmd_node->pd_val = val;

	data_t data = {.ptr=ccmd_node};
	queue_enqueue(queue, 0, data);

	node_t *top = queue_head(queue);
	ccmd_node_t* ccmd_data = queue_node_data(top).ptr;

	if (queue_node_key(top) != 0 || ccmd_data->cmd != STORE)
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_remove() {
	queue_t *queue = queue_alloc(N);

	data_t data = {.value=10};
	queue_enqueue(queue, 0, data);
	
	data_t data2 = {.value=20};
	queue_enqueue(queue, 1, data2);


	queue_dequeue_head(queue);
	node_t *top = queue_head(queue);
	node_t *bottom = queue_tail(queue);

	if (top != bottom 
		|| queue_node_key(bottom) != 1 
		|| queue_node_data(bottom).value != 20
		|| queue_size(queue) != 1)
		goto err;

	queue_dequeue_head(queue);
	queue_dequeue_tail(queue);
	queue_dequeue_head(queue);
	queue_dequeue_tail(queue);

	if (queue_size(queue) != 0)
		goto err;

	if (queue_head(queue)!= NULL 
		|| queue_tail(queue) !=NULL)
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_remove_complex() {
	queue_t *queue = queue_alloc(N);

	for (int i=0; i < 2; i ++) {
		ccmd_node_t* ccmd_node = calloc(1, sizeof(ccmd_node_t));
		pd_spec_t val = pd_build_fixed(i * 10);

		ccmd_node->cmd = STORE;
		ccmd_node->pd_val = val;

		data_t data = {.ptr=ccmd_node};
		queue_enqueue(queue, i, data);
	}

	queue_dequeue_head(queue);
	node_t *top = queue_head(queue);
	node_t *bottom = queue_tail(queue);
	ccmd_node_t* ccmd_data = queue_node_data(bottom).ptr;

	if (top != bottom 
		|| queue_node_key(bottom) != 1
		|| ccmd_data->cmd != STORE
		|| ccmd_data->pd_val.val != 10
		|| queue_size(queue) != 1)
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_capacity() {
	queue_t *queue = queue_alloc(5);

	// accepted data
	for (int i=0; i < queue_capacity(queue); i++) {
		data_t data = {.value=i*10};
		queue_enqueue(queue, i, data);
	}

	// discarded data
	for (int i=0; i < N; i++) {
		data_t data = {.value=i*100};
		queue_enqueue(queue, i, data);
	}

	int i = queue_size(queue) - 1;
	while(queue_size(queue) > 0) {
		if (queue_node_key(queue_tail(queue)) != i
			|| queue_node_data(queue_tail(queue)).value != i*10)
			goto err;
		queue_dequeue_tail(queue);
		i--;
	}

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_drop() {
	queue_t *queue = queue_alloc(20);

	// accepted data
	for (int i=0; i < queue_capacity(queue); i++) {
		data_t data = {.value=i*10};
		queue_enqueue(queue, i, data);
	}

	queue_drop(queue);

	if (queue_head(queue) != NULL || queue_tail(queue) != NULL)
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_iterator_1() {
	queue_t *queue = queue_alloc(20);
	for (int i=0; i < queue_capacity(queue); i++) {
		data_t data = {.value=i*10};
		queue_enqueue(queue, i, data);
	}

	int itr = queue_itr_begin(queue);
	for (int i = 0; i < queue_size(queue); i++) {
		node_t *node = queue_itr_next(queue, &itr);

		if (queue_node_key(node) != i || queue_node_data(node).value != i*10)
			goto err;
	}

	if (queue_itr_has_next(queue, itr))
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

bool test_queue_iterator_2() {
	queue_t *queue = queue_alloc(20);
	for (int i=0; i < queue_capacity(queue); i++) {
		data_t data = {.value=i*10};
		queue_enqueue(queue, i, data);
	}

	queue_dequeue_head(queue);
	queue_dequeue_tail(queue);

	int itr = queue_itr_begin(queue);
	for (int i = 0; i < queue_size(queue); i++) {
		node_t *node = queue_itr_next(queue, &itr);

		if (queue_node_key(node) != i+1
			|| queue_node_data(node).value != (i+1)*10)
			goto err;
	}

	if (queue_itr_has_next(queue, itr))
		goto err;

	queue_free(queue);
	return true;

 err:
	queue_free(queue);
	return false;
}

int main() {
	bool rv = true;
	rv &= perform_test(test_queue_insert());
	rv &= perform_test(test_queue_insert_complex());
	rv &= perform_test(test_queue_remove());
	rv &= perform_test(test_queue_remove_complex());
	rv &= perform_test(test_queue_capacity());
	rv &= perform_test(test_queue_drop());
	rv &= perform_test(test_queue_iterator_1());
	rv &= perform_test(test_queue_iterator_2());
	return rv ? EXIT_SUCCESS : EXIT_FAILURE;
}
