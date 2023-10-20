#include <stdio.h>
#include <stdbool.h>
#include "priority_queue.h"

#define N 100

bool check(pqueue_t *queue, int arr[N], pqueue_node_t *nodes[N]){
	int temp_arr[N], n = pqueue_size(queue);

	for(int i = 0; i < n; i++){
		pqueue_node_t *top = pqueue_top(queue);

		int min_value = 10000000, min_index = 0;
		for(int j = 0; j < n - i; j++){
			if(min_value > arr[j]){
				min_value = arr[j];
				min_index = j;
			}
		}

		if(pqueue_node_key(top) != min_value)
			return false;
		temp_arr[i] = arr[min_index];
		arr[min_index] = arr[n - i - 1];

		pqueue_remove(queue, top);
	}

	for(int i = 0; i < n; i++){
		data_t data = {.value=0};
		arr[i] = temp_arr[i];
		nodes[i] = pqueue_insert(queue, arr[i], data);
	}
	
	return true;
}

bool check_pqueue(){
	pqueue_t *queue = pqueue_alloc(N);
	pqueue_node_t *nodes[N];
	int arr[N];
	int n = 0, insert = 0, remove = 0, checks = 0;

	for(int i = 0; i < 1000; i++){
		int rnd = rand() % 100;
		data_t data = {.value=0};

		if(rnd < 30 && n < N) {
			arr[n] = rand() % 100;
			nodes[n] = pqueue_insert(queue, arr[n], data);
			n++;
			insert++;
		} else if(rnd < 60 && n > 0){
			int idx = rand() % n;
			pqueue_remove(queue, nodes[idx]);
			nodes[idx] = nodes[n - 1];
			arr[idx] = arr[n - 1];
			n--;
			remove++;
		} else {
			bool ret = check(queue, arr, nodes);
			checks++;
			if(!ret)
				goto err;
		}
	}

	bool ret = check(queue, arr, nodes);
	if(!ret)
		goto err;

	pqueue_free(queue);
	return true;
err:
	pqueue_free(queue);
	return false;
}

#define perform_test(fun)            \
	{                                \
		bool res = fun;              \
		printf("TEST " #fun ": ");  \
		if(res)                      \
			printf("SUCCESS");       \
		else                         \
			printf("FAILED");        \
	}     

int main(){

	perform_test( check_pqueue() );
	return 0;
}