#ifndef __AFF_H__
#define __AFF_H__

#include <sched.h>

void aff_list_parse(char *str, cpu_set_t* mask, int ncpu);
int  aff_pin_to(int core_id);

int  aff_it_init(cpu_set_t* mask, int ncpu);
void aff_it_next(int* it, cpu_set_t* mask, int ncpu);

#endif /* __AFF_H__ */
