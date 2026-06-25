#ifndef UDP_BROADCAST_H
#define UDP_BROADCAST_H

#include <pthread.h>

pthread_t *start_advertising() ;
void stop_advertising(pthread_t thread_id);

#endif

