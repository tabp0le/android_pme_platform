
#include <assert.h>
#include <fcntl.h>     
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>     
#include <stdlib.h>    
#include <unistd.h>    


static void* thread_func(void*);



static sem_t* s_sem;

static double s_d1; 
                    
static double s_d2; 
                    
static double s_d3; 
static int    s_debug     = 0;
static int    s_do_printf = 0;
static int    s_do_mutual_exclusion = 0;



int main(int argc, char** argv)
{
  int optchar;
  pthread_t threadid;
  char semaphore_name[32];

  while ((optchar = getopt(argc, argv, "dmp")) != EOF)
  {
    switch (optchar)
    {
    case 'd':
      s_debug = 1;
      break;
    case 'm':
      s_do_mutual_exclusion = 1;
      break;
    case 'p':
      s_do_printf = 1;
      break;
    default:
      assert(0);
    }
  }

  snprintf(semaphore_name, sizeof(semaphore_name), "/drd-sem-open-test-%d",
	   getpid());
  s_sem = sem_open(semaphore_name, O_CREAT | O_EXCL, 0600, 1);
  if (s_sem == SEM_FAILED)
  {
    fprintf(stderr, "Failed to create a semaphore with name %s\n",
            semaphore_name);
    exit(1);
  }

  setlinebuf(stdout);

  if (s_debug)
  {
    printf("&s_d1 = %p; &s_d2 = %p; &s_d3 = %p\n", &s_d1, &s_d2, &s_d3);
  }

  s_d1 = 1;
  s_d3 = 3;

  pthread_create(&threadid, 0, thread_func, 0);

  sleep(1); 

  {
    if (s_do_mutual_exclusion) sem_wait(s_sem);
    s_d3++;
    if (s_do_mutual_exclusion) sem_post(s_sem);
  }

  
  pthread_join(threadid, 0);
  if (s_do_printf) printf("s_d2 = %g (should be 2)\n", s_d2);
  if (s_do_printf) printf("s_d3 = %g (should be 5)\n", s_d3);

  sem_close(s_sem);
  sem_unlink(semaphore_name);

  return 0;
}

static void* thread_func(void* thread_arg)
{
  if (s_do_printf)
  {
    printf("s_d1 = %g (should be 1)\n", s_d1);
  }
  s_d2 = 2;
  {
    if (s_do_mutual_exclusion) sem_wait(s_sem);
    s_d3++;
    if (s_do_mutual_exclusion) sem_post(s_sem);
  }
  return 0;
}
