#define _GNU_SOURCE
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>
#include <err.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <malloc.h>
#include <sys/types.h>
#include <assert.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <endian.h>
#include <byteswap.h>
#include <poll.h>
#include <time.h>

#include "difc_api.h"
#include "defs.h"
#include "seccomp.h"
#include "difc_demos.h"
#include "difc_mem.h"
#include "bpf.h"
#include "bpf-syscall.h"

#include "mpt.h"



#define ITTERATE 10000
#define THREAD_MODE 0
#define FORK_MODE 1
#define UDOM_MODE 2




static volatile int interrupted;
static char *secret_blk;
int glob_test = 10;
char *private_blk;

extern pthread_mutex_t so_mutex; 
struct label_struct cur_label;


static inline unsigned long long time_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts)) {
    exit(1);
  }
  return ((unsigned long long)ts.tv_sec) * 1000000000LLU +
         (unsigned long long)ts.tv_nsec;
}

// Memory we're going to optionally allocating with malloc prioir to launching a
// task. Marked volatile to thwart compiler optimizations.
volatile char* v;

#define min(a, b)                                                              \
  ({                                                                           \
    __typeof__(a) _a = (a);                                                    \
    __typeof__(b) _b = (b);                                                    \
    _a < _b ? _a : _b;                                                         \
  })

void* threadfunc(void* p) {
  (void)p;
 printf("hi\n");
 //set_task_label(0, REPLACE_LABEL, 0, &cur_label);
 syscall(__NR_set_task_label, 0, REPLACE_LABEL, 0, &cur_label);

  return 0;
}

void threadfunc2(void ) {
    
    printf("hi\n");

  return ;
}

int task_func(void *p)
{
      (void)p;

      printf("hi\n");

  /*  printf("[task_func]hello from task_func id %ld\n", (long int)syscall(__NR_gettid));

    char *buf = (char *)arg;
    printf("[task_func]thread recived this buf = \"%s\"\n", buf);

    // strcpy(buf, "hey from your child");
    
    while (1) {
    }
    */
    return 0;
}

void difc_threading_test(void)
{

 // printf("pid = %d\n", getpid());
    const int STACK_SIZE = 8 * 1024;


     int label1 = difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    //if (label1 <= 0)
        //printf("OS capability creation failed\n");
    //else
       // printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    cur_label.sList[0] = (label_t)sec_len;

    for (int i = 0; i < sec_len; i++) {
        cur_label.sList[i + 1] = (label_t)secrecySet[i];
       // printf("[difc_threading_test] cur_label.sList[%d]: %lld \n", (i + 1), cur_label.sList[i + 1]);
    }

    cur_label.iList[0] = (label_t)int_len;

    for (int i = 0; i < int_len; i++) {
        cur_label.iList[i + 1] = (label_t)integritySet[i];
      //  printf("[difc_threading_test] cur_label.iList[%d]: %lld \n", (i + 1), cur_label.iList[i + 1]);
    }


   //difc_replace_labels(secrecySet, sec_len, integritySet, int_len);



  // If mode = 0, measuring pthread launch performance; otherwise
  // measuring fork performance.
  int mode = UDOM_MODE;//FORK_MODE;//THREAD_MODE;//UDOM_MODE;//THREAD_MODE; //mode=1 thread
  void * stackptr=malloc(STACK_SIZE);
  siginfo_t info;
 

  int MEMSIZEMB = 1;
  if (MEMSIZEMB > 0) {
    // Allocate and touch memory to make sure it's paged in.
    int MEMSIZE = MEMSIZEMB * 1e6;
    v = malloc(MEMSIZE);
    if (!v) {
      perror("malloc");
      exit(1);
    }
    for (int i = 0; i < MEMSIZE; ++i) {
      v[i] = i;
    }
  }

  int N = 10000;//10000
  unsigned long long minlaunch = 999999;
  unsigned long long totallaunch = 0;
  unsigned long long minjoin = 999999;
  unsigned long long totaljoin = 0;

  for (int i = 0; i < N; ++i) {
    pthread_t tid;

    unsigned long long t1 = time_ns();
    if (mode==THREAD_MODE) {
      if (pthread_create(&tid, NULL, threadfunc, NULL)) {
        perror("pthread_create");
        exit(1);
      }
    } else if (mode==FORK_MODE) {
      if (fork() == 0) {
        printf("hi\n");
        exit(0);
      }
      // Parent. Fall through to measurement.
    }
    else{//udom mode

     //thread_create(&threadfunc2 , stackptr+STACK_SIZE);
   // udom_thread_create(&threadfunc2 , stackptr+STACK_SIZE,&cur_label);

     if (pthread_create(&tid, NULL, threadfunc, NULL)) {
        perror("pthread_create");
        exit(1);}
    //clone(&task_func , stackptr+STACK_SIZE , CLONE_THREAD | CLONE_SIGHAND | CLONE_VM,NULL);
    

    }
    // Parent process, or thread.
    unsigned long long elapsed = time_ns() - t1;
    minlaunch = min(minlaunch, elapsed);
    totallaunch += elapsed;

    // Let some time pass to not count the actual child running time in
    // elapsed for the teardown.
    usleep(500);

    t1 = time_ns();
    if (mode==THREAD_MODE) {
      if (pthread_join(tid, NULL)) {
        perror("pthread_join");
        exit(1);
      }
    } else if (mode==FORK_MODE){
      if (wait(NULL) == -1) {
        perror("wait");
        exit(1);
      }
    }
    else{//udom mode
     if (pthread_join(tid, NULL)) {
        perror("pthread_join");
        exit(1);
      }
    
//if (waitid(P_ALL, 0, &info, WEXITED) == -1) {
  // perror("waitid");
//}
//pause();
    }
    elapsed = time_ns() - t1;
    minjoin = min(minjoin, elapsed);
    totaljoin += elapsed;
  }

  printf("After %d iterations:\n  minlaunch = %llu\n  minjoin = %llu\n", N,
         minlaunch, minjoin);
  printf("Average:\n  launch = %.2lf\n  join = %.2lf\n",
         (double)totallaunch / N, (double)totaljoin / N);

  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru)) {
    perror("getrusage");
  } else {
    printf("From getrusage:\n");
    printf("  max rss (KiB): %ld\n", ru.ru_maxrss);
  }

  printf("Press <enter> to exit.\n");
  getchar();

}

void test_unallowed_mkdir(void)
{
    int check;
    char *dirname = TEMP_PATH;

    int label1 = difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

    check = create_labeled_dir(dirname, 0644, secrecySet, sec_len, integritySet, int_len);

    // check if directory is created or not
    if (check < 0)
        printf("couldn't labele the Directory \n");
    else
        printf("labeld directory\n");
}

int test_unallowed_file_func(void *arg)
{

    char *filepath = (char *)arg;
    struct stat *buf;

    printf("[test_unallowed_file_func] pid: %u, tid %ld\n", getpid(),
           (long int)syscall(__NR_gettid));

    int label1 = difc_create_label(0, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("[test_unallowed_file_func]OS capability creation failed\n");
    else
        printf("[test_unallowed_file_func]OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);
    // difc_add_label(label1, SECRECY_LABEL);

    buf = malloc(sizeof(struct stat));

    int ret = stat(filepath, buf);
    if (ret < 0)
        printf("[test_unallowed_file_func] stat fails\n");
    else {
        int size = buf->st_size;
        printf("[test_unallowed_file_func] file size %d", size);
    }
    free(buf);

    while (1) {
    }
    return 0;
}

void test_unallowed_file(void)
{

    int check;
    const int STACK_SIZE = 64 * 1024;
    char *filepath = "/tmp/hello";
    char *dirname = "/tmp/test";
    void *stack = malloc(STACK_SIZE);
    struct stat *buf;

    printf("[test_unallowed_file] pid %u \n", getpid());
    int label1 = difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

    check = create_labeled_file(filepath, 0644, secrecySet, sec_len, integritySet, int_len);

    if (check < 0)
        printf("couldn't label file: %s \n", filepath);
    else
        printf("labeledd file: %s\n", filepath);

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        printf("[test_unallowed_file] faild to open %s\n", filepath);
    }

    printf("[test_unallowed_file] opened labeld file %s\n", filepath);

    buf = malloc(sizeof(struct stat));

    int ret = stat(filepath, buf);
    if (ret < 0)
        printf("[test_unallowed_file] stat fails\n");
    int size = buf->st_size;
    printf("[test_unallowed_file] file size %d\n", size);

    free(buf);
    close(fd);

    int thread_pid = clone(&test_unallowed_file_func, stack + STACK_SIZE,
                           CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, filepath);

    getchar();
    // pause();
}

void difc_threading_test_labeld(void)
{

    const int STACK_SIZE = 64 * 1024;
    size_t alignment = 1024 * 1024;
    unsigned long flags = 0;
    char status[] = "/proc/self/status";
    void *stack = aligned_alloc(alignment, STACK_SIZE);

    printf("[difc_threading_test_labeld] pid %u \n", getpid());
    if (stack == NULL) {
        printf("[difc_threading_test_labeld] Error allocation aligned memory for stack \n");
        return;
    }
    if (((unsigned long)stack % alignment) == 0)
        printf("[difc_threading_test_labeld] the stack pointer, %p, is aligned on %zu\n", stack,
               alignment);

    // label the task

    int label1 = difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

    // When called with the difc_threading_testt the CLONE_VM flag on.

    const char *msg = "[difc_threading_test] hello from main thread";
    private_blk = aligned_alloc(alignment, (strlen(msg) + 1) * sizeof(char));
    strcpy(private_blk, msg);

    if (((unsigned long)private_blk % alignment) == 0)
        printf("[difc_threading_test_labeld] private_blk pointer, %p, is aligned on %zu\n",
               private_blk, alignment);
    printf("[difc_threading_test_labeld]main thread sending buf = %s \n", private_blk);

    map_to_domain((unsigned long)private_blk, 1, DOMAIN_TRUSTED);

    printf("[difc_threading_test_labeld] cloning...\n");

    int thread_pid =
        clone(&task_func, stack + STACK_SIZE, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, private_blk);

    getchar();
    // pause();
    // sleep(100);
}

void difc_labeled_domain_dcl(void)
{

    const int STACK_SIZE = 64 * 1024;
    size_t alignment = 1024 * 1024;
    unsigned long flags = 0;
    char status[] = "/proc/self/status";
    void *stack = aligned_alloc(alignment, STACK_SIZE);

    printf("[difc_threading_test_labeld] pid %u \n", getpid());
    if (stack == NULL) {
        printf("[difc_threading_test_labeld] Error allocation aligned memory for stack \n");
        return;
    }
    if (((unsigned long)stack % alignment) == 0)
        printf("[difc_threading_test_labeld] the stack pointer, %p, is aligned on %zu\n", stack,
               alignment);

    // label the task

    int label1 = difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

    // When called with the difc_threading_testt the CLONE_VM flag on.

    const char *msg = "[difc_threading_test] hello from main thread";
    private_blk = aligned_alloc(alignment, (strlen(msg) + 1) * sizeof(char));
    strcpy(private_blk, msg);

    if (((unsigned long)private_blk % alignment) == 0)
        printf("[difc_threading_test_labeld] private_blk pointer, %p, is aligned on %zu\n",
               private_blk, alignment);
    printf("[difc_threading_test_labeld]main thread sending buf = %s \n", private_blk);

    map_to_domain((unsigned long)private_blk, 1, DOMAIN_TRUSTED);

    printf("[difc_threading_test_labeld] cloning...\n");

    capability_t cap1 = (capability_t)(label1 | (~CAP_LABEL_MASK));
    capability_t capSet[1] = {cap1};
    int cap_len = 1;
    do_temporarily_declassification(capSet, cap_len, 2, SECRECY_LABEL);

    int thread_pid =
        clone(&task_func, stack + STACK_SIZE, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, private_blk);

    getchar();
}



void udom_test(void)
{

    const int STACK_SIZE = 64 * 1024;
    size_t alignment = 1024 * 1024;
    unsigned long flags = 0;
    char status[] = "/proc/self/status";
    void *stack = aligned_alloc(alignment, STACK_SIZE);
    char *memblock = NULL;
    char * malloc_blk=NULL;
       struct timespec start,end;
    long sub=0,sum1=0,avg1=0,sum2=0,avg2=0,sum3=0,sum4=0,sum5=0;

    int mmap_mode=2;

int numbers[] = {65536};//512, 1024,2048 , 4096, 8192,16384,32768, 131072,524288,1048576,2097152
    int *numbers_end = numbers + sizeof(numbers)/sizeof(numbers[0]);



    printf("[udom_test] pid %u \n", getpid());
  
    if (stack == NULL) {
        printf("[udom_test] Error allocation aligned memory for stack \n");
        return;
    }
    if (((unsigned long)stack % alignment) == 0)
        printf("[udom_test] the stack pointer, %p, is aligned on %zu\n", stack,
               alignment);

  if (pthread_mutex_init(&so_mutex, NULL) != 0) { 
        printf("\n mutex init has failed\n"); 
        return ; 
    } 


if(mmap_mode==2)
{
  mpt_init(-1);

   for(int i=0;i<ITTERATE;i++){

       clock_gettime(CLOCK_MONOTONIC_RAW,&start);

    int mpt_udom=mpt_mmap((void*)0x100000, (alignment), PROT_READ | PROT_WRITE,0);
           clock_gettime(CLOCK_MONOTONIC_RAW,&end);

    printf("mpt_udom %d\n",mpt_udom);
 sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_tes mmap_cached %ld\n",sub);
    sum1 +=sub;

    clock_gettime(CLOCK_MONOTONIC_RAW,&start);    
   mpt_destroy(mpt_udom,(void*)0x100000,alignment); 
    
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_test munmap-cached %ld\n",sub);
    sum2 +=sub;

   }

}
else if(mmap_mode==1)  {
    int udom_id = udom_create();
       
    printf("allocated udom: %d \n", udom_id);

    void* addr= NULL;//(void*)0x100000;

    for(int i=0;i<ITTERATE;i++){

// here we should check if prot is WO/RO/EO we should map to a predefined uTile instead of regular one
clock_gettime(CLOCK_MONOTONIC_RAW,&start);
     memblock= (char*) udom_mmap(udom_id,addr , (alignment), 
                                PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS , 0, 0);
       clock_gettime(CLOCK_MONOTONIC_RAW,&end);

           printf("[memblock] base is %p\n", memblock);   

        sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_READ | PROT_WRITE %ld\n",sub);
    sum1 +=sub;
               
if( memblock == MAP_FAILED ) {
    fprintf(stderr, "Failed to udom_create using mmap for udom %d\n", udom_id);
    memblock = NULL;
}

      clock_gettime(CLOCK_MONOTONIC_RAW,&start);    
    munmap(memblock,(alignment));
    
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_test munmap-cached %ld\n",sub);
    sum2 +=sub;

   
    }
}else{

    for(int i=0;i<ITTERATE;i++){
        void* addr=(void*)0x100000;

// here we should check if prot is WO/RO/EO we should map to a predefined uTile instead of regular one
clock_gettime(CLOCK_MONOTONIC_RAW,&start);
     memblock= (char*) mmap(addr , (alignment), 
                                PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS , 0, 0);
       clock_gettime(CLOCK_MONOTONIC_RAW,&end);

           printf("[memblock] base is %p\n", memblock);   

        sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_READ | PROT_WRITE %ld\n",sub);
    sum1 +=sub;
               
if( memblock == MAP_FAILED ) {
    fprintf(stderr, "Failed to mmap \n");
    memblock = NULL;
}

      clock_gettime(CLOCK_MONOTONIC_RAW,&start);    
    munmap(memblock,(alignment));
    
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_test munmap-cached %ld\n",sub);
    sum2 +=sub;



}}

         printf("[udom-mmap-cached]avg1 (%ld) , avg2 (%ld)  itter :%d time\n",(sum1/ITTERATE),(sum2/ITTERATE),ITTERATE);

  

/*
 for(int i=0;i<ITTERATE;i++){
    printf("udom_mprotect test \n");
     clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        udom_mprotect(udom_id,addr,alignment,PROT_READ | PROT_WRITE);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_READ | PROT_WRITE %ld\n",sub);
    sum1 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);    
    udom_mprotect(udom_id,addr,alignment,PROT_NONE);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_NONE %ld\n",sub);
    sum2 +=sub;

      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        udom_mprotect(udom_id,addr,alignment,PROT_READ);

            clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_READ %ld\n",sub);
    sum3 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        udom_mprotect(udom_id,addr,alignment,PROT_WRITE);

            clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_WRITE %ld\n",sub);
    sum4 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        udom_mprotect(udom_id,addr,alignment,PROT_EXEC);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("udom_mprotect PROT_EXEC %ld\n",sub);
    sum5 +=sub;


 }

        printf("[udom_mprotect]avg1 (%ld) , avg2 (%ld) , avg3 (%ld), avg4 (%ld), avg5 (%ld) time\n",(sum1/ITTERATE),(sum2/ITTERATE),(sum3/ITTERATE),(sum4/ITTERATE),(sum5/ITTERATE));
        sum1=0;sum2=0;sum3=0;sum4=0;sum5=0;
  for(int i=0;i<ITTERATE;i++){

     printf("mprotect test \n");

     clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        mprotect(addr,alignment,PROT_READ | PROT_WRITE);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("mprotect PROT_READ | PROT_WRITE %ld\n",sub);
    sum1 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);    
    mprotect(addr,alignment,PROT_NONE);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("mprotect PROT_NONE %ld\n",sub);
    sum2 +=sub;

      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        mprotect(addr,alignment,PROT_READ);

            clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("mprotect PROT_READ %ld\n",sub);
    sum3 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        mprotect(addr,alignment,PROT_WRITE);

            clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("mprotect PROT_WRITE %ld\n",sub);
    sum4 +=sub;
      ///////////////////////////////////////      
    clock_gettime(CLOCK_MONOTONIC_RAW,&start);
        mprotect(addr,alignment,PROT_EXEC);
    clock_gettime(CLOCK_MONOTONIC_RAW,&end);
    sub = ( end.tv_nsec )-(start.tv_nsec );
    printf("mprotect PROT_EXEC %ld\n",sub);
    sum5 +=sub;;


 }

         printf("[mprotect]avg1 (%ld) , avg2 (%ld) , avg3 (%ld), avg4 (%ld), avg5 (%ld) time\n",(sum1/ITTERATE),(sum2/ITTERATE),(sum3/ITTERATE),(sum4/ITTERATE),(sum5/ITTERATE));


/*free_list_init( udom_id);


    for (int *it = numbers; it != numbers_end; ++it){

        for(int i=0;i<ITTERATE;i++){

            clock_gettime(CLOCK_MONOTONIC_RAW,&start);

            malloc_blk= (char*) malloc(*it);

            clock_gettime(CLOCK_MONOTONIC_RAW,&end);

        //long ret = ((end.tv_sec + end.tv_nsec * 1e-9) - (start.tv_sec + start.tv_nsec * 1e-9));
            sub = ( end.tv_nsec )-(start.tv_nsec );
            printf("malloc time %ld\n",sub);
            sum1 +=sub;
            printf("malloc_blk %p\n", malloc_blk);

            clock_gettime(CLOCK_MONOTONIC_RAW,&start);
            free(malloc_blk);
            clock_gettime(CLOCK_MONOTONIC_RAW,&end);

            sub = ( end.tv_nsec )-(start.tv_nsec );
            sum2 +=sub;

              printf("free time %ld\n",sub);

      }

        avg1=sum1/ITTERATE;
        avg2=sum2/ITTERATE;
        printf("avg1 (%ld) , avg2 (%ld) time\n",avg1,avg2);
        sum1=0;sum2=0;

    }
*/

    

   // int ret = udom_kill(udom_id);
    //printf("freed udom: ret%d \n", ret);
    //udom_id = sys_udom_alloc(0, 1);
    //printf("allocated udom: %d \n", udom_id);

    // When called with the difc_threading_testt the CLONE_VM flag on.

  /*  const char *msg = "[difc_threading_test] hello from main thread";
    private_blk = aligned_alloc(alignment, (strlen(msg) + 1) * sizeof(char));
    strcpy(private_blk, msg);

    if (((unsigned long)private_blk % alignment) == 0)
        printf("[udom_test] private_blk pointer, %p, is aligned on %zu\n",
               private_blk, alignment);
    printf("[udom_test]main thread sending buf = %s \n", private_blk);

    map_to_domain((unsigned long)private_blk, 1, DOMAIN_TRUSTED);

    printf("[difc_threading_test_labeld] cloning...\n");

    int thread_pid =
        clone(&task_func, stack + STACK_SIZE, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, private_blk);
*/
    getchar();
}

void test_label_existing_file(void)
{

    int check;
    char *filepath = "/tmp/hello";
    struct stat *buf;

    /* int fd = open(filepath, O_CREAT | O_RDWR);
    if (fd == -1) {
        printf("[test_label_existing_file] faild to open %s\n", filepath);
        return;
    }
*/
    buf = malloc(sizeof(struct stat));
    int ret = stat(filepath, buf);
    if (ret < 0)
        printf("[test_unallowed_file] stat fails\n");

    int label1 = difc_create_label(2, THREAD_SELF);

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %d\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

    check = create_labeled_file(filepath, 0644, secrecySet, sec_len, integritySet, int_len);

    if (check < 0)
        printf("couldn't label file: %s \n", filepath);
    else
        printf("labeledd file: %s\n", filepath);

    free(buf);
    // close(fd);
}

int test_dcl_func(void *arg)
{

    char *filepath = (char *)arg;
    struct stat *buf;

    printf("[test_dcl_func] pid: %u, tid %ld,\n", getpid(), (long int)syscall(__NR_gettid));

    buf = malloc(sizeof(struct stat));

    int ret = stat(filepath, buf);
    if (ret < 0)
        printf("[test_dcl_func] stat fails\n");
    else {
        int size = buf->st_size;
        printf("[test_dcl_func] file size %d \n", size);

    } /*
         unsigned long label1 =
             difc_create_label(0, THREAD_SELF); // creating labels with both + and - caps

         if (label1 <= 0)
             printf("OS capability creation failed\n");
         else
             printf("OS capability creation SUCCESSED: %ld\n", label1);

         long secrecySet[1] = {label1};
         int sec_len = 1;
         long *integritySet = NULL;
         int int_len = 0;

         difc_replace_labels(secrecySet, sec_len, integritySet, int_len);

         ret = stat(filepath, buf);
         if (ret < 0)
             printf("[test_dcl_func] stat fails\n");
         size = buf->st_size;
         printf("[test_dcl_func] file size %d \n", size);
     */
    free(buf);

    while (1) {
    }
    return 0;
}

void test_declassification(void)
{

    int check;
    const int STACK_SIZE = 64 * 1024;
    char *filepath = "/tmp/hello";
    char *dirname = "/tmp/test";
    char status_file[] = "/proc/self/status";
 


    void *stack = malloc(STACK_SIZE);
    struct stat *buf;

    printf("[test_unallowed_file] pid %u \n", getpid());
    unsigned long label1 =
        difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %ld\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_add_label(label1, SECRECY_LABEL);

    capability_t cap1 = (capability_t)(label1 | (~CAP_LABEL_MASK));
    printf("[test_declassification] cap1: %llu, %lld\n", cap1, cap1);
    capability_t capSet[1] = {cap1};
    int cap_len = 1;
    do_temporarily_declassification(capSet, cap_len, 2, SECRECY_LABEL);


    restore_suspended_capabilities(capSet, cap_len, 2, SECRECY_LABEL);

    // assert(thread_pid > 0);
    /*
        FILE *fp = fopen(status_file, "rb");

        printf("Looking into %s...\n", status_file);

        while (1) {
            char ch = fgetc(fp);
            if (feof(fp))
                break;
            printf("%c", ch);
        }

        fclose(fp);

        getchar();
    */


    // sleep(100);

    // pause();
    // sleep(1);
    // exit(0);
    // wait(NULL);
}

void test_difc_domain_entreis(void)
{
/*
    int check;
    const int STACK_SIZE = 64 * 1024;
    char *filepath = "/tmp/hello";
    char *dirname = "/tmp/test";
    char status_file[] = "/proc/self/status";

    void *stack = malloc(STACK_SIZE);
    struct stat *buf;
    printf("pid %u \n", getpid());
    unsigned long label1 =
        difc_create_label(2, THREAD_SELF); // creating labels with both + and - caps

    if (label1 <= 0)
        printf("OS capability creation failed\n");
    else
        printf("OS capability creation SUCCESSED: %ld\n", label1);

    long secrecySet[1] = {label1};
    int sec_len = 1;
    long *integritySet = NULL;
    int int_len = 0;

    difc_add_label(label1, SECRECY_LABEL);
*/
    // jump to the entery
 /*   asm volatile(
        "ldr r7, =0x1AD\n"
        "svc #0\n"
        :
        :);

    // exit from it
    asm volatile(
        "ldr r7, =0x1AE\n"
        "svc #0\n"
        :
        :);

        */
}