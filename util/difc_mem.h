#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>


/* define MAP_ANONYMOUS for Mac OS X */
#if defined(MAP_ANON) && ! defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON

#elif ! defined(MAP_ANON) && ! defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS	0x20

#endif


#ifndef MAP_FAILED
#define MAP_FAILED ((void*) -1)
#endif

#define MAX_MEMDOM 16

/* Minimum size of bytes to allocate in one chunk */
#define CHUNK_SIZE 64

/* MMAP flag for udom protected area */
#define MAP_MEMDOM	0x00800000	

/* Maximum heap size a udom can use: 4MB */
#define MEMDOM_HEAP_SIZE 0x400000


//#define INTERCEPT_MALLOC
#ifdef INTERCEPT_MALLOC
#define malloc(sz) udom_alloc(udom_private_id(), sz)
#define calloc(a,b) udom_alloc(udom_private_id(), a*b)
#define free(addr) udom_free(addr)
#endif


//#include <mutex>
//#include <thread>

/* Free list structure
 * A free list struct records a block of memory available for allocation.
 * udom_alloc() allocates memory from the tail of the free list (usually the largest available block).
 * udom_free() inserts free list to the head of the free list
 */
struct free_list_struct {
    void *addr;
    unsigned long size;
    struct free_list_struct *next;
};

/* Every allocated chunk of memory has this block header to record the required
 * metadata for the allocator to free memory
 */
struct block_header_struct {
    void *addr;
    int udom_id;
    unsigned long size;    
};

/* Memory domain metadata structure
 * A memory domain is an anonymously mmap-ed memory area.
 * mmap() is called when udom_alloc is called the first time for a given udom 
 * Subsequent allocation does not invoke mmap(), instead, it allocates memory from the mmaped
 * area and update related metadata fields. 
 */
struct udom_metadata_struct {
    int udom_id;
    void *start;    // start of this udom's addr (inclusive)
    unsigned long total_size; // the total memory size of this udom
    struct free_list_struct *free_list_head;
    struct free_list_struct *free_list_tail;
    pthread_mutex_t mlock;  // protects this udom in sn SMP environment
};
extern int cnt;
void* mem_start[3];
pthread_mutex_t mprotect_mutex[3];
extern struct udom_metadata_struct *udom[MAX_MEMDOM];



/* Create a memory domain and return it to user */
int udom_create(void);

/* Remove a udom from kernel */
int udom_kill(int udom);

/* Allocate memory region in memory domain */
void *udom_mmap(int udom_id, 
                  void * addr, unsigned long len, 
                  unsigned long prot, unsigned long flags, 
                  unsigned long fd, unsigned long pgoff);

/* Allocate npages pages in memory domain udom */
void *udom_alloc(int udom_id, unsigned long nbytes);
void *udom_malloc(unsigned long nbytes);

/* Deallocate npages pages in memory domain udom */
void udom_free(void* data);

/* Get the calling thread's defualt udom id */
int udom_private_id(void);

/*Set protection on a udom */
int udom_mprotect(unsigned long udom_id, void *addr, unsigned long len, unsigned long orig_prot);

void free_list_init(int udom_id);

