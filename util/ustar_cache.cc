
extern "C" {
  #include "difc_api.h"

}
#include "mpt.h"
#include "hash_mpt.h"

#include <iostream>
#include <cstdio>
#include <climits>
#include <atomic>
#include <string>
#include <thread>
#include <mutex>
#include <list>
#include <fcntl.h>
#include <cstring>
#include <map>
#define DEVICE_FILENAME "/dev/udom"  

#define ffz(x)  __ffs(~(x))
#define DEBUG 0 
#define llog(format, ...) { \
    if( DEBUG ) { \
        fprintf(stdout, "[mpt] " format, ##__VA_ARGS__); \
        fflush(NULL);   \
    }\
}


static std::atomic_int cnt;

typedef struct _mpt_node {
  void* buf;
  size_t len;
  int prot;
  int udom;
  int id;
  struct _mpt_node* next;
   _mpt_node(void* b, size_t l, int p) {
    buf = b;
    len = l;
    prot = p;
    udom = -1;
    next = NULL;
  } 
  //std::atomic_int cnt;
} mpt_node;

struct _HashEntry {
  int key;
  mpt_node value;
};

typedef struct _stack_node {
  struct _stack_node* prev;
  struct _stack_node* next;
  int udom;
  _stack_node(int id) {
    prev = NULL; next = NULL; udom = id;
  }
} stack_node;

// Shared data structures

int* udom_arr;

static int exec_udom = -1;
static int threshold = 0;
static std::atomic_int n_udom; 
static std::atomic_int n_mmap;
static struct _HashEntry *mmap_table;
static HashMap<stack_node*> stack;
static std::mutex stack_mutex;
static std::mutex protect_mutex;
static uint16_t udom_indomain_map;
static uint16_t all_udoms_mask = ((1U << 16) - 1);
// XXX do we need head?
static stack_node* head, *tail;
#define MPT_BIT(prot) (prot & (PROT_READ | PROT_WRITE))

mpt_node* hash_get(int key) {
	int hash = (key % TABLE_SIZE);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
	if (mmap_table[hash].key == -1)
		return NULL;
	else
		return &mmap_table[hash].value;
}

void hash_put(int key, mpt_node* value) {
	int hash = (key % TABLE_SIZE);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
/*	
 *	if (table[hash].key != -1) {
		table[hash].key = -1;
		table[hash].value = NULL;
	}	
  */
	mmap_table[hash].key = key;
  memcpy(&mmap_table[hash].value, value, sizeof(mpt_node));
//	table[hash].value = value;
}

static __always_inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}



static inline int mpt_update(int udom, int prot, bool synch) {

  if(prot & PROT_WRITE) {
    sys_udom_set(udom,DOMAIN_MANAGER);
  }
  else if(prot & PROT_READ) {
    sys_udom_set(udom,DOMAIN_CLIENT);
  }
  else {
    sys_udom_set(udom,DOMAIN_NOACCESS);
  }

  return 0;
}

static inline int mpt_find(bool domain) {
  for(int i = START_UDOM ; i < MAX_UDOM; i++) {
    llog("udom_arr[%d] : %d\n", i, udom_arr[i]);
    if(udom_arr[i] == -1) {
      stack_mutex.lock();
      stack.put(i, new stack_node(i));
      stack_mutex.unlock();
      return i;
    }
  }

  if(true) {
    cnt.fetch_add(1, std::memory_order_relaxed);
    if(cnt < threshold) {
      return -1;
    }

    int i = tail->prev->udom;
    mpt_node* mn = hash_get(udom_arr[i]);
    
    if(domain) {
      //check bitmap and change i
      if((udom_indomain_map &= (1 << i))) {
        if(udom_indomain_map == all_udoms_mask) {
          return -1;
          // every udom is used in domain.
        }
        else {
          i = ffz(udom_indomain_map);
        }
      }
      // evict
      syscall(__NR_udom_mprotect_evict, mn->buf, mn->len, PROT_NONE, 0, udom_arr[i]);
    }
    else {
      // evict
      syscall(__NR_udom_mprotect_evict, mn->buf, mn->len, mn->prot, 0, udom_arr[i]);
    }
    // udom_arr[i] = -1;
    cnt = 0;
    return i;
  }

  //evict... but it should be unreachable
  mpt_node* mn = hash_get(udom_arr[15]);
  syscall(__NR_udom_mprotect_evict, mn->buf, mn->len, mn->prot, 0, udom_arr[15]);
  return 15;
}


int mpt_init(int evict_rate)
{
  for(int i = START_UDOM; i < MAX_UDOM; i++) {
    sys_udom_alloc(0, 0);
  }
  threshold = evict_rate + 1;
  head = new stack_node(-1); tail = new stack_node(-1);
  head->next = tail;
  tail->prev = head;
  // 0 index is always allocated.
  udom_indomain_map = 1;
  n_mmap = 0; cnt = 0;
  int fd = open(DEVICE_FILENAME, O_RDWR | O_NDELAY);
  char* p;
  if(fd >= 0) {
    p = (char *)mmap(0, 0x1000 + TABLE_SIZE * sizeof(struct _HashEntry), PROT_READ, MAP_SHARED, fd, 0);
  }
  udom_arr = (int *) p;
  mmap_table = (struct _HashEntry*)( p + 0x1000);


  return 0;
}

int mpt_mmap(void* addr, size_t length, int prot, int flags) 
{
  
  static std::atomic_int m_cnt;
  int id = m_cnt.fetch_add(1, std::memory_order_relaxed);
   // printf("[mpt_mmap] id is %d\n", id);   

  void* r_addr = (void *)syscall(__NR_udom_mmap_cache, addr, length, prot, flags | MAP_ANONYMOUS | MAP_PRIVATE, id);
  //mpt_node* mn = hash_get(id); //new mpt_node(r_addr, length, prot);
  //hash_put(id, mn);
   // printf("[mpt_mmap] r_addr is %p, id is %d\n", r_addr,id);   

  //*addr = r_addr;
  n_mmap.fetch_add(1, std::memory_order_relaxed);

  return id;
}


inline int do_mpt_mprotect(mpt_node* mn, int prot, int grouping_key, bool domain, int id) 
{
  int ret = 2;

  void* buf = mn->buf;
  size_t len = mn->len;
  int udom = mn->udom;
  // I will save is_exec instead of mn->prot
  int mn_prot = mn->prot;
  
  if(grouping_key == -1) {
    if(udom == -1) {
      ret = 1;
      udom = mpt_find(domain);
      if(udom == -1 && !domain) {
        mprotect(buf, len, prot);
        llog("mprotect\n");
        return 0;
      }
      else if(udom == -1 && domain) {
        llog("already MAX_PKEY\n");
        return -1;
      }
      if(prot == PROT_EXEC && exec_udom == -1) {
        exec_udom = udom;
      }

      syscall(__NR_udom_mprotect_set, buf, len, (DEFAULT_PROT | prot), udom, id);
    }
    else {
      // existing entry
      if (!domain && (mn_prot == PROT_EXEC) && (prot != PROT_EXEC)) {
        // previous permission was exec-only, but current permission is not
        mpt_node* cur = hash_get(udom_arr[udom]);
        mpt_node* prev = NULL;
        if(!cur->next) {
          // this is last exec-only page 
          exec_udom = -1;
        } 
        else {
          // still has exec-only
          int tmp_udom = udom;
          udom = mpt_find(domain);
          if(udom == -1 && !domain) {
            syscall(__NR_mprotect_exec, buf, len, prot, tmp_udom);
            llog("mprotect\n");
            return 0;
          }
          else if(udom == -1 && domain) {
            llog("already MAX_PKEY\n");
            return -1;
          }
//          mn->udom = udom;
//          udom_arr[udom] = id;
        }
      }
      // previous permission had exec, but current permission is not, or vice versa
      if (((mn_prot | PROT_EXEC) && !(prot | PROT_EXEC)) || (!(mn_prot | PROT_EXEC) && (prot | PROT_EXEC) ) ) {
        syscall(__NR_udom_mprotect_exec, buf, len, (DEFAULT_PROT | prot), udom, id);
//        udom_mprotect_exec(buf, len, (DEFAULT_PROT | prot), udom);
      }
    }
    // only non domain (mpt_mprotect) need synch 
    mpt_update(udom, prot, !domain);
  }
  else {
    syscall(__NR_udom_mprotect_grouping, buf, len, (DEFAULT_PROT | prot), grouping_key, id);
    //
    mpt_update(grouping_key, prot, !domain);
  }

  if(!(prot == PROT_EXEC && !domain)) {
    stack_mutex.lock();
    stack_node* cur = stack.get(udom);
    mn;
    if(cur->prev)
      cur->prev->next = cur->next;
    if(cur->next)
      cur->next->prev = cur->prev;
    if(head->next) {
      cur->next = head->next;
      head->next->prev = cur;
    }
    cur->prev = head;
    head->next = cur;
    stack_mutex.unlock();
  }
// I can remove this because prot has to be changed only when it includes EXEC permission.
//  mn->prot = prot;
//
  return ret;
}

int mpt_mprotect(int id, int prot) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  int grouping_key = -1;
  if (prot == PROT_EXEC) {
    if(exec_udom != -1) {
      grouping_key = exec_udom;
    }
  }
  return do_mpt_mprotect(mn, prot, grouping_key, false, id);
}


int mpt_begin(int id, int prot) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  udom_indomain_map |= (1 << mn->udom);
  return do_mpt_mprotect(mn, prot, -1, true, id);
}

int mpt_end(int id) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  udom_indomain_map &= ~(1 << mn->udom);
  return do_mpt_mprotect(mn, PROT_NONE, -1, true, id);
}

int mpt_destroy(int id,void* addr,size_t len)
{
  n_mmap.fetch_sub(1, std::memory_order_relaxed);
 // mpt_node* mn = hash_get(id);
  //if(mn == NULL) {
   // llog("already destroy\n");
   // return -1;
 // }
//mn->buf= addr;
//mn->len=len;
  //void* buf = mn->buf;
 //size_t len = mn->len;
//  int udom = mn->udom;

  // if(udom != -1)
  //   udom_arr[udom].udom = -1;
  //delete mn;
  //hash_put(id, NULL);
  //syscall(__NR_udom_munmap, addr, len, id);
      munmap(addr,(len));

  //
  return 0;
}
