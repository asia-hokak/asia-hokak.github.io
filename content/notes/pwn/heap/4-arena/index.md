---
title: "Arena"
date: 2025-02-04
series: ["Heap Exploitation"]
series_order: 4
weight: 47
---

arena是用來管理heap的一種結構，在一般情況下一個thread只有一個arena  
而main thread的arena就叫做main arena

## Defination

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

glibc是用`malloc state`這個結構來實現arena的功能的，其中有幾個重要的成員變數:

- **mutex**: 互斥鎖，防止多個thread同時讀寫同一個分配區
- **flags**: 記錄了一些分配區的標誌，具體如下

  ```c
  /*
  FASTCHUNKS_BIT held in max_fast indicates that there are probably
  some fastbin chunks. It is set true on entering a chunk into any
  fastbin, and cleared only in malloc_consolidate.
  The truth value is inverted so that have_fastchunks will be true
  upon startup (since statics are zero-filled), simplifying
  initialization checks.
  */
  #define FASTCHUNKS_BIT (1U)
  #define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
  #define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
  #define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)
  /*
  NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
  regions.  Otherwise, contiguity is exploited in merging together,
  when possible, results from consecutive MORECORE calls.
  The initial value comes from MORECORE_CONTIGUOUS, but is
  changed dynamically if mmap is ever used as an sbrk substitute.
  */
  #define NONCONTIGUOUS_BIT (2U)
  #define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
  #define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
  #define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
  #define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)
  /* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
  arena.  Such an arena is no longer used to allocate chunks.  Chunks
  allocated in that arena before detecting corruption are not freed.  */
  #define ARENA_CORRUPTION_BIT (4U)
  #define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
  #define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)
  ```

  - **FASTCHUNKS_BIT**: 表示分配區是否有fastbin chunk 1:有 0:沒有
  - **NONCONTIGUOUS_BIT**: 是否回傳連續的分配區 0:連續 1:不連續
    - 在主分配區系統會用sbrk()來擴展記憶體，所以分配趨是連續的
    - 而在非主分配區系統會用mmap()來映射記憶體，所以非配區會不連續
  - **ARENA_CORRUPTION_BIT**: 記憶體是否損壞
    - 當`ARENA_CORRUPTION_BIT`被設置(1)時，glibc會報錯並終止程式

- **fastbinsY**: 各個fastbin的起始pointer
- **top**: 指向top chunk
- **last_reminder**: chunk被切割後的剩下的那塊
- **bins**: 包含unsortedbin、smallbin、largebin的起始點
- **binmaps**:
  在檢查bins，不可能一個一個去訪問，所以會把每個bin鍊的狀態用都一個bit來儲存，這樣用binary位移的方式訪問會比較快

## References

- https://kiprey.github.io/2020/03/heap-1-arena/
- https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heap-structure/#malloc_state