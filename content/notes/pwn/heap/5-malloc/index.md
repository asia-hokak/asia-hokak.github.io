---
title: "Malloc"
date: 2025-02-09
series: ["Heap Exploitation"]
series_order: 5
---
 


## __libc_malloc()

- `__libc_malloc`為呼叫`malloc`實際執行的function
- `victim` 是作為回傳的記憶體

```c
__libc_malloc(size_t bytes)
{
    mstate ar_ptr;
    void *victim;

    _Static_assert(PTRDIFF_MAX <= SIZE_MAX / 2,
                   "PTRDIFF_MAX is not more than half of SIZE_MAX");

    if (!__malloc_initialized) // 檢查heap是否被初始化
        ptmalloc_init(); // 執行malloc 初始化
```

### 嘗試從tcache分配記憶體

```c
#if USE_TCACHE
    /* int_free also calls request2size, be careful to not pad twice.  */
    size_t tbytes;
    if (!checked_request2size(bytes, &tbytes)) // 確保分配大小正常
    {
        __set_errno(ENOMEM);
        return NULL;
    }
    size_t tc_idx = csize2tidx(tbytes);

    MAYBE_INIT_TCACHE();

    DIAG_PUSH_NEEDS_COMMENT;
    if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0) // 如果tcache有東西
    {
        victim = tcache_get(tc_idx);
        return tag_new_usable(victim);
    }
    DIAG_POP_NEEDS_COMMENT;
#endif
```

### 在單執行緒的情況下

- 呼叫了`_int_malloc()`，也是主要在實作malloc的函數

```c
    if (SINGLE_THREAD_P)
    {
        victim = tag_new_usable(_int_malloc(&main_arena, bytes));
        assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
               &main_arena == arena_for_chunk(mem2chunk(victim)));
        return victim;
    }
```

### 在多執行緒的情況下

```c
    arena_get(ar_ptr, bytes); // 獲取arena

    victim = _int_malloc(ar_ptr, bytes);
    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) // 如果分配失敗
    {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes); // 使用其他arena
        victim = _int_malloc(ar_ptr, bytes);
    }

    if (ar_ptr != NULL)
        __libc_lock_unlock(ar_ptr->mutex); // 在多thread的情況下會上鎖arena，這裡解鎖表示arena使用結束

    victim = tag_new_usable(victim);

    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim))); // 檢查 victim不為空 | victim是透過mmap分配 | victim是來自正確的arena，
    return victim;
```

## _int_malloc()

變數功能註解都有寫了，真好owob

```c
_int_malloc (mstate av, size_t bytes)
{
    INTERNAL_SIZE_T nb;               /* normalized request size */
    unsigned int idx;                 /* associated bin index */
    mbinptr bin;                      /* associated bin */

    mchunkptr victim;                 /* inspected/selected chunk */
    INTERNAL_SIZE_T size;             /* its size */
    int victim_index;                 /* its bin index */

    mchunkptr remainder;              /* remainder from a split */
    unsigned long remainder_size;     /* its size */

    unsigned int block;               /* bit map traverser */
    unsigned int bit;                 /* bit map traverser */
    unsigned int map;                 /* current word of binmap */

    mchunkptr fwd;                    /* misc temp for linking */
    mchunkptr bck;                    /* misc temp for linking */

#if USE_TCACHE
    size_t tcache_unsorted_count;	  /* count of unsorted chunks processed */
#endif
```

### fastbin

```c
if ((unsigned long)(nb) <= (unsigned long)(get_max_fast()))
{
    // 得到對應fastbin索引
    idx = fastbin_index(nb);
    // 得到對應索引fastbin的pointer
    mfastbinptr *fb = &fastbin(av, idx);
    mchunkptr pp;
    victim = *fb; // victim 是malloc_chunk的結構
    // 如果對應index的fastbin存在
    if (victim != NULL)
    {
        // fastbin top address對齊檢查
        if (__glibc_unlikely(misaligned_chunk(victim)))
            malloc_printerr("malloc(): unaligned fastbin chunk detected 2");
        // unlink
        if (SINGLE_THREAD_P)
            *fb = REVEAL_PTR(victim->fd);
        else
            REMOVE_FB(fb, pp, victim);
        //
        if (__glibc_likely(victim != NULL))
        {
            size_t victim_idx = fastbin_index(chunksize(victim));
            if (__builtin_expect(victim_idx != idx, 0))
                malloc_printerr("malloc(): memory corruption (fast)");
            check_remalloced_chunk(av, victim, nb);
```

#### tcache

```c
#if USE_TCACHE
            /* While we're here, if we see other chunks of the same size,
            stash them in the tcache.  */

            // 計算tcache index
            size_t tc_idx = csize2tidx(nb);
            // 如果tcache滿足要求
            if (tcache && tc_idx < mp_.tcache_bins)
            {
                mchunkptr tc_victim;

                /* While bin not empty and tcache not full, copy chunks.  */
                // 如果fastbin有東西然後tcache沒滿，把chunks裝到tcache
                while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = *fb) != NULL)
                {
                    if (__glibc_unlikely(misaligned_chunk(tc_victim)))
                        malloc_printerr("malloc(): unaligned fastbin chunk detected 3");
                    if (SINGLE_THREAD_P)
                        *fb = REVEAL_PTR(tc_victim->fd);
                    else
                    {
                        // 斷鍊操作
                        REMOVE_FB(fb, pp, tc_victim);
                        if (__glibc_unlikely(tc_victim == NULL))
                            break;
                    }
                    tcache_put(tc_victim, tc_idx);
                }
            }
#endif
```

#### 回傳記憶體

```c
            // 返回mem地址
            void *p = chunk2mem(victim);
            // 加上0x10的header size
            alloc_perturb(p, bytes);
            return p;
        }
    }
}
  
```

### smallbin

```c
if (in_smallbin_range(nb))
{
    // 計算對應大小的索引值
    idx = smallbin_index(nb);
    // 獲取smallbin指標
    bin = bin_at(av, idx);

    if ((victim = last(bin)) != bin)
    {
        bck = victim->bk;
        // 檢查double linked list結構的完整性
        if (__glibc_unlikely(bck->fd != victim))
            malloc_printerr("malloc(): smallbin double linked list corrupted");
        // 將chunk從尾端取出
        set_inuse_bit_at_offset(victim, nb);
        bin->bk = bck;
        bck->fd = bin;

        // 檢查是否為在main arena
        if (av != &main_arena)
            set_non_main_arena(victim);
        // 檢查chunk是否正常
        check_malloced_chunk(av, victim, nb);

```

#### tcache

```c
#if USE_TCACHE
        /* While we're here, if we see other chunks of the same size,
            stash them in the tcache.  */
        // 計算tcache index
        size_t tc_idx = csize2tidx(nb);
        // 如果tcache滿足要求
        if (tcache && tc_idx < mp_.tcache_bins)
        {
            mchunkptr tc_victim;

            /* While bin not empty and tcache not full, copy chunks over.  */
            // 如果fastbin有東西然後tcache沒滿，把chunks裝到tcache
            while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last(bin)) != bin)
            {
                if (tc_victim != 0)
                {
                    bck = tc_victim->bk;
                    set_inuse_bit_at_offset(tc_victim, nb);

                    if (av != &main_arena)
                        set_non_main_arena(tc_victim);
                    // 斷鏈操作，並把chunk放到tcache
                    bin->bk = bck;
                    bck->fd = bin;

                    tcache_put(tc_victim, tc_idx);
                }
            }
        }
#endif

```

#### 回傳記憶體

```c
        // 返回mem地址
        void *p = chunk2mem(victim);
        // 加上0x10的header size
        alloc_perturb(p, bytes);
        return p;
    }
}
```

#### 合併fastbin

下面這段code的用意是為了在進行檢查儲存大chunk的bin(unsortedbin, largebin)之前先清除fastbin  
因為fastbin不會主動合併，亦阻止了相鄰的chunk合併，使整個記憶體碎片化

```c
else
{
    idx = largebin_index (nb);
    if (atomic_load_relaxed (&av->have_fastchunks))
    malloc_consolidate (av);
}
```

### unsortedbin

- 拿到這個chunk和下個chunk的pointer
- 檢查chunk的結構有沒有被破壞

#### 檢查

```c
for (;;) //這個for迴圈同時包含了unsortedbin和largebin的實作，因為他們兩個息息相關
{
    int iters = 0;
    while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av))
    {
        bck = victim->bk; // 取出 unsortedbin 倒數第二個 freed chunk (victim被為被取下來的那塊)
        size = chunksize(victim);
        mchunkptr next = chunk_at_offset(victim, size); // 根據chunksize找到下一個chunk的位置

        if (__glibc_unlikely(size <= CHUNK_HDR_SZ) || __glibc_unlikely(size > av->system_mem)) // chunk大小小於header大小或比heap空間大
            malloc_printerr("malloc(): invalid size (unsorted)");
        if (__glibc_unlikely(chunksize_nomask(next) < CHUNK_HDR_SZ) || __glibc_unlikely(chunksize_nomask(next) > av->system_mem)) // 檢查下一個chunk的大小是否正常
            malloc_printerr("malloc(): invalid next size (unsorted)");
        if (__glibc_unlikely((prev_size(next) & ~(SIZE_BITS)) != size)) // 檢查prev_size 是否等於當前 size
            malloc_printerr("malloc(): mismatching next->prev_size (unsorted)");
        if (__glibc_unlikely(bck->fd != victim) || __glibc_unlikely(victim->fd != unsorted_chunks(av))) // 檢查doubly linked list的完整性
            malloc_printerr("malloc(): unsorted double linked list corrupted");
        if (__glibc_unlikely(prev_inuse(next))) // 檢查prev_inuse bit (unsortedbin 應該 unset prev_inuse bit)
            malloc_printerr("malloc(): invalid next->prev_inuse (unsorted)");
```

#### 使用last remainder

滿足以下需求

- 如果是small request(小於smallbin max request size，非largebin size)
- 且last remainder(切割剩下的chunk)是unsortedbin裡面唯一一塊chunk的話

註: last remainder 一定會位於unsortedbin，因為切割過後的chunk會先放回unsortedbin

```c

        /*
           If a small request, try to use last remainder if it is the
           only chunk in unsorted bin.  This helps promote locality for
           runs of consecutive small requests. This is the only
           exception to best-fit, and applies only when there is
           no exact fit for a small chunk.
        */
        if (in_smallbin_range(nb) &&
            bck == unsorted_chunks(av) &&
            victim == av->last_remainder &&
            (unsigned long)(size) > (unsigned long)(nb + MINSIZE))
        {
            /* split and reattach remainder */
            remainder_size = size - nb;                                    // 計算remainder chunk被切下來的剩下大小
            remainder = chunk_at_offset(victim, nb);                       // 偏移後得到新的remainder chunk
            unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder; // 調整unsortedbin起始點(因為remainder已經被切割)
            av->last_remainder = remainder;                                // 紀錄last remainder到main arena
            remainder->bk = remainder->fd = unsorted_chunks(av);           // 調整remainder的fd和bk
            if (!in_smallbin_range(remainder_size))                        // 如果remainder的size小於smallbin max request size的話
            {
                remainder->fd_nextsize = NULL; // 清空(fd_nextsize)，這邊有可能是因為從largebin切割完丟回來的
                remainder->bk_nextsize = NULL;
            }

            set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0)); //設定取下的chunk的 chunksize, prev_inuse bit, non_main_arena
            set_head(remainder, remainder_size | PREV_INUSE); // 設定remainder的prev_inuse bit 和isze
            set_foot(remainder, remainder_size); //設定remainder 下一個chunk的prev_size

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }
```

#### unlink

```c
    /* remove from unsorted list */
        if (__glibc_unlikely(bck->fd != victim))
            malloc_printerr("malloc(): corrupted unsorted chunks 3");
        unsorted_chunks(av)->bk = bck;
        bck->fd = unsorted_chunks(av);
```

#### 如果fit size

- 如果fit size的話就直接回傳那塊

```c
        /* Take now instead of binning if exact fit */

        if (size == nb)
        {
            set_inuse_bit_at_offset(victim, size);
            if (av != &main_arena)
                set_non_main_arena(victim);
#if USE_TCACHE
            /* Fill cache first, return to user only if cache fills.
           We may return one of these chunks later.  */
            if (tcache_nb && tcache->counts[tc_idx] < mp_.tcache_count)
            {
                tcache_put(victim, tc_idx);
                return_cached = 1;
                continue;
            }
            else
            {
#endif
                check_malloced_chunk(av, victim, nb);
                void *p = chunk2mem(victim);
                alloc_perturb(p, bytes);
                return p;
#if USE_TCACHE
            }

#endif
        }
```

#### 放回smallbin的情況 

(如果是smallbin range的話)

```c
        if (in_smallbin_range(size))
        {
            victim_index = smallbin_index(size);
            bck = bin_at(av, victim_index);
            fwd = bck->fd;
        }
```

#### 放回largebin的情況

```c
        else
        {
            victim_index = largebin_index(size); // 找到對應size的bin index
            bck = bin_at(av, victim_index); // 使用index找到bin的起始點
            fwd = bck->fd;

            /* maintain large bins in sorted order */
            if (fwd != bck) // 如果bin鍊有東西
            {
                /* Or with inuse bit to speed comparisons */
                size |= PREV_INUSE;
                /* if smaller than smallest, bypass loop below */
                assert(chunk_main_arena(bck->bk));
                if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk))
                {
                    // 如果size為比最後一塊(同時也是最小塊)還小，就直接插入尾端
                    fwd = bck;
                    bck = bck->bk;

                    victim->fd_nextsize = fwd->fd;
                    victim->bk_nextsize = fwd->fd->bk_nextsize;
                    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                }
                else
                {
                    assert(chunk_main_arena(fwd));
                    //從鍊頭開始往下遍歷
                    while ((unsigned long)size < chunksize_nomask(fwd))
                    {
                        // 找到跳過比他大的chunk
                        fwd = fwd->fd_nextsize;
                        assert(chunk_main_arena(fwd));
                    }
                        // 檢查這個chunk的size是否跟他一致
                    if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                    else
                    {
                        // 如果沒有跟他一樣的話就新增一個size進入linked list
                        victim->fd_nextsize = fwd;
                        victim->bk_nextsize = fwd->bk_nextsize;
                        if (__glibc_unlikely(fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr("malloc(): largebin double linked list corrupted (nextsize)");
                        fwd->bk_nextsize = victim;
                        victim->bk_nextsize->fd_nextsize = victim;
                    }
                    bck = fwd->bk;
                    if (bck->fd != fwd)
                        malloc_printerr("malloc(): largebin double linked list corrupted (bk)");
                }
            }
            else
                victim->fd_nextsize = victim->bk_nextsize = victim; //如果largebin沒東西的話那就需要構造一下了
        }
```

#### 放回bin中(剛剛那兩段只是為了找到bck和fwd)

```c
        // 放到對應bin中
        mark_bin(av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;

```

#### 結束while迴圈

- 如果unsorted放太多chunk到tcache的話就直接回傳(前提是大小有對應
- 但預設`mp_.tcache_unsorted_limit` = 0，所以也不會執行這段

```c
#if USE_TCACHE
        /* If we've processed as many chunks as we're allowed while
       filling the cache, return one of the cached ones.  */
       //
        ++tcache_unsorted_count;
        if (return_cached && mp_.tcache_unsorted_limit > 0 && tcache_unsorted_count > mp_.tcache_unsorted_limit)
        {
            return tcache_get(tc_idx);
        }
#endif
```

- 超過最大iteration限制就直接break

```c
#define MAX_ITERS 10000
        if (++iters >= MAX_ITERS)
            break;
    }
```

- unsortedbin binning code跑完之後，再檢查tcache一遍

```c
#if USE_TCACHE
    /* If all the small chunks we found ended up cached, return one now.  */
    if (return_cached)
    {
        return tcache_get(tc_idx);
    }
```

### largebin

```c
/*
       If a large request, scan through the chunks of current bin in
       sorted order to find smallest that fits.  Use the skip list for this.
     */

    if (!in_smallbin_range(nb))
    {
        bin = bin_at(av, idx);
 
         /* skip scan if empty or largest chunk is too small */
         // 遍歷特定大小，跳過那些比請求小或者是空的
        if ((victim = first(bin)) != bin && (unsigned long)chunksize_nomask(victim) >= (unsigned long)(nb))
        {
             victim = victim->bk_nextsize;
             while (((unsigned long)(size = chunksize(victim)) <
                     (unsigned long)(nb)))
                 victim = victim->bk_nextsize;
 
             /* Avoid removing the first entry for a size so that the skip
                list does not have to be rerouted.  */
             // 如果拿到的chunk不是該bin的最後一塊，我們選擇其前面那塊，這樣可以避免調整fd_nextsize和bk_nextsize
             // 因為fd_nextsize和bk_nextsize都是指向某個大小的第一塊
             if (victim != last(bin) && chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                 victim = victim->fd;
 
             remainder_size = size - nb;
             unlink_chunk(av, victim);
 
```

#### 切割後的size不足成為一個chunk

```c
             /* Exhaust */
             // 切割後的size不能做為一個chunk
             if (remainder_size < MINSIZE)
             {
                 set_inuse_bit_at_offset(victim, size);
                 if (av != &main_arena)
                     set_non_main_arena(victim);
             }
             
```

#### 切割chunk

```c
            /* Split */
             else
             {
                 
                 remainder = chunk_at_offset(victim, nb);
                 /* We cannot assume the unsorted list is empty and therefore
                    have to perform a complete insert here.  */
                 bck = unsorted_chunks(av);
                 fwd = bck->fd;
                 if (__glibc_unlikely(fwd->bk != bck))
                     malloc_printerr("malloc(): corrupted unsorted chunks");
                 // unlink操作
                 remainder->bk = bck;
                 remainder->fd = fwd;
                 bck->fd = remainder;
                 fwd->bk = remainder;
                 // 清空fd_nextsize & bk_nextsize
                 if (!in_smallbin_range(remainder_size))
                 {
                     remainder->fd_nextsize = NULL;
                     remainder->bk_nextsize = NULL;
                 }
                 
                 set_head(victim, nb | PREV_INUSE |
                                      (av != &main_arena ? NON_MAIN_ARENA : 0)); //重新分配chunk的標記
                 set_head(remainder, remainder_size | PREV_INUSE); // 設置 remainder的prev_size
                 set_foot(remainder, remainder_size); // 設置 remainder下一個chunk的prev_size
             }
```

#### 回傳記憶體

```c
             check_malloced_chunk(av, victim, nb);
             // 轉為mem型態
             void *p = chunk2mem(victim);
             alloc_perturb(p, bytes);
             return p;
        }
    }
```

### search for larger bin

如果走到這邊，代表相同size的bin都不能滿足  
會找更大的chunk

```c
        /*
            Search for a chunk by scanning bins, starting with next largest
            bin. This search is strictly by best-fit; i.e., the smallest
            (with ties going to approximately the least recently used) chunk
            that fits is selected.

            The bitmap avoids needing to check that most blocks are nonempty.
            The particular case of skipping all bins during warm-up phases
            when no chunks have been returned yet is faster than it might look.
        */
        // 如果在這之前的方式都沒找到合適的bin的話
        // 掃描所有bin
        // binmap: binmap會以bit為單位來紀錄bin鏈是否有東西
        // 會有四組32 bit大小的整數，總共128 bit
        ++idx; // 下一個bin的索引值
        bin = bin_at (av, idx); // 下一個bin的指標位置
        block = idx2block (idx); // 將idx轉成block，block一共四個，大小128，idx 0-31 為0，idx 32-63 為1，以此類推
        map = av->binmap[block]; // 獲取map
        bit = idx2bit (idx); // 將idx轉回bit
```

#### 找到合適的bin

```c
        for (;;)
        {
            /* Skip rest of block if there are no more set bits in this block.  */
            // 跳過空的bin鏈
            if (bit > map || bit == 0)
            {
                do
                {
                    if (++block >= BINMAPSIZE) /* out of bins */
                        goto use_top; // 如果所有block都被搜過了，然後沒東西就跳轉到use_top(使用top chunk分配)
                } while ((map = av->binmap[block]) == 0);

                bin = bin_at(av, (block << BINMAPSHIFT));  
                bit = 1;
            }

            /* Advance to bin with set bit. There must be one. */
            while ((bit & map) == 0) // 找到block中有東西的bin鏈
            {
                bin = next_bin(bin);
                bit <<= 1;
                assert(bit != 0);
            }

            /* Inspect the bin. It is likely to be non-empty */
            // 獲取最後的chunk
            victim = last(bin);
            /*  If a false alarm (empty bin), clear the bit. */
            // 如果bin->bk == bin的話代表bin鏈為空
            // 要清除bit，並繼續循環
            if (victim == bin) //
            {
                av->binmap[block] = map &= ~bit; /* Write through */
                bin = next_bin(bin); 
                bit <<= 1;
            }
```

#### 找到

```c
else
    {
        size = chunksize(victim);

        /*  We know the first chunk in this bin is big enough to use. */
        assert((unsigned long)(size) >= (unsigned long)(nb));

        remainder_size = size - nb;

        /* unlink */
        unlink_chunk(av, victim);
```


```c
        /* Exhaust */
        // 切割剩下的size不足成為一個chunk
        if (remainder_size < MINSIZE)
        {
            set_inuse_bit_at_offset(victim, size);
            if (av != &main_arena)
                set_non_main_arena(victim);
        }

```

#### 切割後的size不足成為一個chunk

```c
        /* Split */
        // 這邊都跟之前差不多
        else
        {
            remainder = chunk_at_offset(victim, nb);

            /* We cannot assume the unsorted list is empty and therefore
                have to perform a complete insert here.  */
            bck = unsorted_chunks(av);
            fwd = bck->fd;
            if (__glibc_unlikely(fwd->bk != bck))
                malloc_printerr("malloc(): corrupted unsorted chunks 2");
            remainder->bk = bck;
            remainder->fd = fwd;
            bck->fd = remainder;
            fwd->bk = remainder;

            /* advertise as last remainder */
            if (in_smallbin_range(nb))
                av->last_remainder = remainder;
            if (!in_smallbin_range(remainder_size))
            {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
            }
            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);
            set_foot(remainder, remainder_size);
        }
```

#### 回傳記憶體

```c
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
    }
}
```

### use top

最後的情況會嘗試從 top chunk切割chunk下來

```c
use_top :
    /*
       If large enough, split off the chunk bordering the end of memory
       (held in av->top). Note that this is in accord with the best-fit
       search rule.  In effect, av->top is treated as larger (and thus
       less well fitting) than any other available chunk since it can
       be extended to be as large as necessary (up to system
       limitations).

       We require that av->top always exists (i.e., has size >=
       MINSIZE) after initialization, so if it would otherwise be
       exhausted by current request, it is replenished. (The main
       reason for ensuring it exists is that we may need MINSIZE space
       to put in fenceposts in sysmalloc.)
     */

        victim = av->top; // top_chunk
        size = chunksize(victim);

        if (__glibc_unlikely(size > av->system_mem)) // chunk size大於heap空間
            malloc_printerr("malloc(): corrupted top size");
```

#### 如果top chunk有足夠的大小可以被切割

```c

        if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))
        {
            remainder_size = size - nb;
            remainder = chunk_at_offset(victim, nb);
            av->top = remainder;
            set_head(victim, nb | PREV_INUSE |
                                (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }

```

#### 如果沒有，檢查是否有fastbin

fastbin不會自動合併，但`malloc_consolidate()`會把相鄰的fastbin合併

```c
        else if (atomic_load_relaxed(&av->have_fastchunks))
        {
            malloc_consolidate(av);
            /* restore original bin index */
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb); //取出對映smallbin size的idx，會在下一個iteration被處理
            else
                idx = largebin_index(nb); //取出對映largebin size的idx，會在下一個iteration被處理
        }
```

#### 最終情況，會用sysmalloc再要一塊記憶體

```c
        /*
        Otherwise, relay to handle system-dependent cases
        */
        else
        {
            void *p = sysmalloc(nb, av); //跟系統要一塊記憶體
            if (p != NULL)
                alloc_perturb(p, bytes);
            return p;
        }
    }
}
```

## __libc_realloc

- 擴展當前記憶體

```c
__libc_realloc(void *oldmem, size_t bytes)
{
    mstate ar_ptr;
    INTERNAL_SIZE_T nb; /* padded request size */

    void *newp; /* chunk to return */

    if (!__malloc_initialized) // 初始化(如果沒有)
        ptmalloc_init();

#if REALLOC_ZERO_BYTES_FREES
    if (bytes == 0 && oldmem != NULL)
    {
        __libc_free(oldmem);
        return 0;
    }
#endif

    /* realloc of null is supposed to be same as malloc */
    if (oldmem == 0) // 舊指標為空，可以使用malloc就好了
        return __libc_malloc(bytes);

    /* Perform a quick check to ensure that the pointer's tag matches the
       memory's tag.  */
    // 確保pointer的tag和memory的tag相符
    if (__glibc_unlikely(mtag_enabled))
        *(volatile char *)oldmem;

    /* chunk corresponding to oldmem */
    const mchunkptr oldp = mem2chunk(oldmem);
    /* its size */
    const INTERNAL_SIZE_T oldsize = chunksize(oldp); //取得舊的size

    if (chunk_is_mmapped(oldp))
        ar_ptr = NULL;
    else
    {
        MAYBE_INIT_TCACHE();
        ar_ptr = arena_for_chunk(oldp);
    }

    /* Little security check which won't hurt performance: the allocator
       never wrapps around at the end of the address space.  Therefore
       we can exclude some size values which might appear here by
       accident or by "design" from some intruder.  */
    if ((__builtin_expect((uintptr_t)oldp > (uintptr_t)-oldsize, 0) || __builtin_expect(misaligned_chunk(oldp), 0))) // 確保舊指標沒越界
        malloc_printerr("realloc(): invalid pointer");

    if (!checked_request2size(bytes, &nb))
    {
        __set_errno(ENOMEM);
        return NULL;
    }

    if (chunk_is_mmapped(oldp)) // chunk是否是mmap出來的
    {
        void *newmem;

#if HAVE_MREMAP
        newp = mremap_chunk(oldp, nb); // 擴展記憶體或壓縮記憶體
        if (newp)
        {
            void *newmem = chunk2mem_tag(newp); 
            /* Give the new block a different tag.  This helps to ensure
               that stale handles to the previous mapping are not
               reused.  There's a performance hit for both us and the
               caller for doing this, so we might want to
               reconsider.  */
            return tag_new_usable(newmem);
        }
#endif
        /* Note the extra SIZE_SZ overhead. */
        if (oldsize - SIZE_SZ >= nb) // realloc的大小比原本的小
            return oldmem; /* do nothing */

        /* Must alloc, copy, free. */
        newmem = __libc_malloc(bytes);
        if (newmem == 0)
            return 0; /* propagate failure */

        memcpy(newmem, oldmem, oldsize - CHUNK_HDR_SZ);
        munmap_chunk(oldp);
        return newmem;
    }

    if (SINGLE_THREAD_P)
    {
        newp = _int_realloc(ar_ptr, oldp, oldsize, nb);
        assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
               ar_ptr == arena_for_chunk(mem2chunk(newp)));

        return newp;
    }

    __libc_lock_lock(ar_ptr->mutex);

    newp = _int_realloc(ar_ptr, oldp, oldsize, nb);

    __libc_lock_unlock(ar_ptr->mutex);
    assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
           ar_ptr == arena_for_chunk(mem2chunk(newp)));

    if (newp == NULL) // 當記憶體分配失敗嘗試在其他arena分配
    {
        /* Try harder to allocate memory in other arenas.  */
        LIBC_PROBE(memory_realloc_retry, 2, bytes, oldmem);
        newp = __libc_malloc(bytes);
        if (newp != NULL)
        {
            size_t sz = memsize(oldp);
            memcpy(newp, oldmem, sz);
            (void)tag_region(chunk2mem(oldp), sz);
            _int_free(ar_ptr, oldp, 0);
        }
    }

    return newp;
}
```

## _int_realloc()

```c
_int_realloc(mstate av, mchunkptr oldp, INTERNAL_SIZE_T oldsize,
             INTERNAL_SIZE_T nb)
{
    mchunkptr newp;          /* chunk to return */
    INTERNAL_SIZE_T newsize; /* its size */
    void *newmem;            /* corresponding user mem */

    mchunkptr next; /* next contiguous chunk after oldp */

    mchunkptr remainder;          /* extra space at end of newp */
    unsigned long remainder_size; /* its size */

    /* oldmem size */
    if (__builtin_expect(chunksize_nomask(oldp) <= CHUNK_HDR_SZ, 0) || __builtin_expect(oldsize >= av->system_mem, 0))
        malloc_printerr("realloc(): invalid old size");

    check_inuse_chunk(av, oldp);

    /* All callers already filter out mmap'ed chunks.  */
    assert(!chunk_is_mmapped(oldp));

    next = chunk_at_offset(oldp, oldsize);
    INTERNAL_SIZE_T nextsize = chunksize(next);
    if (__builtin_expect(chunksize_nomask(next) <= CHUNK_HDR_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0))
        malloc_printerr("realloc(): invalid next size");
```

### 如果舊的夠大

```c
    if ((unsigned long)(oldsize) >= (unsigned long)(nb))
    {
        /* already big enough; split below */
        newp = oldp;
        newsize = oldsize;
    }
```

### 嘗試向top chunk擴展

```c
    else
    {
        /* Try to expand forward into top */
        if (next == av->top &&
            (unsigned long)(newsize = oldsize + nextsize) >=
                (unsigned long)(nb + MINSIZE))
        {
            set_head_size(oldp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
            av->top = chunk_at_offset(oldp, nb);
            set_head(av->top, (newsize - nb) | PREV_INUSE);
            check_inuse_chunk(av, oldp);
            return tag_new_usable(chunk2mem(oldp));
        }
```

### 向下方free chunk擴展

```c
        // 向下擴展，並切割
        else if (next != av->top &&
                 !inuse(next) &&
                 (unsigned long)(newsize = oldsize + nextsize) >=
                     (unsigned long)(nb))
        {
            newp = oldp;
            unlink_chunk(av, next);
        }
```

### 否則重新分配記憶體

```c
        /* allocate, copy, free */
        // 分配新記憶體，複製資料過去，然後釋放舊的記憶體
        else
        {
            newmem = _int_malloc(av, nb - MALLOC_ALIGN_MASK);
            if (newmem == 0)
                return 0; /* propagate failure */

            newp = mem2chunk(newmem);
            newsize = chunksize(newp);

            /*
               Avoid copy if newp is next chunk after oldp.
             */
            if (newp == next)
            {
                newsize += oldsize;
                newp = oldp;
            }
            else
            {
                void *oldmem = chunk2mem(oldp);
                size_t sz = memsize(oldp);
                (void)tag_region(oldmem, sz);
                newmem = tag_new_usable(newmem);
                memcpy(newmem, oldmem, sz);
                _int_free(av, oldp, 1);
                check_inuse_chunk(av, newp);
                return newmem;
            }
        }
```

## __libc_calloc()

- 作用是會malloc一塊全部為0的記憶體
- 然後可以看到並不會從tcache取出chunk

```c
void *__libc_calloc(size_t n, size_t elem_size)
{
    mstate av;
    mchunkptr oldtop;
    INTERNAL_SIZE_T sz, oldtopsize;
    void *mem;
    unsigned long clearsize;
    unsigned long nclears;
    INTERNAL_SIZE_T *d;
    ptrdiff_t bytes;

    if (__glibc_unlikely(__builtin_mul_overflow(n, elem_size, &bytes)))
    {
        __set_errno(ENOMEM);
        return NULL;
    }

    sz = bytes;

    if (!__malloc_initialized)
        ptmalloc_init();

    MAYBE_INIT_TCACHE();
    //macro if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();

    if (SINGLE_THREAD_P)
        av = &main_arena;
    else
        arena_get(av, sz);

    if (av)
    {
        /* Check if we hand out the top chunk, in which case there may be no
       need to clear. */
#if MORECORE_CLEARS // 不做清零
        oldtop = top(av); // 獲取topchunk
        oldtopsize = chunksize(top(av)); // 獲取topchunk size
#if MORECORE_CLEARS < 2
        /* Only newly allocated memory is guaranteed to be cleared.  */
        // 僅清除 top chunk 之外的部分記憶體
        if (av == &main_arena &&
            oldtopsize < mp_.sbrk_base + av->max_system_mem - (char *)oldtop)
            oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *)oldtop);
#endif
        if (av != &main_arena) // 不在main arena
        {
            heap_info *heap = heap_for_ptr(oldtop);
            if (oldtopsize < (char *)heap + heap->mprotect_size - (char *)oldtop)
                oldtopsize = (char *)heap + heap->mprotect_size - (char *)oldtop; // 確保沒有超過mprotect_size的區域
        }
#endif
    }
    else // 沒有可用的arena
    {
        /* No usable arenas.  */
        oldtop = 0;
        oldtopsize = 0;
    }
    mem = _int_malloc(av, sz);

    assert(!mem || chunk_is_mmapped(mem2chunk(mem)) ||
           av == arena_for_chunk(mem2chunk(mem)));

    if (!SINGLE_THREAD_P) // 多 thread 的情況
    {
        if (mem == 0 && av != NULL)
        {
            LIBC_PROBE(memory_calloc_retry, 1, sz);
            av = arena_get_retry(av, sz);
            mem = _int_malloc(av, sz);
        }

        if (av != NULL)
            __libc_lock_unlock(av->mutex);
    }

    /* Allocation failed even after a retry.  */
    // mem分配失敗
    if (mem == 0)
        return 0;

    mchunkptr p = mem2chunk(mem); //轉換mem成chunk結構

    /* If we are using memory tagging, then we need to set the tags
       regardless of MORECORE_CLEARS, so we zero the whole block while
       doing so.  */
    if (__glibc_unlikely(mtag_enabled))
        return tag_new_zero_region(mem, memsize(p));

    INTERNAL_SIZE_T csz = chunksize(p); // chunk size
```

### 清空mem

```c
    if (chunk_is_mmapped(p)) //透過mmap分配的
    {
        if (__builtin_expect(perturb_byte, 0))
            return memset(mem, 0, sz);

        return mem;
    }

#if MORECORE_CLEARS
    if (perturb_byte == 0 && (p == oldtop && csz > oldtopsize))
    {
        /* clear only the bytes from non-freshly-sbrked memory */
        csz = oldtopsize;
    }
#endif

    /* Unroll clear of <= 36 bytes (72 if 8byte sizes).  We know that
       contents have an odd number of INTERNAL_SIZE_T-sized words;
       minimally 3.  */
    d = (INTERNAL_SIZE_T *)mem; // 
    clearsize = csz - SIZE_SZ; // 要清空的大小 (SIZE_SZ代表作業系統處理器的大小)
    nclears = clearsize / sizeof(INTERNAL_SIZE_T);  // 要清空的大小
    assert(nclears >= 3); // 除了本身的大小之外，還有下一個chunk的prev_size

    if (nclears > 9)
        return memset(d, 0, clearsize); // 清空mem(迴圈方式)

    else // 清空mem
    {
        *(d + 0) = 0;
        *(d + 1) = 0;
        *(d + 2) = 0;
        if (nclears > 4)
        {
            *(d + 3) = 0;
            *(d + 4) = 0;
            if (nclears > 6)
            {
                *(d + 5) = 0;
                *(d + 6) = 0;
                if (nclears > 8)
                {
                    *(d + 7) = 0;
                    *(d + 8) = 0;
                }
            }
        }
    }

    return mem;
}
```

## References

- https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/
- https://www.kn0sky.com/?p=11a87cc5-03f1-4b05-b5ea-c6cda6cce999
- https://blog.csdn.net/Tokameine/article/details/119482061
- https://lowerbyte.github.io/Inside-malloc-part-1-malloc/
- https://github.com/HATTER-LONG/glibc_Learnging/blob/main/Doc/02_内存管理/05_Ptmalloc内存申请分析_下.md
- https://blog.csdn.net/initphp/article/details/132815489