---
title: "Free"
date: 2025-02-23
series: ["Heap Exploitation"]
series_order: 6
---

## __libc_free()

- 其實就是`free()`

```c
__libc_free(void *mem)
{
    mstate ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */

    if (mem == 0) /* free(0) has no effect */
        return;

    /* Quickly check that the freed pointer matches the tag for the memory.
       This gives a useful double-free detection.  */
    if (__glibc_unlikely(mtag_enabled)) // 檢查freed pointer是
        *(volatile char *)mem;

    int err = errno;

    p = mem2chunk(mem);
```

### 檢查是否用mmap出來的chunk

```c
    if (chunk_is_mmapped(p)) /* release mmapped memory. */
    {
        
        /* See if the dynamic brk/mmap threshold needs adjusting.
       Dumped fake mmapped chunks do not affect the threshold.  */
        if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold && chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
            mp_.mmap_threshold = chunksize(p);
            mp_.trim_threshold = 2 * mp_.mmap_threshold;
            LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
                       mp_.mmap_threshold, mp_.trim_threshold);
        }
        munmap_chunk(p); // mmap 出來的東西要用munmap釋放
    }
    else
    {
        MAYBE_INIT_TCACHE(); // 初始化tcache(如果還沒)

        /* Mark the chunk as belonging to the library again.  */
        (void)tag_region(chunk2mem(p), memsize(p));

        ar_ptr = arena_for_chunk(p);
        _int_free(ar_ptr, p, 0);
    }

    __set_errno(err);
}
```

## _int_free()

- 實際在執行free的函數

```c
_int_free(mstate av, mchunkptr p, int have_lock)
{
    INTERNAL_SIZE_T size;     /* its size */
    mfastbinptr *fb;          /* associated fastbin */
    mchunkptr nextchunk;      /* next contiguous chunk */
    INTERNAL_SIZE_T nextsize; /* its size */
    int nextinuse;            /* true if nextchunk is used */
    INTERNAL_SIZE_T prevsize; /* size of previous contiguous chunk */
    mchunkptr bck;            /* misc temp for linking */
    mchunkptr fwd;            /* misc temp for linking */

    size = chunksize(p);

    /* Little security check which won't hurt performance: the
       allocator never wrapps around at the end of the address space.
       Therefore we can exclude some size values which might appear
       here by accident or by "design" from some intruder.  */
    // 檢查指針的有效性，包含大小和對齊
    if (__builtin_expect((uintptr_t)p > (uintptr_t)-size, 0) || __builtin_expect(misaligned_chunk(p), 0))
        malloc_printerr("free(): invalid pointer");
    /* We know that each chunk is at least MINSIZE bytes in size or a
       multiple of MALLOC_ALIGNMENT.  */
    // 檢查大小的有效性(是否對齊)
    if (__glibc_unlikely(size < MINSIZE || !aligned_OK(size)))
        malloc_printerr("free(): invalid size");

    check_inuse_chunk(av, p);
```

### tcache

```c
#if USE_TCACHE
    {
        size_t tc_idx = csize2tidx(size);
        if (tcache != NULL && tc_idx < mp_.tcache_bins) // tcache有空間且被初始化
        {
            /* Check to see if it's already in the tcache.  */
            tcache_entry *e = (tcache_entry *)chunk2mem(p); 

            /* This test succeeds on double free.  However, we don't 100%
               trust it (it also matches random payload data at a 1 in
               2^<size_t> chance), so verify it's not an unlikely
               coincidence before aborting.  */
            if (__glibc_unlikely(e->key == tcache_key))
            {
                tcache_entry *tmp;
                size_t cnt = 0;
                LIBC_PROBE(memory_tcache_double_free, 2, e, tc_idx);
                for (tmp = tcache->entries[tc_idx];
                     tmp;
                     tmp = REVEAL_PTR(tmp->next), ++cnt)
                {
                    if (cnt >= mp_.tcache_count)
                        malloc_printerr("free(): too many chunks detected in tcache"); // tcache 太多chunk
                    if (__glibc_unlikely(!aligned_OK(tmp)))
                        malloc_printerr("free(): unaligned chunk detected in tcache 2"); // tcache 未對齊
                    if (tmp == e)
                        malloc_printerr("free(): double free detected in tcache 2"); // tcache 裡面已經有這個chunk了 (double free)
                    /* If we get here, it was a coincidence.  We've wasted a
                       few cycles, but don't abort.  */
                }
            }

            if (tcache->counts[tc_idx] < mp_.tcache_count)
            {
                tcache_put(p, tc_idx); // 放入tcache
                return;
            }
        }
    }
#endif
```

```c
    if ((unsigned long)(size) <= (unsigned long)(get_max_fast())

#if TRIM_FASTBINS
        /*
      If TRIM_FASTBINS set, don't place chunks
      bordering top into fastbins
        */
        && (chunk_at_offset(p, size) != av->top) // 如果下一個chunk是 top chunk 的話不要放進fastbin
#endif
    )
    {

        if (__builtin_expect(chunksize_nomask(chunk_at_offset(p, size)) <= CHUNK_HDR_SZ, 0) || __builtin_expect(chunksize(chunk_at_offset(p, size)) >= av->system_mem, 0))
        {
            bool fail = true;
            /* We might not have a lock at this point and concurrent modifications
               of system_mem might result in a false positive.  Redo the test after
               getting the lock.  */
            if (!have_lock)
            {
                __libc_lock_lock(av->mutex);
                fail = (chunksize_nomask(chunk_at_offset(p, size)) <= CHUNK_HDR_SZ || chunksize(chunk_at_offset(p, size)) >= av->system_mem);
                __libc_lock_unlock(av->mutex);
            }

            if (fail) // 檢查下一個chunk的大小
                malloc_printerr("free(): invalid next size (fast)");
        }

        free_perturb(chunk2mem(p), size - CHUNK_HDR_SZ); 

        atomic_store_relaxed(&av->have_fastchunks, true);// 因為要存入fastbin
        unsigned int idx = fastbin_index(size);
        fb = &fastbin(av, idx); // 找fastbin對應大小的起始點

        /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
        mchunkptr old = *fb, old2;

        if (SINGLE_THREAD_P)
        {
            /* Check that the top of the bin is not the record we are going to
               add (i.e., double free).  */
            if (__builtin_expect(old == p, 0)) // 檢查fastbin top不是現在正在free的chunk的chunk
                malloc_printerr("double free or corruption (fasttop)");
            p->fd = PROTECT_PTR(&p->fd, old); 
            *fb = p;
        }
        else
            do 
            {
                /* Check that the top of the bin is not the record we are going to
                   add (i.e., double free).  */
                if (__builtin_expect(old == p, 0))
                    malloc_printerr("double free or corruption (fasttop)");
                old2 = old;
                p->fd = PROTECT_PTR(&p->fd, old); //safe linking
            } while ((old = catomic_compare_and_exchange_val_rel(fb, p, old2)) != old2);

        /* Check that size of fastbin chunk at the top is the same as
           size of the chunk that we are adding.  We can dereference OLD
           only if we have the lock, otherwise it might have already been
           allocated again.  */
        if (have_lock && old != NULL && __builtin_expect(fastbin_index(chunksize(old)) != idx, 0))
            malloc_printerr("invalid fastbin entry (free)");
    }
```

### unsortedbin

- 會檢查目前目前chunk附近的chunk，避免heap結構被破壞

```c
// 如果chunk不是被mmap出來的
    else if (!chunk_is_mmapped(p))
    {

        /* If we're single-threaded, don't lock the arena.  */
        if (SINGLE_THREAD_P)
            have_lock = true;

        if (!have_lock)
            __libc_lock_lock(av->mutex);

        nextchunk = chunk_at_offset(p, size);

        /* Lightweight tests: check whether the block is already the
           top block.  */
        if (__glibc_unlikely(p == av->top)) // 如果已經在top chunk裡面
            malloc_printerr("double free or corruption (top)");
        /* Or whether the next chunk is beyond the boundaries of the arena.  */
        if (__builtin_expect(contiguous(av) && (char *)nextchunk >= ((char *)av->top + chunksize(av->top)), 0)) // nextchunk不能超越arena的邊界
            malloc_printerr("double free or corruption (out)");
        /* Or whether the block is actually not marked used.  */
        if (__glibc_unlikely(!prev_inuse(nextchunk))) // 如果nextchunk 的 prev_inuse 已經被unset
            malloc_printerr("double free or corruption (!prev)");

        nextsize = chunksize(nextchunk);
        if (__builtin_expect(chunksize_nomask(nextchunk) <= CHUNK_HDR_SZ, 0) || __builtin_expect(nextsize >= av->system_mem, 0)) // chunk size 不正常
            malloc_printerr("free(): invalid next size (normal)");

        free_perturb(chunk2mem(p), size - CHUNK_HDR_SZ);
```

#### 合併 or 標記為freed chunk

- 這裡執行會檢查前後的chunk是不是freed chunk，如果不是的話就會嘗試合併
- 在請求大chunk的時候為了減少碎片劃，可能會觸發fastbin consolidation


```c
        /* consolidate backward */
        if (!prev_inuse(p)) // 向後合併
        {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long)prevsize));
            if (__glibc_unlikely(chunksize(p) != prevsize))
                malloc_printerr("corrupted size vs. prev_size while consolidating");
            unlink_chunk(av, p);
        }

        if (nextchunk != av->top)
        {
            /* get and clear inuse bit */
            nextinuse = inuse_bit_at_offset(nextchunk, nextsize); // unset下一個chunk的prev_inuse bit

            /* consolidate forward */
            if (!nextinuse) // 向前合併
            {
                unlink_chunk(av, nextchunk);
                size += nextsize;
            }
            else
                clear_inuse_bit_at_offset(nextchunk, 0); // unset nextchunk inuse bit

            /*
          Place the chunk in unsorted chunk list. Chunks are
          not placed into regular bins until after they have
          been given one chance to be used in malloc.
            */

            // 標記為freed chunk
            bck = unsorted_chunks(av);
            fwd = bck->fd;
            if (__glibc_unlikely(fwd->bk != bck))
                malloc_printerr("free(): corrupted unsorted chunks");
            p->fd = fwd; // unlink操作
            p->bk = bck;
            if (!in_smallbin_range(size))
            {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
            }
            bck->fd = p;
            fwd->bk = p;

            set_head(p, size | PREV_INUSE); // 設定freed chunk
            set_foot(p, size);

            check_free_chunk(av, p);
        }

        /*
          If the chunk borders the current high end of memory,
          consolidate into top
        */

        else // 向top chunk合併
        {
            size += nextsize;
            set_head(p, size | PREV_INUSE);
            av->top = p;
            check_chunk(av, p);
        }
```

#### 修剪 chunk

```c
        /*
          If freeing a large space, consolidate possibly-surrounding
          chunks. Then, if the total unused topmost memory exceeds trim
          threshold, ask malloc_trim to reduce top.

          Unless max_fast is 0, we don't know if there are fastbins
          bordering top, so we cannot tell for sure whether threshold
          has been reached unless fastbins are consolidated.  But we
          don't want to consolidate on each free.  As a compromise,
          consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
          is reached.
        */
        // 如果要free的大小大於FASTBIN_CONSOLIDATION_THRESHOLD(觸發fastbin合併的臨界點)
        if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD)
        {
            if (atomic_load_relaxed(&av->have_fastchunks))
                malloc_consolidate(av); //如果有fastchunks就合併

            if (av == &main_arena)
            {
#ifndef MORECORE_CANNOT_TRIM
                if ((unsigned long)(chunksize(av->top)) >=
                    (unsigned long)(mp_.trim_threshold))
                    systrim(mp_.top_pad, av); // top chunk收縮，但不會把記憶體還給系統
#endif
            }
            else
            {
                // 非主分配區直接歸還
                /* Always try heap_trim(), even if the top chunk is not
                   large, because the corresponding heap might go away.  */
                heap_info *heap = heap_for_ptr(top(av));

                assert(heap->ar_ptr == av);
                heap_trim(heap, mp_.top_pad);
            }
        }

        if (!have_lock)
            __libc_lock_unlock(av->mutex);
    }
    /*
      If the chunk was allocated via mmap, release via munmap().
    */
```

### munmap

```c
    /*
      If the chunk was allocated via mmap, release via munmap().
    */

    else // mmap出來的，munmap
    {
        munmap_chunk(p);
    }
}
```

## malloc_consolidate()

- 這個函數主要用來合併fastbin的

```c
static void malloc_consolidate(mstate av)
{
    mfastbinptr *fb;          /* current fastbin being consolidated */
    mfastbinptr *maxfb;       /* last fastbin (for loop control) */
    mchunkptr p;              /* current chunk being consolidated */
    mchunkptr nextp;          /* next chunk to consolidate */
    mchunkptr unsorted_bin;   /* bin header */
    mchunkptr first_unsorted; /* chunk to link to */

    /* These have same use as in free() */
    mchunkptr nextchunk;
    INTERNAL_SIZE_T size;
    INTERNAL_SIZE_T nextsize;
    INTERNAL_SIZE_T prevsize;
    int nextinuse;

    atomic_store_relaxed(&av->have_fastchunks, false); // 清空fastbin標記

    unsorted_bin = unsorted_chunks(av);

    /*
      Remove each chunk from fast bin and consolidate it, placing it
      then in unsorted bin. Among other reasons for doing this,
      placing in unsorted bin avoids needing to calculate actual bins
      until malloc is sure that chunks aren't immediately going to be
      reused anyway.
    */
    // 按照fd順序依序合併每個chunk
```

### 開始遍歷 + 檢查

```c
    maxfb = &fastbin(av, NFASTBINS - 1); // 總共幾個fastbin鏈
    fb = &fastbin(av, 0);
    do // 以bin為單位遍歷
    {
        p = atomic_exchange_acq(fb, NULL);
        if (p != 0) // 以chunk為單位變歷
        {
            do
            {
                {
                    if (__glibc_unlikely(misaligned_chunk(p))) // 檢查是否隊齊
                        malloc_printerr("malloc_consolidate(): unaligned fastbin chunk detected");

                    unsigned int idx = fastbin_index(chunksize(p));
                    if ((&fastbin(av, idx)) != fb) // 檢查大小是否正確
                        malloc_printerr("malloc_consolidate(): invalid chunk size");
                }
                check_inuse_chunk(av, p);
                nextp = REVEAL_PTR(p->fd); // 下一個fastbin

                /* Slightly streamlined version of consolidation code in free() */
                size = chunksize(p);
                nextchunk = chunk_at_offset(p, size);
                nextsize = chunksize(nextchunk);
```

#### 向前(低位)合併

```c
                if (!prev_inuse(p)) // 向前(低位)合併
                {
                    prevsize = prev_size(p);
                    size += prevsize;
                    p = chunk_at_offset(p, -((long)prevsize));
                    if (__glibc_unlikely(chunksize(p) != prevsize))
                        malloc_printerr("corrupted size vs. prev_size in fastbins");
                    unlink_chunk(av, p);
                }
```

#### 向後合併

```c
                if (nextchunk != av->top)
                {
                    nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

                    if (!nextinuse) // 如果下一個chunk是freed，向前合併
                    {
                        size += nextsize;
                        unlink_chunk(av, nextchunk);
                    }
```

#### 丟進unsorted bin

```c
                else
                        clear_inuse_bit_at_offset(nextchunk, 0);
                    // 丟進unsortedbin
                    first_unsorted = unsorted_bin->fd;
                    unsorted_bin->fd = p;
                    first_unsorted->bk = p;

                    if (!in_smallbin_range(size))
                    {
                        p->fd_nextsize = NULL;
                        p->bk_nextsize = NULL;
                    }

                    set_head(p, size | PREV_INUSE);
                    p->bk = unsorted_bin;
                    p->fd = first_unsorted;
                    set_foot(p, size);
                }
```

#### 向top chunk合併

```c
                else // 向top chunk合併
                {
                    size += nextsize;
                    set_head(p, size | PREV_INUSE);
                    av->top = p;
                }
```

#### 結束迴圈

```c
           } while ((p = nextp) != 0);
        }
    } while (fb++ != maxfb);
```

## Reference

- https://www.kn0sky.com/?p=e81d8a0c-22b2-4263-910f-955664c3995c