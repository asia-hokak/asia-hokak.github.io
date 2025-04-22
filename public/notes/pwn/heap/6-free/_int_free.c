#define USE_TCACHE 1
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

    /*
      If eligible, place chunk on a fastbin so it can be found
      and used quickly in malloc.
    */

    // 如果大小符合fastbin
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

    /*
      Consolidate other non-mmapped chunks as they arrive.
    */

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
                clear_inuse_bit_at_offset(nextchunk, 0);

            /*
          Place the chunk in unsorted chunk list. Chunks are
          not placed into regular bins until after they have
          been given one chance to be used in malloc.
            */

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

    else // mmap出來的，munmap
    {
        munmap_chunk(p);
    }
}