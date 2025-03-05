for (;;)
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

        /*
           If a small request, try to use last remainder if it is the
           only chunk in unsorted bin.  This helps promote locality for
           runs of consecutive small requests. This is the only
           exception to best-fit, and applies only when there is
           no exact fit for a small chunk.

           如果是small request(小於smallbin max request size，非largebin size)，且這塊是unsortedbin裡面唯一一塊chunk的話，使用last remainder(切割剩下的chunk)
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

            set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0)); // 設定取下的chunk的 chunksize, prev_inuse bit, non_main_arena
            set_head(remainder, remainder_size | PREV_INUSE);                             // 設定remainder的prev_inuse bit 和isze
            set_foot(remainder, remainder_size);                                          // 設定remainder 下一個chunk的prev_size

            check_malloced_chunk(av, victim, nb);
            void *p = chunk2mem(victim);
            alloc_perturb(p, bytes);
            return p;
        }

        /* remove from unsorted list */
        if (__glibc_unlikely(bck->fd != victim))
            malloc_printerr("malloc(): corrupted unsorted chunks 3");
        unsorted_chunks(av)->bk = bck;
        bck->fd = unsorted_chunks(av);

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

        /* place chunk in bin */

        if (in_smallbin_range(size))
        {
            victim_index = smallbin_index(size);
            bck = bin_at(av, victim_index);
            fwd = bck->fd;
        }
        else
        {
            victim_index = largebin_index(size); // 找到對應size的bin index
            bck = bin_at(av, victim_index);      // 使用index找到bin的起始點
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
                    // 從鍊頭開始往下遍歷
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
                victim->fd_nextsize = victim->bk_nextsize = victim; // 如果largebin沒東西的話那就需要構造一下了
        }

        // 放到對應bin中
        mark_bin(av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;

#if USE_TCACHE
        /* If we've processed as many chunks as we're allowed while
       filling the cache, return one of the cached ones.  */
        // 如果對應的tcache滿出來就從tcache拿出一個chunk出來
        ++tcache_unsorted_count;
        if (return_cached && mp_.tcache_unsorted_limit > 0 && tcache_unsorted_count > mp_.tcache_unsorted_limit)
        {
            return tcache_get(tc_idx);
        }
#endif

#define MAX_ITERS 10000
        if (++iters >= MAX_ITERS)
            break;
    }

#if USE_TCACHE
    /* If all the small chunks we found ended up cached, return one now.  */
    // 如果對應的tcache滿出來就從tcache拿出一個chunk出來
    if (return_cached)
    {
        return tcache_get(tc_idx);
    }
#endif

    