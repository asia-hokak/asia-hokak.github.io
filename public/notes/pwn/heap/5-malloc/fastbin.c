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
        // single linked list 斷鏈操作
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
            // 返回mem地址
            void *p = chunk2mem(victim);
            // 加上0x10的header size
            alloc_perturb(p, bytes);
            return p;
        }
    }
}