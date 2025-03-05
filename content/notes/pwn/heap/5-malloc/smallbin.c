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
        // 返回mem地址
        void *p = chunk2mem(victim);
        // 加上0x10的header size
        alloc_perturb(p, bytes);
        return p;
    }
}