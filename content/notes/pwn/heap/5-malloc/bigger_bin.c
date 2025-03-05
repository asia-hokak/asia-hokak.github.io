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
++idx;                   // 下一個bin的索引值
bin = bin_at(av, idx);   // 下一個bin的指標位置
block = idx2block(idx);  // 將idx轉成block，block一共四個，大小128，idx 0-31 為0，idx 32-63 為1，以此類推
map = av->binmap[block]; // 獲取map
bit = idx2bit(idx);      // 將idx轉回bit

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

    else
    {
        size = chunksize(victim);

        /*  We know the first chunk in this bin is big enough to use. */
        assert((unsigned long)(size) >= (unsigned long)(nb));

        remainder_size = size - nb;

        /* unlink */
        unlink_chunk(av, victim);

        /* Exhaust */
        // 切割剩下的size不足成為一個chunk
        if (remainder_size < MINSIZE)
        {
            set_inuse_bit_at_offset(victim, size);
            if (av != &main_arena)
                set_non_main_arena(victim);
        }

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
        check_malloced_chunk(av, victim, nb);
        void *p = chunk2mem(victim);
        alloc_perturb(p, bytes);
        return p;
    }
}