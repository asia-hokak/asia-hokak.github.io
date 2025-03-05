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
 
             /* Exhaust */
             // 切割後的size不能做為一個chunk
             if (remainder_size < MINSIZE)
             {
                 set_inuse_bit_at_offset(victim, size);
                 if (av != &main_arena)
                     set_non_main_arena(victim);
             }
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
             check_malloced_chunk(av, victim, nb);
             // 轉為mem型態
             void *p = chunk2mem(victim);
             alloc_perturb(p, bytes);
             return p;
         }
     }