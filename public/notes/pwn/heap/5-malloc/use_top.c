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

        /* When we are using atomic ops to free fast chunks we can get
        here for all block sizes.  */
        // 如果有fastbin就嘗試合併heap
        else if (atomic_load_relaxed(&av->have_fastchunks))
        {
            malloc_consolidate(av);
            /* restore original bin index */
            if (in_smallbin_range(nb))
                idx = smallbin_index(nb); //取出對映smallbin size的idx，會在下一個iteration被處理
            else
                idx = largebin_index(nb); //取出對映largebin size的idx，會在下一個iteration被處理
        }

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