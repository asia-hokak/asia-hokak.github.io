for (;;)
{
    int iters = 0;
    while ((victim = unsorted_chunks(av)->bk) != unsorted_chunks(av))
    {
        bck = victim->bk;
        size = chunksize(victim);
        mchunkptr next = chunk_at_offset(victim, size);

        if (__glibc_unlikely(size <= CHUNK_HDR_SZ) || __glibc_unlikely(size > av->system_mem))
            malloc_printerr("malloc(): invalid size (unsorted)");
        if (__glibc_unlikely(chunksize_nomask(next) < CHUNK_HDR_SZ) || __glibc_unlikely(chunksize_nomask(next) > av->system_mem))
            malloc_printerr("malloc(): invalid next size (unsorted)");
        if (__glibc_unlikely((prev_size(next) & ~(SIZE_BITS)) != size))
            malloc_printerr("malloc(): mismatching next->prev_size (unsorted)");
        if (__glibc_unlikely(bck->fd != victim) || __glibc_unlikely(victim->fd != unsorted_chunks(av)))
            malloc_printerr("malloc(): unsorted double linked list corrupted");
        if (__glibc_unlikely(prev_inuse(next)))
            malloc_printerr("malloc(): invalid next->prev_inuse (unsorted)");

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
            remainder_size = size - nb;
            remainder = chunk_at_offset(victim, nb);
            unsorted_chunks(av)->bk = unsorted_chunks(av)->fd = remainder;
            av->last_remainder = remainder;
            remainder->bk = remainder->fd = unsorted_chunks(av);
            if (!in_smallbin_range(remainder_size))
            {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
            }

            set_head(victim, nb | PREV_INUSE |
                                 (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head(remainder, remainder_size | PREV_INUSE);
            set_foot(remainder, remainder_size);

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
            victim_index = largebin_index(size);
            bck = bin_at(av, victim_index);
            fwd = bck->fd;

            /* maintain large bins in sorted order */
            if (fwd != bck)
            {
                /* Or with inuse bit to speed comparisons */
                size |= PREV_INUSE;
                /* if smaller than smallest, bypass loop below */
                assert(chunk_main_arena(bck->bk));
                if ((unsigned long)(size) < (unsigned long)chunksize_nomask(bck->bk))
                {
                    fwd = bck;
                    bck = bck->bk;

                    victim->fd_nextsize = fwd->fd;
                    victim->bk_nextsize = fwd->fd->bk_nextsize;
                    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                }
                else
                {
                    assert(chunk_main_arena(fwd));
                    while ((unsigned long)size < chunksize_nomask(fwd))
                    {
                        fwd = fwd->fd_nextsize;
                        assert(chunk_main_arena(fwd));
                    }

                    if ((unsigned long)size == (unsigned long)chunksize_nomask(fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                    else
                    {
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
                victim->fd_nextsize = victim->bk_nextsize = victim;
        }

        mark_bin(av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;

#if USE_TCACHE
        /* If we've processed as many chunks as we're allowed while
       filling the cache, return one of the cached ones.  */
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
    if (return_cached)
    {
        return tcache_get(tc_idx);
    }
#endif

    /*
       If a large request, scan through the chunks of current bin in
       sorted order to find smallest that fits.  Use the skip list for this.
     */

    if (!in_smallbin_range(nb))
    {
        bin = bin_at(av, idx);

        /* skip scan if empty or largest chunk is too small */
        if ((victim = first(bin)) != bin && (unsigned long)chunksize_nomask(victim) >= (unsigned long)(nb))
        {
            victim = victim->bk_nextsize;
            while (((unsigned long)(size = chunksize(victim)) <
                    (unsigned long)(nb)))
                victim = victim->bk_nextsize;

            /* Avoid removing the first entry for a size so that the skip
               list does not have to be rerouted.  */
            if (victim != last(bin) && chunksize_nomask(victim) == chunksize_nomask(victim->fd))
                victim = victim->fd;

            remainder_size = size - nb;
            unlink_chunk(av, victim);

            /* Exhaust */
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
                remainder->bk = bck;
                remainder->fd = fwd;
                bck->fd = remainder;
                fwd->bk = remainder;
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
    ++idx;
    bin = bin_at(av, idx);
    block = idx2block(idx);
    map = av->binmap[block];
    bit = idx2bit(idx);

    for (;;)
    {
        /* Skip rest of block if there are no more set bits in this block.  */
        if (bit > map || bit == 0)
        {
            do
            {
                if (++block >= BINMAPSIZE) /* out of bins */
                    goto use_top;
            } while ((map = av->binmap[block]) == 0);

            bin = bin_at(av, (block << BINMAPSHIFT));
            bit = 1;
        }

        /* Advance to bin with set bit. There must be one. */
        while ((bit & map) == 0)
        {
            bin = next_bin(bin);
            bit <<= 1;
            assert(bit != 0);
        }

        /* Inspect the bin. It is likely to be non-empty */
        victim = last(bin);

        /*  If a false alarm (empty bin), clear the bit. */
        if (victim == bin)
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

use_top:
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

    victim = av->top;
    size = chunksize(victim);

    if (__glibc_unlikely(size > av->system_mem))
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
    else if (atomic_load_relaxed(&av->have_fastchunks))
    {
        malloc_consolidate(av);
        /* restore original bin index */
        if (in_smallbin_range(nb))
            idx = smallbin_index(nb);
        else
            idx = largebin_index(nb);
    }

    /*
       Otherwise, relay to handle system-dependent cases
     */
    else
    {
        void *p = sysmalloc(nb, av);
        if (p != NULL)
            alloc_perturb(p, bytes);
        return p;
    }
}