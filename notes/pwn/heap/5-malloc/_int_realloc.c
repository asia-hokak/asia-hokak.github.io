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

    if ((unsigned long)(oldsize) >= (unsigned long)(nb))
    {
        /* already big enough; split below */
        newp = oldp;
        newsize = oldsize;
    }

    else
    {
        /* Try to expand forward into top */
        // 嘗試向top擴展
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

        /* Try to expand forward into next chunk;  split off remainder below */
        // 向下擴展，並切割
        else if (next != av->top &&
                 !inuse(next) &&
                 (unsigned long)(newsize = oldsize + nextsize) >=
                     (unsigned long)(nb))
        {
            newp = oldp;
            unlink_chunk(av, next);
        }

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
    }
}