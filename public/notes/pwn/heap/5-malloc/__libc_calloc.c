void *__libc_calloc(size_t n, size_t elem_size)
{
    mstate av;
    mchunkptr oldtop;
    INTERNAL_SIZE_T sz, oldtopsize;
    void *mem;
    unsigned long clearsize;
    unsigned long nclears;
    INTERNAL_SIZE_T *d;
    ptrdiff_t bytes;

    if (__glibc_unlikely(__builtin_mul_overflow(n, elem_size, &bytes)))
    {
        __set_errno(ENOMEM);
        return NULL;
    }

    sz = bytes;

    if (!__malloc_initialized)
        ptmalloc_init();

    MAYBE_INIT_TCACHE();
    //macro if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();

    if (SINGLE_THREAD_P)
        av = &main_arena;
    else
        arena_get(av, sz);

    if (av)
    {
        /* Check if we hand out the top chunk, in which case there may be no
       need to clear. */
#if MORECORE_CLEARS // 不做清零
        oldtop = top(av); // 獲取topchunk
        oldtopsize = chunksize(top(av)); // 獲取topchunk size
#if MORECORE_CLEARS < 2
        /* Only newly allocated memory is guaranteed to be cleared.  */
        // 僅清除 top chunk 之外的部分記憶體
        if (av == &main_arena &&
            oldtopsize < mp_.sbrk_base + av->max_system_mem - (char *)oldtop)
            oldtopsize = (mp_.sbrk_base + av->max_system_mem - (char *)oldtop);
#endif
        if (av != &main_arena) // 不在main arena
        {
            heap_info *heap = heap_for_ptr(oldtop);
            if (oldtopsize < (char *)heap + heap->mprotect_size - (char *)oldtop)
                oldtopsize = (char *)heap + heap->mprotect_size - (char *)oldtop; // 確保沒有超過mprotect_size的區域
        }
#endif
    }
    else // 沒有可用的arena
    {
        /* No usable arenas.  */
        oldtop = 0;
        oldtopsize = 0;
    }
    mem = _int_malloc(av, sz);

    assert(!mem || chunk_is_mmapped(mem2chunk(mem)) ||
           av == arena_for_chunk(mem2chunk(mem)));

    if (!SINGLE_THREAD_P) // 多 thread 的情況
    {
        if (mem == 0 && av != NULL)
        {
            LIBC_PROBE(memory_calloc_retry, 1, sz);
            av = arena_get_retry(av, sz);
            mem = _int_malloc(av, sz);
        }

        if (av != NULL)
            __libc_lock_unlock(av->mutex);
    }

    /* Allocation failed even after a retry.  */
    // mem分配失敗
    if (mem == 0)
        return 0;

    mchunkptr p = mem2chunk(mem); //轉換mem成chunk結構

    /* If we are using memory tagging, then we need to set the tags
       regardless of MORECORE_CLEARS, so we zero the whole block while
       doing so.  */
    if (__glibc_unlikely(mtag_enabled))
        return tag_new_zero_region(mem, memsize(p));

    INTERNAL_SIZE_T csz = chunksize(p); // chunk size

    /* Two optional cases in which clearing not necessary */
    if (chunk_is_mmapped(p)) //透過mmap分配的
    {
        if (__builtin_expect(perturb_byte, 0))
            return memset(mem, 0, sz);

        return mem;
    }

#if MORECORE_CLEARS
    if (perturb_byte == 0 && (p == oldtop && csz > oldtopsize))
    {
        /* clear only the bytes from non-freshly-sbrked memory */
        csz = oldtopsize;
    }
#endif

    /* Unroll clear of <= 36 bytes (72 if 8byte sizes).  We know that
       contents have an odd number of INTERNAL_SIZE_T-sized words;
       minimally 3.  */
    d = (INTERNAL_SIZE_T *)mem; // 
    clearsize = csz - SIZE_SZ; // 要清空的大小 (SIZE_SZ代表作業系統處理器的大小)
    nclears = clearsize / sizeof(INTERNAL_SIZE_T);  // 要清空的大小
    assert(nclears >= 3); // 除了本身的大小之外，還有下一個chunk的prev_size

    if (nclears > 9)
        return memset(d, 0, clearsize); // 清空mem(迴圈方式)

    else // 清空mem
    {
        *(d + 0) = 0;
        *(d + 1) = 0;
        *(d + 2) = 0;
        if (nclears > 4)
        {
            *(d + 3) = 0;
            *(d + 4) = 0;
            if (nclears > 6)
            {
                *(d + 5) = 0;
                *(d + 6) = 0;
                if (nclears > 8)
                {
                    *(d + 7) = 0;
                    *(d + 8) = 0;
                }
            }
        }
    }

    return mem;
}