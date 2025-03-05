__libc_realloc(void *oldmem, size_t bytes)
{
    mstate ar_ptr;
    INTERNAL_SIZE_T nb; /* padded request size */

    void *newp; /* chunk to return */

    if (!__malloc_initialized) // 初始化(如果沒有)
        ptmalloc_init();

#if REALLOC_ZERO_BYTES_FREES
    if (bytes == 0 && oldmem != NULL)
    {
        __libc_free(oldmem);
        return 0;
    }
#endif

    /* realloc of null is supposed to be same as malloc */
    if (oldmem == 0) // 舊指標為空，可以使用malloc就好了
        return __libc_malloc(bytes);

    /* Perform a quick check to ensure that the pointer's tag matches the
       memory's tag.  */
    // 確保pointer的tag和memory的tag相符
    if (__glibc_unlikely(mtag_enabled))
        *(volatile char *)oldmem;

    /* chunk corresponding to oldmem */
    const mchunkptr oldp = mem2chunk(oldmem);
    /* its size */
    const INTERNAL_SIZE_T oldsize = chunksize(oldp); //取得舊的size

    if (chunk_is_mmapped(oldp))
        ar_ptr = NULL;
    else
    {
        MAYBE_INIT_TCACHE();
        ar_ptr = arena_for_chunk(oldp);
    }

    /* Little security check which won't hurt performance: the allocator
       never wrapps around at the end of the address space.  Therefore
       we can exclude some size values which might appear here by
       accident or by "design" from some intruder.  */
    if ((__builtin_expect((uintptr_t)oldp > (uintptr_t)-oldsize, 0) || __builtin_expect(misaligned_chunk(oldp), 0))) // 確保舊指標沒越界
        malloc_printerr("realloc(): invalid pointer");

    if (!checked_request2size(bytes, &nb))
    {
        __set_errno(ENOMEM);
        return NULL;
    }

    if (chunk_is_mmapped(oldp)) // chunk是否是mmap出來的
    {
        void *newmem;

#if HAVE_MREMAP
        newp = mremap_chunk(oldp, nb); // 擴展記憶體或壓縮記憶體
        if (newp)
        {
            void *newmem = chunk2mem_tag(newp); 
            /* Give the new block a different tag.  This helps to ensure
               that stale handles to the previous mapping are not
               reused.  There's a performance hit for both us and the
               caller for doing this, so we might want to
               reconsider.  */
            return tag_new_usable(newmem);
        }
#endif
        /* Note the extra SIZE_SZ overhead. */
        if (oldsize - SIZE_SZ >= nb) // 不需要更動: 0x10 -> 0x18
            return oldmem; /* do nothing */

        /* Must alloc, copy, free. */
        newmem = __libc_malloc(bytes);
        if (newmem == 0)
            return 0; /* propagate failure */

        memcpy(newmem, oldmem, oldsize - CHUNK_HDR_SZ);
        munmap_chunk(oldp);
        return newmem;
    }

    if (SINGLE_THREAD_P)
    {
        newp = _int_realloc(ar_ptr, oldp, oldsize, nb);
        assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
               ar_ptr == arena_for_chunk(mem2chunk(newp)));

        return newp;
    }

    __libc_lock_lock(ar_ptr->mutex);

    newp = _int_realloc(ar_ptr, oldp, oldsize, nb);

    __libc_lock_unlock(ar_ptr->mutex);
    assert(!newp || chunk_is_mmapped(mem2chunk(newp)) ||
           ar_ptr == arena_for_chunk(mem2chunk(newp)));

    if (newp == NULL) // 當記憶體分配失敗嘗試在其他arena分配
    {
        /* Try harder to allocate memory in other arenas.  */
        LIBC_PROBE(memory_realloc_retry, 2, bytes, oldmem);
        newp = __libc_malloc(bytes);
        if (newp != NULL)
        {
            size_t sz = memsize(oldp);
            memcpy(newp, oldmem, sz);
            (void)tag_region(chunk2mem(oldp), sz);
            _int_free(ar_ptr, oldp, 0);
        }
    }

    return newp;
}