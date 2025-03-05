__libc_malloc(size_t bytes)
{
    mstate ar_ptr;
    void *victim;

    _Static_assert(PTRDIFF_MAX <= SIZE_MAX / 2,
                   "PTRDIFF_MAX is not more than half of SIZE_MAX");

    if (!__malloc_initialized) // 檢查heap是否被初始化
        ptmalloc_init(); // 執行malloc 初始化
#if USE_TCACHE
    /* int_free also calls request2size, be careful to not pad twice.  */
    size_t tbytes;
    if (!checked_request2size(bytes, &tbytes)) // 確保分配大小正常
    {
        __set_errno(ENOMEM);
        return NULL;
    }
    size_t tc_idx = csize2tidx(tbytes);

    MAYBE_INIT_TCACHE();

    DIAG_PUSH_NEEDS_COMMENT;
    if (tc_idx < mp_.tcache_bins && tcache && tcache->counts[tc_idx] > 0) // 如果tcache有東西
    {
        victim = tcache_get(tc_idx);
        return tag_new_usable(victim);
    }
    DIAG_POP_NEEDS_COMMENT;
#endif

    if (SINGLE_THREAD_P) // 在單thread的情況下
    {
        victim = tag_new_usable(_int_malloc(&main_arena, bytes));
        assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
               &main_arena == arena_for_chunk(mem2chunk(victim)));
        return victim;
    }

    arena_get(ar_ptr, bytes); // 獲取arena

    victim = _int_malloc(ar_ptr, bytes);
    /* Retry with another arena only if we were able to find a usable arena
       before.  */
    if (!victim && ar_ptr != NULL) // 如果分配失敗
    {
        LIBC_PROBE(memory_malloc_retry, 1, bytes);
        ar_ptr = arena_get_retry(ar_ptr, bytes); // 使用其他arena
        victim = _int_malloc(ar_ptr, bytes);
    }

    if (ar_ptr != NULL)
        __libc_lock_unlock(ar_ptr->mutex); // 在多thread的情況下會上鎖arena，這裡解鎖表示arena使用結束

    victim = tag_new_usable(victim);

    assert(!victim || chunk_is_mmapped(mem2chunk(victim)) ||
           ar_ptr == arena_for_chunk(mem2chunk(victim))); // 檢查 victim不為空 | victim是透過mmap分配 | victim是來自正確的arena，
    return victim;
}