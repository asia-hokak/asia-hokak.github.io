__libc_free(void *mem)
{
    mstate ar_ptr;
    mchunkptr p; /* chunk corresponding to mem */

    if (mem == 0) /* free(0) has no effect */
        return;

    /* Quickly check that the freed pointer matches the tag for the memory.
       This gives a useful double-free detection.  */
    if (__glibc_unlikely(mtag_enabled)) // 檢查freed pointer是
        *(volatile char *)mem;

    int err = errno;

    p = mem2chunk(mem);

    if (chunk_is_mmapped(p)) /* release mmapped memory. */
    {
        
        /* See if the dynamic brk/mmap threshold needs adjusting.
       Dumped fake mmapped chunks do not affect the threshold.  */
        if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold && chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
            mp_.mmap_threshold = chunksize(p);
            mp_.trim_threshold = 2 * mp_.mmap_threshold;
            LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,
                       mp_.mmap_threshold, mp_.trim_threshold);
        }
        munmap_chunk(p); // mmap 出來的東西要用munmap釋放
    }
    else
    {
        MAYBE_INIT_TCACHE(); // 初始化tcache(如果還沒)

        /* Mark the chunk as belonging to the library again.  */
        (void)tag_region(chunk2mem(p), memsize(p));

        ar_ptr = arena_for_chunk(p);
        _int_free(ar_ptr, p, 0);
    }

    __set_errno(err);
}

