import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Pagination parameters
 */
export interface PaginationParams {
    page: number
    limit: number
    sortBy?: string
    sortOrder?: 'asc' | 'desc'
    search?: string
    filters?: Record<string, any>
}

/**
 * Paginated response from API
 */
export interface PaginatedResponse<T> {
    data: T[]
    pagination: {
        page: number
        limit: number
        total: number
        totalPages: number
        hasNext: boolean
        hasPrev: boolean
    }
    meta?: {
        sortBy?: string
        sortOrder?: string
        search?: string
        filters?: Record<string, any>
    }
}

/**
 * Cache entry with TTL
 */
interface CacheEntry<T> {
    data: T
    timestamp: number
    ttl: number
}

/**
 * Simple in-memory cache for frontend
 */
class FrontendCache {
    private cache: Map<string, CacheEntry<any>> = new Map()

    get<T>(key: string): T | null {
        const entry = this.cache.get(key)
        if (!entry) return null

        if (Date.now() - entry.timestamp > entry.ttl) {
            this.cache.delete(key)
            return null
        }

        return entry.data as T
    }

    set<T>(key: string, data: T, ttl: number = 60000): void {
        this.cache.set(key, { data, timestamp: Date.now(), ttl })
    }

    delete(key: string): void {
        this.cache.delete(key)
    }

    deletePattern(pattern: string): void {
        const regex = new RegExp(pattern)
        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key)
            }
        }
    }

    clear(): void {
        this.cache.clear()
    }
}

// Singleton cache instance
export const frontendCache = new FrontendCache()

// Cache TTL constants
export const CACHE_TTL = {
    SHORT: 30 * 1000,      // 30 seconds
    MEDIUM: 5 * 60 * 1000, // 5 minutes
    LONG: 30 * 60 * 1000,  // 30 minutes
}

/**
 * Hook options
 */
interface UseDataFetchingOptions<T> {
    cacheKey?: string
    cacheTTL?: number
    initialData?: T
    enabled?: boolean
    refetchInterval?: number
    onSuccess?: (data: T) => void
    onError?: (error: Error) => void
}

/**
 * Hook return type
 */
interface UseDataFetchingReturn<T> {
    data: T | null
    loading: boolean
    error: Error | null
    refetch: () => Promise<void>
    invalidate: () => void
}

/**
 * Custom hook for data fetching with caching
 */
export function useDataFetching<T>(
    fetchFn: () => Promise<T>,
    options: UseDataFetchingOptions<T> = {}
): UseDataFetchingReturn<T> {
    const {
        cacheKey,
        cacheTTL = CACHE_TTL.MEDIUM,
        initialData,
        enabled = true,
        refetchInterval,
        onSuccess,
        onError
    } = options

    const [data, setData] = useState<T | null>(initialData ?? null)
    const [loading, setLoading] = useState(!initialData)
    const [error, setError] = useState<Error | null>(null)
    const mountedRef = useRef(true)
    const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

    const fetchData = useCallback(async () => {
        // Check cache first
        if (cacheKey) {
            const cached = frontendCache.get<T>(cacheKey)
            if (cached) {
                setData(cached)
                setLoading(false)
                return
            }
        }

        setLoading(true)
        setError(null)

        try {
            const result = await fetchFn()

            if (!mountedRef.current) return

            setData(result)

            // Cache the result
            if (cacheKey) {
                frontendCache.set(cacheKey, result, cacheTTL)
            }

            onSuccess?.(result)
        } catch (err) {
            if (!mountedRef.current) return

            const error = err instanceof Error ? err : new Error(String(err))
            setError(error)
            onError?.(error)
        } finally {
            if (mountedRef.current) {
                setLoading(false)
            }
        }
    }, [fetchFn, cacheKey, cacheTTL, onSuccess, onError])

    const refetch = useCallback(async () => {
        // Invalidate cache before refetching
        if (cacheKey) {
            frontendCache.delete(cacheKey)
        }
        await fetchData()
    }, [fetchData, cacheKey])

    const invalidate = useCallback(() => {
        if (cacheKey) {
            frontendCache.delete(cacheKey)
        }
        setData(null)
    }, [cacheKey])

    // Initial fetch
    useEffect(() => {
        mountedRef.current = true

        if (enabled) {
            fetchData()
        }

        return () => {
            mountedRef.current = false
        }
    }, [enabled]) // Only depend on enabled, not fetchData to avoid infinite loops

    // Refetch interval
    useEffect(() => {
        if (refetchInterval && enabled) {
            intervalRef.current = setInterval(fetchData, refetchInterval)
        }

        return () => {
            if (intervalRef.current) {
                clearInterval(intervalRef.current)
            }
        }
    }, [refetchInterval, enabled, fetchData])

    return { data, loading, error, refetch, invalidate }
}

/**
 * Hook for paginated data fetching
 */
interface UsePaginatedDataOptions<T> extends UseDataFetchingOptions<PaginatedResponse<T>> {
    initialPage?: number
    initialLimit?: number
}

interface UsePaginatedDataReturn<T> extends UseDataFetchingReturn<PaginatedResponse<T>> {
    page: number
    limit: number
    totalPages: number
    total: number
    hasNext: boolean
    hasPrev: boolean
    goToPage: (page: number) => void
    nextPage: () => void
    prevPage: () => void
    setLimit: (limit: number) => void
}

export function usePaginatedData<T>(
    fetchFn: (params: PaginationParams) => Promise<PaginatedResponse<T>>,
    options: UsePaginatedDataOptions<T> = {}
): UsePaginatedDataReturn<T> {
    const { initialPage = 1, initialLimit = 20, ...restOptions } = options

    const [page, setPage] = useState(initialPage)
    const [limit, setLimitState] = useState(initialLimit)

    const cacheKey = options.cacheKey
        ? `${options.cacheKey}:page:${page}:limit:${limit}`
        : undefined

    const { data, loading, error, refetch, invalidate } = useDataFetching(
        () => fetchFn({ page, limit }),
        { ...restOptions, cacheKey }
    )

    const goToPage = useCallback((newPage: number) => {
        if (newPage >= 1 && (!data || newPage <= data.pagination.totalPages)) {
            setPage(newPage)
        }
    }, [data])

    const nextPage = useCallback(() => {
        if (data?.pagination.hasNext) {
            setPage(p => p + 1)
        }
    }, [data])

    const prevPage = useCallback(() => {
        if (data?.pagination.hasPrev) {
            setPage(p => p - 1)
        }
    }, [data])

    const setLimit = useCallback((newLimit: number) => {
        setLimitState(newLimit)
        setPage(1) // Reset to first page when limit changes
    }, [])

    // Refetch when page or limit changes
    useEffect(() => {
        refetch()
    }, [page, limit])

    return {
        data,
        loading,
        error,
        refetch,
        invalidate,
        page,
        limit,
        totalPages: data?.pagination.totalPages ?? 0,
        total: data?.pagination.total ?? 0,
        hasNext: data?.pagination.hasNext ?? false,
        hasPrev: data?.pagination.hasPrev ?? false,
        goToPage,
        nextPage,
        prevPage,
        setLimit
    }
}

/**
 * Hook for infinite scroll data fetching
 */
interface UseInfiniteDataOptions<T> extends UseDataFetchingOptions<T[]> {
    limit?: number
}

interface UseInfiniteDataReturn<T> {
    data: T[]
    loading: boolean
    loadingMore: boolean
    error: Error | null
    hasMore: boolean
    loadMore: () => Promise<void>
    refetch: () => Promise<void>
    invalidate: () => void
}

export function useInfiniteData<T>(
    fetchFn: (params: { page: number; limit: number }) => Promise<PaginatedResponse<T>>,
    options: UseInfiniteDataOptions<T> = {}
): UseInfiniteDataReturn<T> {
    const { limit = 20, cacheKey, cacheTTL = CACHE_TTL.MEDIUM, enabled = true, onError } = options

    const [data, setData] = useState<T[]>([])
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(true)
    const [loadingMore, setLoadingMore] = useState(false)
    const [error, setError] = useState<Error | null>(null)
    const [hasMore, setHasMore] = useState(true)
    const mountedRef = useRef(true)

    const fetchPage = useCallback(async (pageNum: number, append: boolean = false) => {
        const isFirstPage = pageNum === 1

        if (isFirstPage) {
            setLoading(true)
        } else {
            setLoadingMore(true)
        }
        setError(null)

        try {
            const result = await fetchFn({ page: pageNum, limit })

            if (!mountedRef.current) return

            if (append) {
                setData(prev => [...prev, ...result.data])
            } else {
                setData(result.data)
            }

            setHasMore(result.pagination.hasNext)
            setPage(pageNum)

            // Cache if key provided
            if (cacheKey && isFirstPage) {
                frontendCache.set(cacheKey, result.data, cacheTTL)
            }
        } catch (err) {
            if (!mountedRef.current) return

            const error = err instanceof Error ? err : new Error(String(err))
            setError(error)
            onError?.(error)
        } finally {
            if (mountedRef.current) {
                setLoading(false)
                setLoadingMore(false)
            }
        }
    }, [fetchFn, limit, cacheKey, cacheTTL, onError])

    const loadMore = useCallback(async () => {
        if (!loadingMore && hasMore) {
            await fetchPage(page + 1, true)
        }
    }, [loadingMore, hasMore, page, fetchPage])

    const refetch = useCallback(async () => {
        if (cacheKey) {
            frontendCache.delete(cacheKey)
        }
        setData([])
        setPage(1)
        setHasMore(true)
        await fetchPage(1, false)
    }, [cacheKey, fetchPage])

    const invalidate = useCallback(() => {
        if (cacheKey) {
            frontendCache.delete(cacheKey)
        }
        setData([])
        setPage(1)
        setHasMore(true)
    }, [cacheKey])

    // Initial fetch
    useEffect(() => {
        mountedRef.current = true

        if (enabled) {
            // Check cache first
            if (cacheKey) {
                const cached = frontendCache.get<T[]>(cacheKey)
                if (cached) {
                    setData(cached)
                    setLoading(false)
                    return
                }
            }
            fetchPage(1, false)
        }

        return () => {
            mountedRef.current = false
        }
    }, [enabled])

    return {
        data,
        loading,
        loadingMore,
        error,
        hasMore,
        loadMore,
        refetch,
        invalidate
    }
}

export default {
    useDataFetching,
    usePaginatedData,
    useInfiniteData,
    frontendCache,
    CACHE_TTL
}