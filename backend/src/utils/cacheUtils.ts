/**
 * In-memory cache utility with TTL support
 * For production, consider using Redis or similar
 */

interface CacheEntry<T> {
    data: T;
    timestamp: number;
    ttl: number;
}

class MemoryCache {
    private cache: Map<string, CacheEntry<any>> = new Map();
    private cleanupInterval: NodeJS.Timeout | null = null;

    constructor() {
        // Run cleanup every minute
        this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    }

    /**
     * Get cached data
     */
    get<T>(key: string): T | null {
        const entry = this.cache.get(key);

        if (!entry) {
            return null;
        }

        // Check if expired
        if (Date.now() - entry.timestamp > entry.ttl) {
            this.cache.delete(key);
            return null;
        }

        return entry.data as T;
    }

    /**
     * Set cached data with TTL (in milliseconds)
     */
    set<T>(key: string, data: T, ttl: number = 60000): void {
        this.cache.set(key, {
            data,
            timestamp: Date.now(),
            ttl
        });
    }

    /**
     * Delete cached data
     */
    delete(key: string): boolean {
        return this.cache.delete(key);
    }

    /**
     * Delete all cached data matching a pattern
     */
    deletePattern(pattern: string): number {
        let deleted = 0;
        const regex = new RegExp(pattern);

        for (const key of this.cache.keys()) {
            if (regex.test(key)) {
                this.cache.delete(key);
                deleted++;
            }
        }

        return deleted;
    }

    /**
     * Clear all cached data
     */
    clear(): void {
        this.cache.clear();
    }

    /**
     * Get cache statistics
     */
    stats(): { size: number; keys: string[] } {
        return {
            size: this.cache.size,
            keys: Array.from(this.cache.keys())
        };
    }

    /**
     * Cleanup expired entries
     */
    private cleanup(): void {
        const now = Date.now();

        for (const [key, entry] of this.cache.entries()) {
            if (now - entry.timestamp > entry.ttl) {
                this.cache.delete(key);
            }
        }
    }

    /**
     * Destroy the cache (cleanup interval)
     */
    destroy(): void {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        this.cache.clear();
    }
}

// Singleton instance
export const cache = new MemoryCache();

// Cache TTL constants (in milliseconds)
export const CACHE_TTL = {
    SHORT: 30 * 1000,        // 30 seconds
    MEDIUM: 5 * 60 * 1000,   // 5 minutes
    LONG: 30 * 60 * 1000,    // 30 minutes
    HOUR: 60 * 60 * 1000,    // 1 hour
};

// Cache key generators
export const cacheKeys = {
    projects: () => 'projects:list',
    project: (id: string) => `projects:${id}`,
    projectEndpoints: (id: string) => `projects:${id}:endpoints`,
    projectHistory: (id: string) => `projects:${id}:history`,
    scan: (id: string) => `scans:${id}`,
    scanStatus: (id: string) => `scans:${id}:status`,
    attackGraph: (scanId: string) => `attack-graph:${scanId}`,
    nodeDetails: (nodeId: string) => `nodes:${nodeId}`,
    report: (scanId: string) => `reports:${scanId}`,
    vulnerabilities: (projectId: string, page: number) => `vulnerabilities:${projectId}:page:${page}`,
};

/**
 * Cache decorator for async functions
 */
export function withCache<T>(
    key: string,
    ttl: number,
    fn: () => Promise<T>
): Promise<T> {
    const cached = cache.get<T>(key);

    if (cached !== null) {
        return Promise.resolve(cached);
    }

    return fn().then(data => {
        cache.set(key, data, ttl);
        return data;
    });
}

/**
 * Invalidate cache when data changes
 */
export function invalidateCache(patterns: string[]): void {
    patterns.forEach(pattern => {
        cache.deletePattern(pattern);
    });
}

export default cache;