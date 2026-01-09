import { supabase } from '../db/supabase';
import * as fs from 'fs';
import * as path from 'path';
import {
    PaginationParams,
    PaginatedResponse,
    calculateOffset,
    createPaginatedResponse,
    DEFAULT_PAGE,
    DEFAULT_LIMIT
} from './paginationUtils';
import { cache, CACHE_TTL, cacheKeys, withCache } from './cacheUtils';

// Logger utility
const LOG_FILE = path.join(__dirname, '../../logs/app.log');

// Ensure log directory exists
try {
    const logDir = path.dirname(LOG_FILE);
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
    }
} catch (e) {
    // Ignore if can't create log directory
}

export enum LogLevel {
    DEBUG = 'DEBUG',
    INFO = 'INFO',
    WARN = 'WARN',
    ERROR = 'ERROR'
}

export function log(level: LogLevel, context: string, message: string, data?: any): void {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        context,
        message,
        data: data ? JSON.stringify(data).substring(0, 500) : undefined
    };

    const logLine = `[${timestamp}] [${level}] [${context}] ${message}${data ? ' | Data: ' + JSON.stringify(data).substring(0, 200) : ''}`;

    // Console output
    switch (level) {
        case LogLevel.ERROR:
            console.error(logLine);
            break;
        case LogLevel.WARN:
            console.warn(logLine);
            break;
        case LogLevel.DEBUG:
            if (process.env.NODE_ENV === 'development') {
                console.log(logLine);
            }
            break;
        default:
            console.log(logLine);
    }

    // File output
    try {
        fs.appendFileSync(LOG_FILE, logLine + '\n');
    } catch (e) {
        // Ignore file write errors
    }
}

// Retry configuration
interface RetryConfig {
    maxRetries: number;
    baseDelay: number;
    maxDelay: number;
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 5000
};

// Sleep utility
function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Calculate exponential backoff delay
function getBackoffDelay(attempt: number, config: RetryConfig): number {
    const delay = Math.min(config.baseDelay * Math.pow(2, attempt), config.maxDelay);
    // Add jitter
    return delay + Math.random() * 1000;
}

// Generic retry wrapper for database operations
export async function withRetry<T>(
    operation: () => Promise<T>,
    context: string,
    config: RetryConfig = DEFAULT_RETRY_CONFIG
): Promise<T> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
        try {
            if (attempt > 0) {
                const delay = getBackoffDelay(attempt - 1, config);
                log(LogLevel.INFO, context, `Retry attempt ${attempt}/${config.maxRetries} after ${Math.round(delay)}ms`);
                await sleep(delay);
            }

            const result = await operation();

            if (attempt > 0) {
                log(LogLevel.INFO, context, `Operation succeeded on retry ${attempt}`);
            }

            return result;
        } catch (error: any) {
            lastError = error;
            log(LogLevel.WARN, context, `Attempt ${attempt + 1} failed: ${error.message}`);

            // Don't retry on certain errors
            if (error.code === 'PGRST116' || // Not found
                error.code === '23505' || // Unique violation
                error.code === '23503') { // Foreign key violation
                throw error;
            }
        }
    }

    log(LogLevel.ERROR, context, `All ${config.maxRetries + 1} attempts failed`, { error: lastError?.message });
    throw lastError;
}

// Database query helpers with retry and validation
export const dbQuery = {
    // Fetch single record with retry
    async fetchOne<T>(
        table: string,
        column: string,
        value: string,
        context: string
    ): Promise<T | null> {
        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Fetching ${table} where ${column}=${value}`);

            const { data, error } = await supabase
                .from(table)
                .select('*')
                .eq(column, value)
                .single();

            if (error) {
                if (error.code === 'PGRST116') {
                    log(LogLevel.WARN, context, `No ${table} found with ${column}=${value}`);
                    return null;
                }
                throw new Error(`Database error: ${error.message}`);
            }

            log(LogLevel.DEBUG, context, `Found ${table} record`, { id: data?.id });
            return data as T;
        }, context);
    },

    // Fetch multiple records with retry
    async fetchMany<T>(
        table: string,
        filters: Record<string, any>,
        context: string,
        options?: { orderBy?: string; ascending?: boolean; limit?: number }
    ): Promise<T[]> {
        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Fetching ${table} with filters`, filters);

            let query = supabase.from(table).select('*');

            // Apply filters
            Object.entries(filters).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    query = query.eq(key, value);
                }
            });

            // Apply ordering
            if (options?.orderBy) {
                query = query.order(options.orderBy, { ascending: options.ascending ?? false });
            }

            // Apply limit
            if (options?.limit) {
                query = query.limit(options.limit);
            }

            const { data, error } = await query;

            if (error) {
                throw new Error(`Database error: ${error.message}`);
            }

            log(LogLevel.DEBUG, context, `Found ${data?.length || 0} ${table} records`);
            return (data || []) as T[];
        }, context);
    },

    // Update record with retry
    async update<T>(
        table: string,
        id: string,
        updates: Partial<T>,
        context: string
    ): Promise<T | null> {
        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Updating ${table} id=${id}`, updates);

            const { data, error } = await supabase
                .from(table)
                .update(updates)
                .eq('id', id)
                .select()
                .single();

            if (error) {
                throw new Error(`Database error: ${error.message}`);
            }

            log(LogLevel.INFO, context, `Updated ${table} id=${id}`);
            return data as T;
        }, context);
    },

    // Insert record with retry
    async insert<T>(
        table: string,
        record: Partial<T>,
        context: string
    ): Promise<T> {
        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Inserting into ${table}`, record);

            const { data, error } = await supabase
                .from(table)
                .insert([record])
                .select()
                .single();

            if (error) {
                throw new Error(`Database error: ${error.message}`);
            }

            log(LogLevel.INFO, context, `Inserted into ${table}`, { id: data?.id });
            return data as T;
        }, context);
    },

    // Fetch paginated records with caching
    async fetchPaginated<T>(
        table: string,
        params: PaginationParams,
        context: string,
        cacheKey?: string,
        cacheTTL?: number
    ): Promise<PaginatedResponse<T>> {
        const { page = DEFAULT_PAGE, limit = DEFAULT_LIMIT, sortBy, sortOrder, filters } = params;
        const offset = calculateOffset(page, limit);

        // Try cache first if cacheKey provided
        if (cacheKey) {
            const cached = cache.get<PaginatedResponse<T>>(cacheKey);
            if (cached) {
                log(LogLevel.DEBUG, context, `Cache hit for ${cacheKey}`);
                return cached;
            }
        }

        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Fetching paginated ${table}`, { page, limit, sortBy, sortOrder, filters });

            // Build query for data
            let query = supabase.from(table).select('*', { count: 'exact' });

            // Apply filters
            if (filters) {
                Object.entries(filters).forEach(([key, value]) => {
                    if (value !== undefined && value !== null) {
                        query = query.eq(key, value);
                    }
                });
            }

            // Apply sorting
            if (sortBy) {
                query = query.order(sortBy, { ascending: sortOrder === 'asc' });
            }

            // Apply pagination
            query = query.range(offset, offset + limit - 1);

            const { data, error, count } = await query;

            if (error) {
                throw new Error(`Database error: ${error.message}`);
            }

            const result = createPaginatedResponse<T>(
                (data || []) as T[],
                count || 0,
                params
            );

            // Cache the result if cacheKey provided
            if (cacheKey) {
                cache.set(cacheKey, result, cacheTTL || CACHE_TTL.SHORT);
                log(LogLevel.DEBUG, context, `Cached result for ${cacheKey}`);
            }

            log(LogLevel.DEBUG, context, `Found ${data?.length || 0} ${table} records (page ${page}/${result.pagination.totalPages})`);
            return result;
        }, context);
    },

    // Count records matching filters
    async count(
        table: string,
        filters: Record<string, any>,
        context: string
    ): Promise<number> {
        return withRetry(async () => {
            log(LogLevel.DEBUG, context, `Counting ${table}`, filters);

            let query = supabase.from(table).select('*', { count: 'exact', head: true });

            Object.entries(filters).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    query = query.eq(key, value);
                }
            });

            const { count, error } = await query;

            if (error) {
                throw new Error(`Database error: ${error.message}`);
            }

            return count || 0;
        }, context);
    },

    // Fetch with caching
    async fetchWithCache<T>(
        table: string,
        column: string,
        value: string,
        context: string,
        cacheKey: string,
        cacheTTL: number = CACHE_TTL.MEDIUM
    ): Promise<T | null> {
        // Try cache first
        const cached = cache.get<T>(cacheKey);
        if (cached) {
            log(LogLevel.DEBUG, context, `Cache hit for ${cacheKey}`);
            return cached;
        }

        // Fetch from database
        const data = await this.fetchOne<T>(table, column, value, context);

        // Cache the result
        if (data) {
            cache.set(cacheKey, data, cacheTTL);
            log(LogLevel.DEBUG, context, `Cached result for ${cacheKey}`);
        }

        return data;
    },

    // Invalidate cache for a table
    invalidateTableCache(table: string): void {
        cache.deletePattern(`^${table}:`);
        log(LogLevel.DEBUG, 'dbQuery', `Invalidated cache for table: ${table}`);
    }
};

// Re-export cache utilities for convenience
export { cache, CACHE_TTL, cacheKeys, withCache };

// Validation helpers
export const validate = {
    // Validate UUID format
    isValidUUID(id: string): boolean {
        if (!id || typeof id !== 'string') return false;
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(id);
    },

    // Validate any ID format (UUID or simple string ID)
    isValidId(id: string): boolean {
        if (!id || typeof id !== 'string') return false;
        // Accept UUIDs or simple alphanumeric IDs with dashes/underscores
        const idRegex = /^[a-zA-Z0-9_-]{1,100}$/;
        return this.isValidUUID(id) || idRegex.test(id);
    },

    // Validate required fields
    hasRequiredFields<T extends object>(obj: T, fields: (keyof T)[]): { valid: boolean; missing: string[] } {
        const missing = fields.filter(field => obj[field] === undefined || obj[field] === null);
        return {
            valid: missing.length === 0,
            missing: missing as string[]
        };
    },

    // Sanitize string input
    sanitizeString(input: string, maxLength: number = 1000): string {
        if (typeof input !== 'string') return '';
        return input.trim().substring(0, maxLength);
    }
};

// Error response helper
export function createErrorResponse(
    res: any,
    statusCode: number,
    message: string,
    context: string,
    details?: any
): void {
    log(LogLevel.ERROR, context, message, details);
    res.status(statusCode).json({
        error: true,
        message,
        details: process.env.NODE_ENV === 'development' ? details : undefined
    });
}

// Success response helper
export function createSuccessResponse<T>(
    res: any,
    data: T,
    context: string,
    message?: string
): void {
    log(LogLevel.INFO, context, message || 'Request successful');
    res.json(data);
}