/**
 * Pagination utilities for handling large datasets
 */

export interface PaginationParams {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
    search?: string;
    filters?: Record<string, any>;
}

export interface PaginatedResponse<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
    };
    meta?: {
        sortBy?: string;
        sortOrder?: string;
        search?: string;
        filters?: Record<string, any>;
    };
}

// Default pagination values
export const DEFAULT_PAGE = 1;
export const DEFAULT_LIMIT = 20;
export const MAX_LIMIT = 100;

/**
 * Parse and validate pagination parameters from request query
 */
export function parsePaginationParams(query: any): PaginationParams {
    const page = Math.max(1, parseInt(query.page) || DEFAULT_PAGE);
    const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(query.limit) || DEFAULT_LIMIT));
    const sortBy = query.sortBy || 'created_at';
    const sortOrder = query.sortOrder === 'asc' ? 'asc' : 'desc';
    const search = query.search?.trim() || undefined;

    // Parse filters from query
    const filters: Record<string, any> = {};
    const filterKeys = ['status', 'type', 'severity', 'project_id'];

    filterKeys.forEach(key => {
        if (query[key]) {
            filters[key] = query[key];
        }
    });

    return { page, limit, sortBy, sortOrder, search, filters };
}

/**
 * Calculate pagination metadata
 */
export function calculatePagination(
    total: number,
    page: number,
    limit: number
): PaginatedResponse<any>['pagination'] {
    const totalPages = Math.ceil(total / limit);

    return {
        page,
        limit,
        total,
        totalPages,
        hasNext: page < totalPages,
        hasPrev: page > 1
    };
}

/**
 * Calculate offset for database query
 */
export function calculateOffset(page: number, limit: number): number {
    return (page - 1) * limit;
}

/**
 * Create a paginated response
 */
export function createPaginatedResponse<T>(
    data: T[],
    total: number,
    params: PaginationParams
): PaginatedResponse<T> {
    const { page = DEFAULT_PAGE, limit = DEFAULT_LIMIT, sortBy, sortOrder, search, filters } = params;

    return {
        data,
        pagination: calculatePagination(total, page, limit),
        meta: {
            sortBy,
            sortOrder,
            search,
            filters
        }
    };
}

/**
 * Apply cursor-based pagination (for infinite scroll)
 */
export interface CursorPaginationParams {
    cursor?: string;
    limit?: number;
    direction?: 'forward' | 'backward';
}

export interface CursorPaginatedResponse<T> {
    data: T[];
    cursors: {
        next: string | null;
        prev: string | null;
    };
    hasMore: boolean;
}

/**
 * Parse cursor pagination parameters
 */
export function parseCursorParams(query: any): CursorPaginationParams {
    return {
        cursor: query.cursor || undefined,
        limit: Math.min(MAX_LIMIT, Math.max(1, parseInt(query.limit) || DEFAULT_LIMIT)),
        direction: query.direction === 'backward' ? 'backward' : 'forward'
    };
}

/**
 * Create cursor-based paginated response
 */
export function createCursorResponse<T extends { id: string }>(
    data: T[],
    limit: number,
    hasMore: boolean
): CursorPaginatedResponse<T> {
    return {
        data,
        cursors: {
            next: hasMore && data.length > 0 ? data[data.length - 1].id : null,
            prev: data.length > 0 ? data[0].id : null
        },
        hasMore
    };
}

export default {
    parsePaginationParams,
    calculatePagination,
    calculateOffset,
    createPaginatedResponse,
    parseCursorParams,
    createCursorResponse,
    DEFAULT_PAGE,
    DEFAULT_LIMIT,
    MAX_LIMIT
};