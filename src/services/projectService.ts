import apiClient from '@/lib/api'
import type { Project, ProjectUploadData, ScanStatus, Endpoint, ScanHistoryItem } from '@/types/project'
import { PaginatedResponse, PaginationParams } from '@/hooks/useDataFetching'

export const projectService = {
  /**
   * Get all projects (legacy - no pagination)
   */
  async getProjects(): Promise<Project[]> {
    const { data } = await apiClient.get<Project[]>('/projects')
    return data
  },

  /**
   * Get projects with pagination
   */
  async getProjectsPaginated(params: PaginationParams): Promise<PaginatedResponse<Project>> {
    const { data } = await apiClient.get<PaginatedResponse<Project>>('/projects', {
      params: {
        page: params.page,
        limit: params.limit,
        sortBy: params.sortBy,
        sortOrder: params.sortOrder,
        search: params.search,
        ...params.filters
      }
    })
    return data
  },

  /**
   * Get a single project by ID
   */
  async getProject(id: string): Promise<Project> {
    const { data } = await apiClient.get<Project>(`/projects/${id}`)
    return data
  },

  /**
   * Upload/create a new project
   */
  async uploadProject(projectData: ProjectUploadData): Promise<Project> {
    const { data: project } = await apiClient.post<Project>('/projects', projectData)
    return project
  },

  /**
   * Delete a project
   */
  async deleteProject(id: string): Promise<void> {
    await apiClient.delete(`/projects/${id}`)
  },

  /**
   * Start a security scan for a project
   */
  async startScan(projectId: string): Promise<{ scan_id: string }> {
    const { data } = await apiClient.post<{ scan_id: string }>(`/projects/${projectId}/scan`)
    return data
  },

  /**
   * Get scan status
   */
  async getScanStatus(scanId: string): Promise<import('@/types/project').ScanStatusResponse> {
    const { data } = await apiClient.get<import('@/types/project').ScanStatusResponse>(`/projects/scan/${scanId}`)
    return data
  },

  /**
   * Pause a running scan (placeholder)
   */
  async pauseScan(scanId: string): Promise<void> {
    console.log('Pause scan not implemented in backend MVP')
  },

  /**
   * Stop a running scan (placeholder)
   */
  async stopScan(scanId: string): Promise<void> {
    console.log('Stop scan not implemented in backend MVP')
  },

  /**
   * Get scan logs
   */
  async getScanLogs(scanId: string): Promise<string[]> {
    const { data } = await apiClient.get<string[]>(`/projects/scan/${scanId}/logs`)
    return data
  },

  /**
   * Get project endpoints
   */
  async getProjectEndpoints(projectId: string): Promise<Endpoint[]> {
    const { data } = await apiClient.get<Endpoint[]>(`/projects/${projectId}/endpoints`)
    return data
  },

  /**
   * Get project scan history (legacy - no pagination)
   */
  async getProjectScanHistory(projectId: string): Promise<ScanHistoryItem[]> {
    const { data } = await apiClient.get<ScanHistoryItem[]>(`/projects/${projectId}/history`)
    return data
  },

  /**
   * Get project scan history with pagination
   */
  async getProjectScanHistoryPaginated(
    projectId: string,
    params: PaginationParams
  ): Promise<PaginatedResponse<ScanHistoryItem>> {
    const { data } = await apiClient.get<PaginatedResponse<ScanHistoryItem>>(
      `/projects/${projectId}/history`,
      {
        params: {
          page: params.page,
          limit: params.limit,
          sortBy: params.sortBy,
          sortOrder: params.sortOrder
        }
      }
    )
    return data
  }
}

export default projectService
