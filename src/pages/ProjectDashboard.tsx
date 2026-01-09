import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { projectService } from '@/services/projectService'
import { useProjectStore } from '@/stores/projectStore'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle
} from '@/components/ui/dialog'
import {
  Plus,
  FolderOpen,
  ExternalLink,
  Trash2,
  Play,
  AlertTriangle,
  Loader2,
  Eye,
  LayoutGrid,
  List
} from 'lucide-react'
import { formatDate } from '@/lib/utils'
import { useToast } from '@/components/ui/use-toast'
import type { Project } from '@/types/project'

export default function ProjectDashboard() {
  const navigate = useNavigate()
  const { projects, setProjects, removeProject } = useProjectStore()
  const [loading, setLoading] = useState(true)
  const toast = useToast()

  // View state
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')

  // Delete dialog state
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [projectToDelete, setProjectToDelete] = useState<Project | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  useEffect(() => {
    loadProjects()
  }, [])

  const loadProjects = async () => {
    try {
      setLoading(true)
      const data = await projectService.getProjects()
      setProjects(data)
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to load projects', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  const handleStartScan = async (projectId: string) => {
    try {
      const { scan_id } = await projectService.startScan(projectId)
      navigate(`/dashboard/scan/${projectId}?scanId=${scan_id}`)
    } catch (error: any) {
      toast({ title: 'Error', description: 'Failed to start scan', variant: 'destructive' })
    }
  }

  const openDeleteDialog = (project: Project) => {
    setProjectToDelete(project)
    setDeleteDialogOpen(true)
  }

  const closeDeleteDialog = () => {
    setDeleteDialogOpen(false)
    setProjectToDelete(null)
  }

  const handleDeleteProject = async () => {
    if (!projectToDelete) return

    setIsDeleting(true)
    try {
      await projectService.deleteProject(projectToDelete.id)
      removeProject(projectToDelete.id)
      toast({
        title: 'Project Deleted',
        description: `"${projectToDelete.name}" has been permanently deleted.`
      })
      closeDeleteDialog()
    } catch (error: any) {
      toast({
        title: 'Delete Failed',
        description: error.message || 'Failed to delete project. Please try again.',
        variant: 'destructive'
      })
    } finally {
      setIsDeleting(false)
    }
  }

  // Calculate total vulnerabilities for a project
  const getTotalVulnerabilities = (project: Project) => {
    if (!project.vulnerability_counts) return 0
    return (
      project.vulnerability_counts.critical +
      project.vulnerability_counts.high +
      project.vulnerability_counts.medium +
      project.vulnerability_counts.low
    )
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Projects</h1>
            <p className="text-muted-foreground">Manage your security scan projects</p>
          </div>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-6 w-3/4" />
                <Skeleton className="h-4 w-1/2 mt-2" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Projects</h1>
          <p className="text-muted-foreground">Manage your security scan projects</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center bg-muted/50 p-1 rounded-lg border">
            <Button
              variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
              size="sm"
              className="h-8 w-8 p-0"
              onClick={() => setViewMode('grid')}
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'list' ? 'secondary' : 'ghost'}
              size="sm"
              className="h-8 w-8 p-0"
              onClick={() => setViewMode('list')}
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
          <Button onClick={() => navigate('/dashboard/upload')}>
            <Plus className="mr-2 h-4 w-4" />
            Create Project
          </Button>
        </div>
      </div>

      {projects.length === 0 ? (
        <Card className="p-12 text-center bg-card border-yellow-green/30">
          <div className="h-16 w-16 rounded-2xl bg-yellow-green flex items-center justify-center mx-auto mb-4 border-2 border-yellow-green shadow-lg shadow-yellow-green/50">
            <FolderOpen className="h-8 w-8 text-background" />
          </div>
          <h3 className="text-lg font-bold mb-2 text-primary">No projects yet</h3>
          <p className="text-dim-grey-light mb-4">
            Upload an API spec or codebase to start scanning for vulnerabilities
          </p>
          <Button
            onClick={() => navigate('/dashboard/upload')}
            className="bg-yellow-green hover:bg-yellow-green/90 text-background shadow-lg shadow-yellow-green/50 font-bold"
          >
            <Plus className="mr-2 h-4 w-4" />
            Create Project
          </Button>
        </Card>
      ) : viewMode === 'grid' ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {projects.map((project) => (
            <Card key={project.id} className="hover:border-yellow-green/50 transition-all bg-card border-dim-grey/30 hover:shadow-lg hover:shadow-yellow-green/20 group">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <CardTitle className="text-lg mb-2">
                      <span
                        onClick={() => navigate(`/dashboard/project/${project.id}`)}
                        className="cursor-pointer hover:text-primary transition-colors"
                      >
                        {project.name}
                      </span>
                    </CardTitle>
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="outline">{project.type}</Badge>
                      {project.last_scan_status && (
                        <Badge
                          variant={
                            project.last_scan_status === 'completed'
                              ? 'info'
                              : project.last_scan_status === 'running'
                                ? 'info'
                                : project.last_scan_status === 'failed'
                                  ? 'destructive'
                                  : 'secondary'
                          }
                        >
                          {project.last_scan_status}
                        </Badge>
                      )}
                    </div>
                  </div>
                  {/* Delete button in top right corner */}
                  <Button
                    size="icon"
                    variant="ghost"
                    className="opacity-0 group-hover:opacity-100 transition-opacity h-8 w-8"
                    onClick={(e) => {
                      e.stopPropagation()
                      openDeleteDialog(project)
                    }}
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
                <CardDescription>
                  Updated {formatDate(project.updated_at)}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {project.vulnerability_counts && getTotalVulnerabilities(project) > 0 ? (
                  <div className="flex items-center gap-2 mb-4 flex-wrap">
                    {project.vulnerability_counts.critical > 0 && (
                      <Badge variant="critical" className="gap-1">
                        {project.vulnerability_counts.critical} Critical
                      </Badge>
                    )}
                    {project.vulnerability_counts.high > 0 && (
                      <Badge variant="high" className="gap-1">
                        {project.vulnerability_counts.high} High
                      </Badge>
                    )}
                    {project.vulnerability_counts.medium > 0 && (
                      <Badge variant="medium" className="gap-1">
                        {project.vulnerability_counts.medium} Medium
                      </Badge>
                    )}
                    {project.vulnerability_counts.low > 0 && (
                      <Badge variant="low" className="gap-1">
                        {project.vulnerability_counts.low} Low
                      </Badge>
                    )}
                  </div>
                ) : (
                  <div className="mb-4 text-sm text-muted-foreground">
                    No vulnerabilities detected yet
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    className="flex-1"
                    onClick={() => handleStartScan(project.id)}
                  >
                    <Play className="mr-2 h-4 w-4" />
                    Scan
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => navigate(`/dashboard/project/${project.id}`)}
                  >
                    <Eye className="h-4 w-4" />
                  </Button>
                  {project.last_scan_id && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => navigate(`/dashboard/attack-graph/${project.last_scan_id}`)}
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card className="border-dim-grey/30 bg-card">
          <div className="relative w-full overflow-auto">
            <table className="w-full caption-bottom text-sm">
              <thead className="[&_tr]:border-b">
                <tr className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Project Name</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Type</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Last Scan</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Vulnerabilities</th>
                  <th className="h-12 px-4 text-left align-middle font-medium text-muted-foreground">Updated</th>
                  <th className="h-12 px-4 text-right align-middle font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody className="[&_tr:last-child]:border-0">
                {projects.map((project) => (
                  <tr key={project.id} className="border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted">
                    <td className="p-4 align-middle font-medium">
                      <span
                        onClick={() => navigate(`/dashboard/project/${project.id}`)}
                        className="cursor-pointer hover:text-primary hover:underline underline-offset-4"
                      >
                        {project.name}
                      </span>
                    </td>
                    <td className="p-4 align-middle">
                      <Badge variant="outline">{project.type}</Badge>
                    </td>
                    <td className="p-4 align-middle">
                      {project.last_scan_status ? (
                        <div className="flex items-center gap-2">
                          <Badge
                            variant={
                              project.last_scan_status === 'completed'
                                ? 'info'
                                : project.last_scan_status === 'running'
                                  ? 'info'
                                  : project.last_scan_status === 'failed'
                                    ? 'destructive'
                                    : 'secondary'
                            }
                          >
                            {project.last_scan_status}
                          </Badge>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </td>
                    <td className="p-4 align-middle">
                      {project.vulnerability_counts && getTotalVulnerabilities(project) > 0 ? (
                        <div className="flex items-center gap-2">
                          {project.vulnerability_counts.critical > 0 && (
                            <div className="h-2 w-2 rounded-full bg-critical" title={`${project.vulnerability_counts.critical} Critical`} />
                          )}
                          {project.vulnerability_counts.high > 0 && (
                            <div className="h-2 w-2 rounded-full bg-high" title={`${project.vulnerability_counts.high} High`} />
                          )}
                          <span className="text-xs text-muted-foreground">{getTotalVulnerabilities(project)} issues</span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground text-xs">Safe</span>
                      )}
                    </td>
                    <td className="p-4 align-middle text-muted-foreground">
                      {formatDate(project.updated_at)}
                    </td>
                    <td className="p-4 align-middle text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleStartScan(project.id)}
                          title="Start Scan"
                        >
                          <Play className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => navigate(`/dashboard/project/${project.id}`)}
                          title="View Details"
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={() => openDeleteDialog(project)}
                          title="Delete Project"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-[425px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              Delete Project
            </DialogTitle>
            <DialogDescription className="pt-2">
              Are you sure you want to delete this project? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>

          {projectToDelete && (
            <div className="py-4">
              <Card className="bg-muted/50">
                <CardContent className="pt-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Project Name</span>
                      <span className="font-medium">{projectToDelete.name}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Type</span>
                      <Badge variant="outline">{projectToDelete.type}</Badge>
                    </div>
                    {projectToDelete.vulnerability_counts && getTotalVulnerabilities(projectToDelete) > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">Vulnerabilities</span>
                        <span className="font-medium">{getTotalVulnerabilities(projectToDelete)} found</span>
                      </div>
                    )}
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Last Updated</span>
                      <span className="text-sm">{formatDate(projectToDelete.updated_at)}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <div className="mt-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                <p className="text-sm text-destructive">
                  <strong>Warning:</strong> Deleting this project will also remove:
                </p>
                <ul className="text-sm text-destructive mt-2 space-y-1 list-disc list-inside">
                  <li>All scan history and results</li>
                  <li>Attack graphs and vulnerability data</li>
                  <li>Generated reports</li>
                </ul>
              </div>
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="outline"
              onClick={closeDeleteDialog}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteProject}
              disabled={isDeleting}
            >
              {isDeleting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete Project
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
