import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { projectService } from '@/services/projectService'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'

import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Progress } from '@/components/ui/progress'
import { Upload, FileText, Globe, Loader2, CheckCircle2, AlertCircle, ShieldAlert } from 'lucide-react'
import { useToast } from '@/components/ui/use-toast'

export default function ProjectUpload() {
  const navigate = useNavigate()
  const toast = useToast()
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [activeTab, setActiveTab] = useState<'openapi' | 'zip' | 'url'>('openapi')

  const [formData, setFormData] = useState({
    name: '',
    // specific fields for each type
    apiFile: null as File | null,
    zipFile: null as File | null,
    targetUrl: '',
  })

  const [errors, setErrors] = useState<Record<string, string>>({})

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, field: 'apiFile' | 'zipFile') => {
    const file = e.target.files?.[0]
    if (file) {
      setFormData(prev => ({ ...prev, [field]: file }))
      // Auto-fill name if empty
      if (!formData.name) {
        setFormData(prev => ({ ...prev, name: file.name.replace(/\.[^/.]+$/, '') }))
      }
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrors({})

    if (!formData.name.trim()) {
      setErrors({ name: 'Project name is required' })
      return
    }

    let type: 'api' | 'codebase' = 'api'
    let file: File | undefined
    let repoUrl: string | undefined
    let openapi_spec: string | undefined

    // Validation based on active tab
    if (activeTab === 'openapi') {
      type = 'api'
      if (!formData.apiFile) {
        setErrors({ apiFile: 'Please upload an API specification file' })
        return
      }
      file = formData.apiFile

      // Read file content
      try {
        openapi_spec = await new Promise((resolve, reject) => {
          const reader = new FileReader()
          reader.onload = (e) => resolve(e.target?.result as string)
          reader.onerror = (e) => reject(e)
          reader.readAsText(file!)
        })
      } catch (err) {
        setErrors({ apiFile: 'Failed to read file content' })
        return
      }

    } else if (activeTab === 'zip') {
      type = 'codebase'
      if (!formData.zipFile) {
        setErrors({ zipFile: 'Please upload a source code ZIP' })
        return
      }
      file = formData.zipFile
      // For MVP: We are not uploading the actual ZIP to storage yet (requires storage bucket)
      // We will simulate it by setting a mock repoUrl so the backend knows it's a file.
      repoUrl = `uploaded://${file.name}`
    } else if (activeTab === 'url') {
      type = 'api' // Treating Target URL as API project
      if (!formData.targetUrl.trim()) {
        setErrors({ targetUrl: 'Target API URL is required' })
        return
      }
      repoUrl = formData.targetUrl
    }

    setUploading(true)
    setProgress(0)

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 10
        })
      }, 500)

      // Send payload to backend
      // Note: We are sending 'openapi_spec' which backend expects
      await projectService.uploadProject({
        name: formData.name,
        type,
        // file, // Don't send File object in JSON
        repoUrl,
        openapi_spec
      } as any) // Casting as any to bypass strict type check for now if interface mismatches

      clearInterval(progressInterval)
      setProgress(100)

      toast({ title: 'Success', description: 'Project created successfully' })
      setTimeout(() => {
        navigate('/dashboard')
      }, 1000)
    } catch (error: any) {
      setProgress(0)
      const errorMessage = error.response?.data?.message || 'Failed to create project'
      setErrors({ submit: errorMessage })
      toast({ title: 'Error', description: errorMessage, variant: 'destructive' })
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold">New Security Scan</h1>
        <p className="text-muted-foreground">Configure your target for vulnerability scanning</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Scan Configuration</CardTitle>
          <CardDescription>
            Select your target type and provide the necessary details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="name">Project / Scan Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="e.g. Production API Check"
                required
                disabled={uploading}
              />
              {errors.name && (
                <p className="text-sm text-destructive flex items-center gap-2">
                  <AlertCircle className="h-4 w-4" />
                  {errors.name}
                </p>
              )}
            </div>

            <Tabs value={activeTab} onValueChange={(val) => setActiveTab(val as any)} className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="openapi" className="flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  OpenAPI / Swagger
                </TabsTrigger>
                <TabsTrigger value="zip" className="flex items-center gap-2">
                  <Upload className="h-4 w-4" />
                  Source Code (ZIP)
                </TabsTrigger>
                <TabsTrigger value="url" className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  Target API URL
                </TabsTrigger>
              </TabsList>

              {/* Tab 1: OpenAPI */}
              <TabsContent value="openapi" className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="apiFile">Upload Specification File</Label>
                  <div className="flex items-center gap-4">
                    <Input
                      id="apiFile"
                      type="file"
                      accept=".json,.yaml,.yml"
                      onChange={(e) => handleFileChange(e, 'apiFile')}
                      disabled={uploading}
                      className="cursor-pointer"
                    />
                  </div>
                  {formData.apiFile && (
                    <div className="flex items-center gap-2 text-sm text-primary font-medium mt-2">
                      <CheckCircle2 className="h-4 w-4" />
                      {formData.apiFile.name}
                    </div>
                  )}
                  {errors.apiFile && (
                    <p className="text-sm text-destructive flex items-center gap-2 mt-2">
                      <AlertCircle className="h-4 w-4" />
                      {errors.apiFile}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-2">
                    Supported formats: OpenAPI 3.0, Swagger 2.0 (JSON/YAML)
                  </p>
                </div>
              </TabsContent>

              {/* Tab 2: ZIP */}
              <TabsContent value="zip" className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="zipFile">Upload Source Code Archive</Label>
                  <div className="flex items-center gap-4">
                    <Input
                      id="zipFile"
                      type="file"
                      accept=".zip,.tar,.gz"
                      onChange={(e) => handleFileChange(e, 'zipFile')}
                      disabled={uploading}
                      className="cursor-pointer"
                    />
                  </div>
                  {formData.zipFile && (
                    <div className="flex items-center gap-2 text-sm text-primary font-medium mt-2">
                      <CheckCircle2 className="h-4 w-4" />
                      {formData.zipFile.name}
                    </div>
                  )}
                  {errors.zipFile && (
                    <p className="text-sm text-destructive flex items-center gap-2 mt-2">
                      <AlertCircle className="h-4 w-4" />
                      {errors.zipFile}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-2">
                    Supported formats: .zip, .tar, .gz (Max 500MB)
                  </p>
                </div>
              </TabsContent>

              {/* Tab 3: Target URL */}
              <TabsContent value="url" className="space-y-4 pt-4">
                <div className="space-y-2">
                  <Label htmlFor="targetUrl">Target API Base URL</Label>
                  <Input
                    id="targetUrl"
                    type="url"
                    value={formData.targetUrl}
                    onChange={(e) => setFormData({ ...formData, targetUrl: e.target.value })}
                    placeholder="https://api.example.com/v1"
                    disabled={uploading}
                  />
                  {errors.targetUrl && (
                    <p className="text-sm text-destructive flex items-center gap-2 mt-2">
                      <AlertCircle className="h-4 w-4" />
                      {errors.targetUrl}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-2">
                    The scanner will perform dynamic analysis (DAST) against this endpoint.
                  </p>
                </div>
              </TabsContent>
            </Tabs>

            {/* Progress Bar */}
            {uploading && (
              <div className="space-y-2 pt-4">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Initializing Scan...</span>
                  <span className="font-medium">{progress}%</span>
                </div>
                <Progress value={progress} />
              </div>
            )}

            {errors.submit && (
              <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <p className="text-sm text-destructive">{errors.submit}</p>
              </div>
            )}

            <div className="flex items-center gap-4 pt-4">
              <Button type="submit" disabled={uploading} className="w-full bg-red-600 hover:bg-red-700 text-white font-bold h-12 shadow-lg shadow-red-600/20">
                {uploading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Initializing Sentinel...
                  </>
                ) : (
                  <>
                    <ShieldAlert className="mr-2 h-5 w-5" />
                    Start Sentinel Scan
                  </>
                )}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
