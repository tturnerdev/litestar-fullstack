import { useCallback, useEffect, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  AlertTriangle,
  Check,
  Cpu,
  Download,
  Loader2,
  Plus,
  Search,
  Trash2,
  X,
} from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button, buttonVariants } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { EmptyState } from "@/components/ui/empty-state"
import {
  useAdminDeviceTemplates,
  useAdminDeviceTemplate,
  useCreateDeviceTemplate,
  useUpdateDeviceTemplate,
  useDeleteDeviceTemplate,
} from "@/lib/api/hooks/device-templates"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { DeviceTemplateList } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/device-templates")({
  component: AdminDeviceTemplatesPage,
})

const PAGE_SIZE = 25

const deviceTypeOptions = [
  { value: "desk_phone", label: "Desk Phone" },
  { value: "softphone", label: "Softphone" },
  { value: "ata", label: "ATA" },
  { value: "conference", label: "Conference" },
  { value: "other", label: "Other" },
]

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

const csvHeaders: CsvHeader<DeviceTemplateList>[] = [
  { label: "Display Name", accessor: (t) => t.displayName },
  { label: "Manufacturer", accessor: (t) => t.manufacturer },
  { label: "Model", accessor: (t) => t.model },
  { label: "Device Type", accessor: (t) => t.deviceType },
  { label: "Active", accessor: (t) => (t.isActive ? "Yes" : "No") },
  { label: "Created At", accessor: (t) => t.createdAt },
  { label: "Updated At", accessor: (t) => t.updatedAt },
]

// ---------------------------------------------------------------------------
// Create / Edit Dialog
// ---------------------------------------------------------------------------

interface TemplateFormState {
  manufacturer: string
  model: string
  displayName: string
  deviceType: string
  wireframeData: string
  provisioningTemplate: string
  templateVariables: string
  imageUrl: string
  isActive: boolean
}

const emptyForm: TemplateFormState = {
  manufacturer: "",
  model: "",
  displayName: "",
  deviceType: "desk_phone",
  wireframeData: "",
  provisioningTemplate: "",
  templateVariables: "",
  imageUrl: "",
  isActive: true,
}

function TemplateFormDialog({
  mode,
  templateId,
  open,
  onOpenChange,
}: {
  mode: "create" | "edit"
  templateId?: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [form, setForm] = useState<TemplateFormState>(emptyForm)
  const [wireframeError, setWireframeError] = useState<string | null>(null)
  const [variablesError, setVariablesError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)

  const createMutation = useCreateDeviceTemplate()
  const updateMutation = useUpdateDeviceTemplate(templateId ?? "")
  const { data: detail } = useAdminDeviceTemplate(mode === "edit" && templateId ? templateId : "")

  // Load detail data into form when editing
  if (mode === "edit" && detail && !loaded) {
    setForm({
      manufacturer: detail.manufacturer,
      model: detail.model,
      displayName: detail.displayName,
      deviceType: detail.deviceType,
      wireframeData: JSON.stringify(detail.wireframeData, null, 2),
      provisioningTemplate: detail.provisioningTemplate ?? "",
      templateVariables: detail.templateVariables ? JSON.stringify(detail.templateVariables, null, 2) : "",
      imageUrl: detail.imageUrl ?? "",
      isActive: detail.isActive,
    })
    setLoaded(true)
  }

  function resetForm() {
    setForm(emptyForm)
    setWireframeError(null)
    setVariablesError(null)
    setLoaded(false)
  }

  function handleOpenChange(next: boolean) {
    if (!next) resetForm()
    onOpenChange(next)
  }

  function handleSubmit() {
    // Validate JSON fields
    let wireframeData: Record<string, unknown>
    try {
      wireframeData = JSON.parse(form.wireframeData)
      setWireframeError(null)
    } catch {
      setWireframeError("Invalid JSON")
      return
    }

    let templateVariables: Record<string, unknown> | undefined
    if (form.templateVariables.trim()) {
      try {
        templateVariables = JSON.parse(form.templateVariables)
        setVariablesError(null)
      } catch {
        setVariablesError("Invalid JSON")
        return
      }
    }

    const payload = {
      manufacturer: form.manufacturer,
      model: form.model,
      displayName: form.displayName,
      deviceType: form.deviceType,
      wireframeData,
      provisioningTemplate: form.provisioningTemplate || undefined,
      templateVariables: templateVariables ?? undefined,
      imageUrl: form.imageUrl || undefined,
      isActive: form.isActive,
    }

    if (mode === "create") {
      createMutation.mutate(payload as never, {
        onSuccess: () => {
          toast.success("Device template created")
          handleOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to create device template", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      })
    } else {
      updateMutation.mutate(payload as never, {
        onSuccess: () => {
          toast.success("Device template updated")
          handleOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to update device template", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      })
    }
  }

  const isPending = createMutation.isPending || updateMutation.isPending

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{mode === "create" ? "Create Device Template" : "Edit Device Template"}</DialogTitle>
          <DialogDescription>
            {mode === "create"
              ? "Define a new device template with wireframe layout and provisioning configuration."
              : "Update the device template configuration."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="manufacturer">Manufacturer</Label>
              <Input
                id="manufacturer"
                value={form.manufacturer}
                onChange={(e) => setForm((f) => ({ ...f, manufacturer: e.target.value }))}
                placeholder="e.g. Yealink"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="model">Model</Label>
              <Input
                id="model"
                value={form.model}
                onChange={(e) => setForm((f) => ({ ...f, model: e.target.value }))}
                placeholder="e.g. T31P"
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="displayName">Display Name</Label>
              <Input
                id="displayName"
                value={form.displayName}
                onChange={(e) => setForm((f) => ({ ...f, displayName: e.target.value }))}
                placeholder="e.g. Yealink T31P"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="deviceType">Device Type</Label>
              <Select
                value={form.deviceType}
                onValueChange={(v) => setForm((f) => ({ ...f, deviceType: v }))}
              >
                <SelectTrigger id="deviceType">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {deviceTypeOptions.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="wireframeData">Wireframe Data (JSON)</Label>
            <Textarea
              id="wireframeData"
              value={form.wireframeData}
              onChange={(e) => {
                setForm((f) => ({ ...f, wireframeData: e.target.value }))
                setWireframeError(null)
              }}
              rows={8}
              className="font-mono text-xs"
              placeholder='{"width": 400, "height": 380, "regions": [...], "dialpad": {...}}'
            />
            {wireframeError && <p className="text-destructive text-sm">{wireframeError}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="provisioningTemplate">Provisioning Template</Label>
            <Textarea
              id="provisioningTemplate"
              value={form.provisioningTemplate}
              onChange={(e) => setForm((f) => ({ ...f, provisioningTemplate: e.target.value }))}
              rows={8}
              className="font-mono text-xs"
              placeholder="Jinja2-style provisioning template..."
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="templateVariables">Template Variables (JSON)</Label>
            <Textarea
              id="templateVariables"
              value={form.templateVariables}
              onChange={(e) => {
                setForm((f) => ({ ...f, templateVariables: e.target.value }))
                setVariablesError(null)
              }}
              rows={4}
              className="font-mono text-xs"
              placeholder='{"sip_password": "", "display_name": ""}'
            />
            {variablesError && <p className="text-destructive text-sm">{variablesError}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="imageUrl">Image URL (optional)</Label>
            <Input
              id="imageUrl"
              value={form.imageUrl}
              onChange={(e) => setForm((f) => ({ ...f, imageUrl: e.target.value }))}
              placeholder="https://..."
            />
          </div>

          <div className="flex items-center gap-3">
            <Switch
              id="isActive"
              checked={form.isActive}
              onCheckedChange={(c) => setForm((f) => ({ ...f, isActive: c }))}
            />
            <Label htmlFor="isActive">Active</Label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isPending || !form.manufacturer || !form.model || !form.displayName || !form.wireframeData}>
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {mode === "create" ? "Create" : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

function AdminDeviceTemplatesPage() {
  useDocumentTitle("Device Templates - Admin")
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [createOpen, setCreateOpen] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError, refetch } = useAdminDeviceTemplates(page, PAGE_SIZE, debouncedSearch || undefined)
  const deleteMutation = useDeleteDeviceTemplate()

  const templates = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleExport = useCallback(() => {
    if (!templates.length) return
    exportToCsv("device-templates", csvHeaders, templates)
  }, [templates])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Device Templates"
        description="Manage wireframe layouts and provisioning templates for device models."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={
          <Button variant="outline" size="sm" onClick={handleExport} disabled={!templates.length}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        }
      />
      <AdminNav />

      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                  <Cpu className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                </div>
                <div>
                  <CardTitle>Templates</CardTitle>
                  <CardDescription>
                    {total} template{total !== 1 ? "s" : ""} total
                  </CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="relative max-w-sm">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search templates..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="pl-9 pr-8"
                  />
                  {search && (
                    <button
                      type="button"
                      onClick={() => setSearch("")}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                    >
                      <X className="h-3.5 w-3.5" />
                      <span className="sr-only">Clear search</span>
                    </button>
                  )}
                </div>
                <Button size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus className="mr-2 h-4 w-4" />
                  Create Template
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={5} />
            ) : isError ? (
              <EmptyState
                icon={AlertCircle}
                title="Unable to load device templates"
                description="Something went wrong. Please try again."
                action={<Button variant="outline" size="sm" onClick={() => refetch()}>Try again</Button>}
              />
            ) : templates.length === 0 ? (
              <EmptyState
                icon={Cpu}
                title="No device templates"
                description={search ? "No templates match your search." : "Create your first device template to get started."}
                action={
                  search ? (
                    <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                      Clear search
                    </Button>
                  ) : (
                    <Button size="sm" onClick={() => setCreateOpen(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Create Template
                    </Button>
                  )
                }
              />
            ) : (
              <>
                <Table aria-label="Device templates">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Display Name</TableHead>
                      <TableHead>Manufacturer</TableHead>
                      <TableHead>Model</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Active</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="w-[60px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {templates.map((tmpl, index) => (
                      <TableRow
                        key={tmpl.id}
                        className={cn(
                          "cursor-pointer hover:bg-muted/50 transition-colors",
                          index % 2 === 1 && "bg-muted/20",
                        )}
                        onClick={() => setEditId(tmpl.id)}
                      >
                        <TableCell className="font-medium">{tmpl.displayName}</TableCell>
                        <TableCell className="text-muted-foreground">{tmpl.manufacturer}</TableCell>
                        <TableCell className="text-muted-foreground">{tmpl.model}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{deviceTypeLabels[tmpl.deviceType] ?? tmpl.deviceType}</Badge>
                        </TableCell>
                        <TableCell>
                          {tmpl.isActive ? (
                            <Check className="h-4 w-4 text-emerald-500" />
                          ) : (
                            <X className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {formatDateTime(tmpl.createdAt)}
                        </TableCell>
                        <TableCell>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8 text-muted-foreground hover:text-destructive"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <Trash2 className="h-4 w-4" />
                                <span className="sr-only">Delete</span>
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent onClick={(e) => e.stopPropagation()}>
                              <AlertDialogHeader>
                                <AlertDialogTitle className="flex items-center gap-2">
                                  <AlertTriangle className="h-5 w-5 text-destructive" />
                                  Delete Device Template
                                </AlertDialogTitle>
                                <AlertDialogDescription>
                                  Are you sure you want to delete the template{" "}
                                  <span className="font-medium text-foreground">
                                    {tmpl.displayName}
                                  </span>
                                  ? This action cannot be undone.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel disabled={deleteMutation.isPending}>
                                  Cancel
                                </AlertDialogCancel>
                                <AlertDialogAction
                                  className={buttonVariants({ variant: "destructive" })}
                                  disabled={deleteMutation.isPending}
                                  onClick={() => {
                                    deleteMutation.mutate(tmpl.id, {
                                      onSuccess: () => {
                                        toast.success("Device template deleted")
                                      },
                                      onError: (err) => {
                                        toast.error("Failed to delete device template", {
                                          description: err instanceof Error ? err.message : undefined,
                                        })
                                      },
                                    })
                                  }}
                                >
                                  {deleteMutation.isPending ? "Deleting..." : "Delete Template"}
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {totalPages > 1 && (
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-muted-foreground">
                      Page {page} of {totalPages} ({total} total)
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page <= 1}
                      >
                        Previous
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                        disabled={page >= totalPages}
                      >
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>
      </PageSection>

      {/* Create dialog */}
      <TemplateFormDialog mode="create" open={createOpen} onOpenChange={setCreateOpen} />

      {/* Edit dialog */}
      {editId && (
        <TemplateFormDialog
          mode="edit"
          templateId={editId}
          open={!!editId}
          onOpenChange={(open) => {
            if (!open) setEditId(null)
          }}
        />
      )}
    </PageContainer>
  )
}
