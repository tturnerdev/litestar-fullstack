import { useCallback, useEffect, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  AlertTriangle,
  Check,
  Download,
  Loader2,
  Music,
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
  useAdminMusicOnHold,
  useAdminMusicOnHoldDetail,
  useCreateMusicOnHold,
  useUpdateMusicOnHold,
  useDeleteMusicOnHold,
} from "@/lib/api/hooks/music-on-hold"
import { useDebouncedValue } from "@/hooks/use-debounced-value"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { exportToCsv, type CsvHeader } from "@/lib/csv-export"
import { formatDateTime } from "@/lib/date-utils"
import type { MusicOnHoldList } from "@/lib/generated/api"

export const Route = createFileRoute("/_app/admin/music-on-hold")({
  component: AdminMusicOnHoldPage,
})

const PAGE_SIZE = 25

const categoryOptions = [
  { value: "default", label: "Default" },
  { value: "custom", label: "Custom" },
  { value: "holiday", label: "Holiday" },
]

const categoryVariants: Record<string, "default" | "secondary" | "outline"> = {
  default: "default",
  custom: "secondary",
  holiday: "outline",
}

const csvHeaders: CsvHeader<MusicOnHoldList>[] = [
  { label: "Name", accessor: (m) => m.name },
  { label: "Category", accessor: (m) => m.category },
  { label: "Active", accessor: (m) => (m.isActive ? "Yes" : "No") },
  { label: "Default", accessor: (m) => (m.isDefault ? "Yes" : "No") },
  { label: "Files", accessor: (m) => String(m.fileCount) },
  { label: "Created At", accessor: (m) => m.createdAt },
]

// ---------------------------------------------------------------------------
// Create / Edit Dialog
// ---------------------------------------------------------------------------

interface MohFormState {
  name: string
  description: string
  category: string
  isDefault: boolean
  isActive: boolean
  randomOrder: boolean
  fileList: string
}

const emptyForm: MohFormState = {
  name: "",
  description: "",
  category: "custom",
  isDefault: false,
  isActive: true,
  randomOrder: false,
  fileList: "",
}

function MohFormDialog({
  mode,
  mohId,
  open,
  onOpenChange,
}: {
  mode: "create" | "edit"
  mohId?: string
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [form, setForm] = useState<MohFormState>(emptyForm)
  const [fileListError, setFileListError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)

  const createMutation = useCreateMusicOnHold()
  const updateMutation = useUpdateMusicOnHold(mohId ?? "")
  const { data: detail } = useAdminMusicOnHoldDetail(mode === "edit" && mohId ? mohId : "")

  // Load detail data into form when editing
  if (mode === "edit" && detail && !loaded) {
    setForm({
      name: detail.name,
      description: detail.description,
      category: detail.category,
      isDefault: detail.isDefault,
      isActive: detail.isActive,
      randomOrder: detail.randomOrder,
      fileList: detail.fileList.length > 0 ? detail.fileList.join("\n") : "",
    })
    setLoaded(true)
  }

  function resetForm() {
    setForm(emptyForm)
    setFileListError(null)
    setLoaded(false)
  }

  function handleOpenChange(next: boolean) {
    if (!next) resetForm()
    onOpenChange(next)
  }

  function handleSubmit() {
    // Parse file list — one file path per line
    const fileList: string[] = form.fileList
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)

    setFileListError(null)

    const payload = {
      name: form.name,
      description: form.description,
      category: form.category,
      isDefault: form.isDefault,
      isActive: form.isActive,
      randomOrder: form.randomOrder,
      fileList,
    }

    if (mode === "create") {
      createMutation.mutate(payload as never, {
        onSuccess: () => {
          toast.success("Music on hold created")
          handleOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to create music on hold", {
            description: err instanceof Error ? err.message : undefined,
          })
        },
      })
    } else {
      updateMutation.mutate(payload as never, {
        onSuccess: () => {
          toast.success("Music on hold updated")
          handleOpenChange(false)
        },
        onError: (err) => {
          toast.error("Failed to update music on hold", {
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
          <DialogTitle>{mode === "create" ? "Create Music on Hold Class" : "Edit Music on Hold Class"}</DialogTitle>
          <DialogDescription>
            {mode === "create"
              ? "Define a new Music on Hold class with audio files and playback settings."
              : "Update the Music on Hold class configuration."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Default Hold Music"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="category">Category</Label>
              <Select
                value={form.category}
                onValueChange={(v) => setForm((f) => ({ ...f, category: v }))}
              >
                <SelectTrigger id="category">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {categoryOptions.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              rows={2}
              placeholder="Optional description of this MOH class..."
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="fileList">Audio Files (one per line)</Label>
            <Textarea
              id="fileList"
              value={form.fileList}
              onChange={(e) => {
                setForm((f) => ({ ...f, fileList: e.target.value }))
                setFileListError(null)
              }}
              rows={6}
              className="font-mono text-xs"
              placeholder={"music/hold-track-01.wav\nmusic/hold-track-02.wav"}
            />
            {fileListError && <p className="text-destructive text-sm">{fileListError}</p>}
          </div>

          <div className="flex flex-wrap items-center gap-6">
            <div className="flex items-center gap-3">
              <Switch
                id="isDefault"
                checked={form.isDefault}
                onCheckedChange={(c) => setForm((f) => ({ ...f, isDefault: c }))}
              />
              <Label htmlFor="isDefault">Default</Label>
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="isActive"
                checked={form.isActive}
                onCheckedChange={(c) => setForm((f) => ({ ...f, isActive: c }))}
              />
              <Label htmlFor="isActive">Active</Label>
            </div>
            <div className="flex items-center gap-3">
              <Switch
                id="randomOrder"
                checked={form.randomOrder}
                onCheckedChange={(c) => setForm((f) => ({ ...f, randomOrder: c }))}
              />
              <Label htmlFor="randomOrder">Random Order</Label>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)} disabled={isPending}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={isPending || !form.name}>
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

function AdminMusicOnHoldPage() {
  useDocumentTitle("Music on Hold - Admin")
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState("")
  const debouncedSearch = useDebouncedValue(search)
  const [createOpen, setCreateOpen] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)

  // Reset page when debounced search changes
  useEffect(() => {
    setPage(1)
  }, [debouncedSearch])

  const { data, isLoading, isError } = useAdminMusicOnHold(page, PAGE_SIZE, debouncedSearch || undefined)
  const deleteMutation = useDeleteMusicOnHold()

  const items = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const handleExport = useCallback(() => {
    exportToCsv("music-on-hold", csvHeaders, items)
  }, [items])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Music on Hold"
        description="Manage Music on Hold classes, audio files, and playback settings."
        breadcrumbs={<AdminBreadcrumbs />}
      />
      <AdminNav />

      <PageSection>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                  <Music className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                </div>
                <div>
                  <CardTitle>MOH Classes</CardTitle>
                  <CardDescription>
                    {total} class{total !== 1 ? "es" : ""} total
                  </CardDescription>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <div className="relative max-w-sm">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    placeholder="Search classes..."
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
                <Button variant="outline" size="sm" onClick={handleExport} disabled={!items.length}>
                  <Download className="mr-2 h-4 w-4" />
                  Export
                </Button>
                <Button size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus className="mr-2 h-4 w-4" />
                  Add Class
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              <SkeletonTable rows={5} />
            ) : isError ? (
              <div className="flex items-center gap-3 py-8 justify-center text-muted-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                <span>Unable to load Music on Hold classes.</span>
              </div>
            ) : items.length === 0 ? (
              <EmptyState
                icon={Music}
                title="No Music on Hold classes"
                description={search ? "No classes match your search." : "Create your first MOH class to get started."}
                action={
                  search ? (
                    <Button variant="outline" size="sm" onClick={() => setSearch("")}>
                      Clear search
                    </Button>
                  ) : (
                    <Button size="sm" onClick={() => setCreateOpen(true)}>
                      <Plus className="mr-2 h-4 w-4" />
                      Add Class
                    </Button>
                  )
                }
              />
            ) : (
              <>
                <Table aria-label="Music on Hold classes">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Files</TableHead>
                      <TableHead>Default</TableHead>
                      <TableHead>Active</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="w-[60px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((moh, index) => (
                      <TableRow
                        key={moh.id}
                        className={cn(
                          "cursor-pointer hover:bg-muted/50 transition-colors",
                          index % 2 === 1 && "bg-muted/20",
                        )}
                        onClick={() => setEditId(moh.id)}
                      >
                        <TableCell className="font-medium">{moh.name}</TableCell>
                        <TableCell>
                          <Badge variant={categoryVariants[moh.category] ?? "outline"}>
                            {moh.category.charAt(0).toUpperCase() + moh.category.slice(1)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{moh.fileCount}</TableCell>
                        <TableCell>
                          {moh.isDefault ? (
                            <Badge variant="default">Default</Badge>
                          ) : (
                            <span className="text-muted-foreground text-sm">-</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {moh.isActive ? (
                            <Check className="h-4 w-4 text-emerald-500" />
                          ) : (
                            <X className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {formatDateTime(moh.createdAt)}
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
                                  Delete MOH Class
                                </AlertDialogTitle>
                                <AlertDialogDescription>
                                  Are you sure you want to delete the MOH class{" "}
                                  <span className="font-medium text-foreground">
                                    {moh.name}
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
                                    deleteMutation.mutate(moh.id, {
                                      onSuccess: () => {
                                        toast.success("Music on hold deleted")
                                      },
                                      onError: (err) => {
                                        toast.error("Failed to delete music on hold", {
                                          description: err instanceof Error ? err.message : undefined,
                                        })
                                      },
                                    })
                                  }}
                                >
                                  {deleteMutation.isPending ? "Deleting..." : "Delete Class"}
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
      <MohFormDialog mode="create" open={createOpen} onOpenChange={setCreateOpen} />

      {/* Edit dialog */}
      {editId && (
        <MohFormDialog
          mode="edit"
          mohId={editId}
          open={!!editId}
          onOpenChange={(open) => {
            if (!open) setEditId(null)
          }}
        />
      )}
    </PageContainer>
  )
}
