import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { ArrowLeft, Check, Pencil, Trash2, X } from "lucide-react"
import { useState } from "react"
import { EmailRouteEditor } from "@/components/fax/email-route-editor"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDeleteFaxNumber, useFaxNumber, useUpdateFaxNumber } from "@/lib/api/hooks/fax"

export const Route = createFileRoute("/_app/fax/numbers/$faxNumberId/")({
  component: FaxNumberDetailPage,
})

function FaxNumberDetailPage() {
  const { faxNumberId } = Route.useParams()
  const navigate = useNavigate()
  const { data, isLoading, isError } = useFaxNumber(faxNumberId)
  const updateFaxNumber = useUpdateFaxNumber(faxNumberId)
  const deleteFaxNumber = useDeleteFaxNumber()
  const [editingLabel, setEditingLabel] = useState(false)
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [labelValue, setLabelValue] = useState("")

  function startEditingLabel() {
    setLabelValue(data?.label ?? "")
    setEditingLabel(true)
  }

  function cancelEditingLabel() {
    setEditingLabel(false)
    setLabelValue("")
  }

  function saveLabel() {
    const trimmed = labelValue.trim()
    updateFaxNumber.mutate(
      { label: trimmed || null },
      { onSuccess: () => setEditingLabel(false) },
    )
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Communications" title="Fax Number Details" />
        <PageSection>
          <SkeletonCard />
        </PageSection>
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Communications"
          title="Fax Number Details"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to numbers
              </Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              We could not load this fax number.
            </CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title={data.label ?? data.number}
        description={data.label ? data.number : undefined}
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:bg-destructive/10"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to numbers
              </Link>
            </Button>
          </div>
        }
      />

      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete fax number</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-medium text-foreground">{data.label ?? data.number}</span>?
              This will also remove all associated email routes. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)} disabled={deleteFaxNumber.isPending}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleteFaxNumber.isPending}
              onClick={() => {
                deleteFaxNumber.mutate(faxNumberId, {
                  onSuccess: () => {
                    setShowDeleteDialog(false)
                    navigate({ to: "/fax/numbers" })
                  },
                })
              }}
            >
              {deleteFaxNumber.isPending ? "Deleting..." : "Delete fax number"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <PageSection>
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 text-sm md:grid-cols-2">
              <div>
                <p className="text-muted-foreground mb-1">Number</p>
                <p className="font-mono text-base">{data.number}</p>
              </div>
              <div>
                <p className="text-muted-foreground mb-1">Label</p>
                {editingLabel ? (
                  <div className="flex items-center gap-2">
                    <Input
                      value={labelValue}
                      onChange={(e) => setLabelValue(e.target.value)}
                      placeholder="e.g. Main Fax, Billing Dept"
                      className="h-9 max-w-xs"
                      onKeyDown={(e) => {
                        if (e.key === "Enter") saveLabel()
                        if (e.key === "Escape") cancelEditingLabel()
                      }}
                      autoFocus
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={saveLabel}
                      disabled={updateFaxNumber.isPending}
                    >
                      <Check className="h-4 w-4 text-emerald-600" />
                    </Button>
                    <Button variant="ghost" size="sm" onClick={cancelEditingLabel}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <p>{data.label || "--"}</p>
                    <Button variant="ghost" size="sm" onClick={startEditingLabel} className="h-7 w-7 p-0">
                      <Pencil className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                )}
              </div>
              <div>
                <p className="text-muted-foreground mb-1">Status</p>
                <Badge variant={data.isActive ? "default" : "secondary"}>
                  {data.isActive ? "Active" : "Inactive"}
                </Badge>
              </div>
              <div>
                <p className="text-muted-foreground mb-1">Assignment</p>
                <p>{data.teamId ? "Team" : "Personal"}</p>
              </div>
              <div>
                <p className="text-muted-foreground mb-1">Created</p>
                <p>{data.createdAt ? new Date(data.createdAt).toLocaleDateString() : "--"}</p>
              </div>
              <div>
                <p className="text-muted-foreground mb-1">Updated</p>
                <p>{data.updatedAt ? new Date(data.updatedAt).toLocaleDateString() : "--"}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 pt-2 border-t border-border/40">
              <Button
                variant={data.isActive ? "outline" : "default"}
                onClick={() => updateFaxNumber.mutate({ isActive: !data.isActive })}
                disabled={updateFaxNumber.isPending}
              >
                {updateFaxNumber.isPending
                  ? "Updating..."
                  : data.isActive
                    ? "Deactivate Number"
                    : "Activate Number"}
              </Button>
            </div>
          </CardContent>
        </Card>
      </PageSection>

      <PageSection delay={0.1}>
        <EmailRouteEditor faxNumberId={faxNumberId} />
      </PageSection>
    </PageContainer>
  )
}
