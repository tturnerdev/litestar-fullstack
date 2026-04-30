import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useEffect, useRef, useState } from "react"
import { Loader2 } from "lucide-react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { useFaxNumber, useUpdateFaxNumber } from "@/lib/api/hooks/fax"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/numbers/$faxNumberId/edit")({
  component: EditFaxNumberPage,
})

const LABEL_MAX = 100

function EditFaxNumberPage() {
  const { faxNumberId } = Route.useParams()
  const router = useRouter()
  const { data, isLoading, isError } = useFaxNumber(faxNumberId)
  const updateFaxNumber = useUpdateFaxNumber(faxNumberId)

  const [label, setLabel] = useState("")
  const [isActive, setIsActive] = useState(true)
  const [initialized, setInitialized] = useState(false)
  const justSubmittedRef = useRef(false)

  // Reset form state when navigating to a different fax number
  useEffect(() => {
    setInitialized(false)
  }, [faxNumberId])

  // Pre-populate form fields when fax number data loads
  useEffect(() => {
    if (data && !initialized) {
      setLabel(data.label ?? "")
      setIsActive(data.isActive)
      setInitialized(true)
    }
  }, [data, initialized])

  const isDirty = initialized && data != null && (label !== (data.label ?? "") || isActive !== data.isActive)

  // Block navigation when form has unsaved changes
  const blocker = useBlocker({
    shouldBlockFn: () => isDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!data) return

    const payload: Record<string, unknown> = {}

    // Only include fields that changed
    const trimmedLabel = label.trim() || null
    if (trimmedLabel !== (data.label || null)) payload.label = trimmedLabel
    if (isActive !== data.isActive) payload.isActive = isActive

    if (Object.keys(payload).length === 0) {
      justSubmittedRef.current = true
      router.navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })
      return
    }

    justSubmittedRef.current = true
    updateFaxNumber.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })
      },
      onError: () => {
        justSubmittedRef.current = false
      },
    })
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Fax" title="Edit Fax Number" />
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
          eyebrow="Fax"
          title="Edit Fax Number"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/fax/numbers">Back to numbers</Link>
            </Button>
          }
        />
        <PageSection>
          <Card>
            <CardHeader>
              <CardTitle>Error</CardTitle>
            </CardHeader>
            <CardContent className="text-muted-foreground">We could not load this fax number.</CardContent>
          </Card>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Fax"
        title="Edit Fax Number"
        description={`Editing "${data.label ?? data.number}"`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/fax/numbers">Fax Numbers</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId }}>{data.label ?? data.number}</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>Edit</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="text-lg">Fax Number Details</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label>Number</Label>
              <Input
                value={data.number}
                disabled
                className="bg-muted/50"
              />
              <p className="text-xs text-muted-foreground">
                The fax number cannot be changed after creation.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="fax-label">Label</Label>
              <Input
                id="fax-label"
                placeholder="e.g., Main Fax, Billing Dept"
                value={label}
                onChange={(e) => {
                  if (e.target.value.length <= LABEL_MAX) setLabel(e.target.value)
                }}
                maxLength={LABEL_MAX}
                autoFocus
              />
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  An optional friendly name to identify this number.
                </p>
                <p className={cn("shrink-0 text-xs", label.length >= LABEL_MAX ? "text-destructive" : label.length >= LABEL_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                  {label.length}/{LABEL_MAX}
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/20 p-4">
              <div>
                <p className="font-medium text-sm">Active</p>
                <p className="text-xs text-muted-foreground">Enable this number to send and receive faxes.</p>
              </div>
              <Switch checked={isActive} onCheckedChange={setIsActive} />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => router.navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateFaxNumber.isPending}>
                {updateFaxNumber.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageContainer>

    {/* -- Unsaved changes dialog ---------------------------------------- */}
    <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
          <AlertDialogDescription>
            You have unsaved changes to this fax number. Are you sure you want to leave? Your changes will be lost.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
          <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}
