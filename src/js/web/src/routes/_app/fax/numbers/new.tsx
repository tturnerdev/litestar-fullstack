import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { useRef, useState } from "react"
import { AlertTriangle, Loader2 } from "lucide-react"
import { useDocumentTitle } from "@/hooks/use-document-title"
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
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Switch } from "@/components/ui/switch"
import { useAuth } from "@/hooks/use-auth"
import { useCreateFaxNumber } from "@/lib/api/hooks/fax"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/fax/numbers/new")({
  component: NewFaxNumberPage,
})

const LABEL_MAX = 100

function NewFaxNumberPage() {
  useDocumentTitle("New Fax Number")
  const router = useRouter()
  const { currentTeam } = useAuth()
  const createFaxNumber = useCreateFaxNumber()
  const justSubmittedRef = useRef(false)

  const [number, setNumber] = useState("")
  const [label, setLabel] = useState("")
  const [isActive, setIsActive] = useState(true)

  const formDirty = number.trim() !== "" || label.trim() !== "" || !isActive

  const blocker = useBlocker({
    shouldBlockFn: () => formDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    justSubmittedRef.current = true

    const payload: { number: string; label?: string; isActive?: boolean; teamId?: string } = {
      number: number.trim(),
    }

    if (label.trim()) payload.label = label.trim()
    if (!isActive) payload.isActive = false
    if (currentTeam) payload.teamId = currentTeam.id

    createFaxNumber.mutate(payload, {
      onSuccess: () => {
        router.navigate({ to: "/fax/numbers" })
      },
      onSettled: () => {
        justSubmittedRef.current = false
      },
    })
  }

  const isValid = number.trim() !== ""

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Fax"
        title="New Number"
        description="Add a new fax number to your account."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/fax/numbers">Fax Numbers</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>New Number</BreadcrumbPage></BreadcrumbItem>
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
              <Label htmlFor="fax-number">Number *</Label>
              <Input
                id="fax-number"
                placeholder="e.g., +15551234567"
                value={number}
                onChange={(e) => setNumber(e.target.value)}
                required
                autoFocus
              />
              <p className="text-xs text-muted-foreground">
                Enter the full phone number including country code.
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
                onClick={() => router.navigate({ to: "/fax/numbers" })}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!isValid || createFaxNumber.isPending}>
                {createFaxNumber.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create Number
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={(open) => !open && blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Unsaved Changes
            </AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes on this form. If you leave now, your progress will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on Page</AlertDialogCancel>
            <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard Changes</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
