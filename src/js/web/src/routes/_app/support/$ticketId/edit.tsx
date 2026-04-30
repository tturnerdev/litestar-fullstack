import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useBlocker, useParams, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, ArrowLeft, Loader2 } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { useTicket, useUpdateTicket } from "@/lib/api/hooks/support"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const SUBJECT_MAX = 200

export const Route = createFileRoute("/_app/support/$ticketId/edit")({
  component: EditTicketPage,
})

const editTicketSchema = z.object({
  subject: z.string().min(1, "Subject is required").max(200, "Subject must be under 200 characters"),
  priority: z.string().min(1),
  status: z.string().min(1),
  category: z.string().optional(),
})

type EditTicketFormData = z.infer<typeof editTicketSchema>

// ── Loading Skeleton ─────────────────────────────────────────────────────

function EditTicketSkeleton() {
  return (
    <PageContainer className="flex-1 space-y-8">
      <div className="space-y-3">
        <Skeleton className="h-3 w-48" />
        <Skeleton className="h-9 w-64" />
        <Skeleton className="h-4 w-40" />
      </div>
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32" />
        </CardHeader>
        <CardContent className="space-y-6">
          <Skeleton className="h-10 w-full" />
          <div className="grid gap-6 sm:grid-cols-2">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
          <div className="grid gap-6 sm:grid-cols-2">
            <Skeleton className="h-10 w-full" />
          </div>
          <Separator />
          <div className="flex justify-between">
            <Skeleton className="h-9 w-20" />
            <Skeleton className="h-9 w-32" />
          </div>
        </CardContent>
      </Card>
    </PageContainer>
  )
}

// ── Error State ──────────────────────────────────────────────────────────

function TicketNotFound({ message }: { message: string }) {
  return (
    <PageContainer className="flex-1">
      <div className="flex flex-col items-center justify-center py-24">
        <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted/50">
          <AlertCircle className="h-8 w-8 text-muted-foreground" />
        </div>
        <h2 className="mt-4 text-lg font-semibold">Unable to load ticket</h2>
        <p className="mt-1 max-w-sm text-center text-sm text-muted-foreground">{message}</p>
        <Button variant="outline" size="sm" asChild className="mt-6">
          <Link to="/support">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Tickets
          </Link>
        </Button>
      </div>
    </PageContainer>
  )
}

// ── Edit Form ────────────────────────────────────────────────────────────

function EditTicketForm({ ticketId }: { ticketId: string }) {
  const router = useRouter()
  const { data: ticket, isLoading, isError } = useTicket(ticketId)
  const updateTicket = useUpdateTicket(ticketId)

  const form = useForm<EditTicketFormData>({
    resolver: zodResolver(editTicketSchema),
    values: ticket
      ? {
          subject: ticket.subject,
          priority: ticket.priority,
          status: ticket.status,
          category: ticket.category ?? "",
        }
      : undefined,
  })

  // Unsaved changes detection
  const isFormDirty = form.formState.isDirty && !form.formState.isSubmitting

  // Router navigation blocker
  const blocker = useBlocker({
    shouldBlockFn: () => isFormDirty,
    withResolver: true,
  })

  if (isLoading) {
    return <EditTicketSkeleton />
  }

  if (isError) {
    return <TicketNotFound message="We couldn't load this ticket. It may have been deleted or you may not have permission to view it." />
  }

  if (!ticket) {
    return <TicketNotFound message="This ticket could not be found. It may have been deleted." />
  }

  const onSubmit = async (data: EditTicketFormData) => {
    // Only send fields that actually changed
    const changes: Record<string, unknown> = {}
    if (data.subject !== ticket.subject) changes.subject = data.subject
    if (data.priority !== ticket.priority) changes.priority = data.priority
    if (data.status !== ticket.status) changes.status = data.status
    const newCategory = data.category || null
    if (newCategory !== (ticket.category ?? null)) changes.category = newCategory

    if (Object.keys(changes).length === 0) {
      router.navigate({
        to: "/support/$ticketId",
        params: { ticketId },
      })
      return
    }

    try {
      await updateTicket.mutateAsync(changes)
      // Reset dirty state before navigating so blocker doesn't fire
      form.reset(data)
      router.navigate({
        to: "/support/$ticketId",
        params: { ticketId },
      })
    } catch (_error) {
      form.setError("root", {
        message: "Failed to update ticket",
      })
    }
  }

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Helpdesk"
        title="Edit Ticket"
        description={`${ticket.ticketNumber} · ${ticket.subject}`}
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/home">Home</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/support">Support</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbLink asChild>
                  <Link to="/support/$ticketId" params={{ ticketId }}>
                    {ticket.subject}
                  </Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                <BreadcrumbPage>Edit</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Ticket Details</CardTitle>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="subject"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Subject</FormLabel>
                    <FormControl>
                      <Input placeholder="Brief summary of the issue" maxLength={SUBJECT_MAX} {...field} />
                    </FormControl>
                    <div className="flex items-center justify-between">
                      <FormMessage />
                      <p className={cn("shrink-0 text-xs", field.value.length >= SUBJECT_MAX ? "text-destructive" : field.value.length >= SUBJECT_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                        {field.value.length}/{SUBJECT_MAX}
                      </p>
                    </div>
                  </FormItem>
                )}
              />

              <div className="grid gap-6 sm:grid-cols-2">
                <FormField
                  control={form.control}
                  name="status"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Status</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select status" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="open">Open</SelectItem>
                          <SelectItem value="in_progress">In Progress</SelectItem>
                          <SelectItem value="waiting_on_customer">Waiting on Customer</SelectItem>
                          <SelectItem value="waiting_on_support">Waiting on Support</SelectItem>
                          <SelectItem value="resolved">Resolved</SelectItem>
                          <SelectItem value="closed">Closed</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="priority"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Priority</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select priority" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="urgent">Urgent</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="grid gap-6 sm:grid-cols-2">
                <FormField
                  control={form.control}
                  name="category"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Category</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select category" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="general">General</SelectItem>
                          <SelectItem value="billing">Billing</SelectItem>
                          <SelectItem value="technical">Technical</SelectItem>
                          <SelectItem value="account">Account</SelectItem>
                          <SelectItem value="device">Device</SelectItem>
                          <SelectItem value="voice">Voice</SelectItem>
                          <SelectItem value="fax">Fax</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {form.formState.errors.root && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
                </Alert>
              )}

              <Separator />

              <div className="flex items-center justify-between">
                <Button type="button" variant="ghost" asChild>
                  <Link to="/support/$ticketId" params={{ ticketId }}>
                    Cancel
                  </Link>
                </Button>
                <Button type="submit" disabled={form.formState.isSubmitting}>
                  {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {form.formState.isSubmitting ? "Saving..." : "Save Changes"}
                </Button>
              </div>
            </form>
          </Form>
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

// ── Main Page ────────────────────────────────────────────────────────────

function EditTicketPage() {
  const { ticketId } = useParams({ from: "/_app/support/$ticketId/edit" as const })
  return <EditTicketForm ticketId={ticketId} />
}
