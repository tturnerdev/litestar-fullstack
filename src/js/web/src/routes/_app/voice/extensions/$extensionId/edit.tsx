import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, Loader2 } from "lucide-react"
import { useRef } from "react"
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
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { useExtension, usePhoneNumbers, useUpdateExtension } from "@/lib/api/hooks/voice"
import { cn } from "@/lib/utils"

// ── Field limits ──────────────────────────────────────────────────────

const DISPLAY_NAME_MAX = 100

export const Route = createFileRoute("/_app/voice/extensions/$extensionId/edit")({
  component: EditExtensionPage,
})

const editExtensionSchema = z.object({
  displayName: z.string().max(DISPLAY_NAME_MAX, "Display name must be 100 characters or less").optional(),
  isActive: z.boolean(),
  phoneNumberId: z.string().optional(),
})

type EditExtensionFormData = z.infer<typeof editExtensionSchema>

function EditExtensionPage() {
  const { extensionId } = Route.useParams()
  const { data, isLoading, isError } = useExtension(extensionId)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Voice" title="Edit Extension" />
        <SkeletonCard />
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="Edit Extension"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/voice/extensions">Back to extensions</Link>
            </Button>
          }
        />
        <Card>
          <CardHeader>
            <CardTitle>Error</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground">We could not load this extension.</CardContent>
        </Card>
      </PageContainer>
    )
  }

  return <EditExtensionForm extensionId={extensionId} initialData={data} />
}

// ---------------------------------------------------------------------------
// Edit Form (rendered after data loads)
// ---------------------------------------------------------------------------

interface EditExtensionFormProps {
  extensionId: string
  initialData: {
    extensionNumber: string
    displayName: string
    isActive: boolean
    phoneNumberId: string | null
  }
}

function EditExtensionForm({ extensionId, initialData }: EditExtensionFormProps) {
  const router = useRouter()
  const updateExtension = useUpdateExtension(extensionId)
  const { data: phoneNumbers } = usePhoneNumbers(1, 100)
  const justSubmittedRef = useRef(false)

  const form = useForm<EditExtensionFormData>({
    resolver: zodResolver(editExtensionSchema),
    values: {
      displayName: initialData.displayName ?? "",
      isActive: initialData.isActive,
      phoneNumberId: initialData.phoneNumberId ?? "",
    },
  })

  const { isDirty } = form.formState

  // Block navigation when form has unsaved changes
  const blocker = useBlocker({
    shouldBlockFn: () => isDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  const onSubmit = async (data: EditExtensionFormData) => {
    // Only send fields that actually changed
    const payload: Record<string, unknown> = {}
    if ((data.displayName || "") !== (initialData.displayName || "")) payload.displayName = data.displayName || null
    if (data.isActive !== initialData.isActive) payload.isActive = data.isActive
    if ((data.phoneNumberId || null) !== (initialData.phoneNumberId || null)) payload.phoneNumberId = data.phoneNumberId || null

    if (Object.keys(payload).length === 0) {
      justSubmittedRef.current = true
      router.navigate({ to: "/voice/extensions/$extensionId", params: { extensionId } })
      return
    }

    try {
      justSubmittedRef.current = true
      await updateExtension.mutateAsync(payload)
      router.invalidate()
      router.navigate({ to: "/voice/extensions/$extensionId", params: { extensionId } })
    } catch (_error) {
      justSubmittedRef.current = false
      form.setError("root", {
        message: "Failed to update extension",
      })
    }
  }

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title={`Edit ${initialData.displayName || `Ext. ${initialData.extensionNumber}`}`}
        description="Update extension settings."
        breadcrumbs={
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/voice/extensions">Extensions</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/voice/extensions/$extensionId" params={{ extensionId }}>{initialData.displayName || `Ext. ${initialData.extensionNumber}`}</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>Edit</BreadcrumbPage></BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        }
      />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="text-lg">Extension Details</CardTitle>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <div className="space-y-2">
                <FormLabel>Extension Number</FormLabel>
                <Input value={initialData.extensionNumber} disabled />
                <p className="text-xs text-muted-foreground">Extension numbers cannot be changed after creation.</p>
              </div>

              <FormField
                control={form.control}
                name="displayName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Display Name</FormLabel>
                    <FormControl>
                      <Input placeholder="Front Desk" maxLength={DISPLAY_NAME_MAX} {...field} />
                    </FormControl>
                    <div className="flex items-center justify-between">
                      <FormDescription>This name appears in the directory and call logs.</FormDescription>
                      <p className={cn("shrink-0 text-xs", (field.value?.length ?? 0) >= DISPLAY_NAME_MAX ? "text-destructive" : (field.value?.length ?? 0) >= DISPLAY_NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                        {field.value?.length ?? 0}/{DISPLAY_NAME_MAX}
                      </p>
                    </div>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="phoneNumberId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Phone Number</FormLabel>
                    <Select onValueChange={field.onChange} value={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="None (optional)" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="">None</SelectItem>
                        {phoneNumbers?.items.map((pn) => (
                          <SelectItem key={pn.id} value={pn.id}>
                            {pn.number}{pn.label ? ` - ${pn.label}` : ""}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormDescription>Optionally link a DID number that routes directly to this extension.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="isActive"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">Active</FormLabel>
                      <FormDescription>Whether this extension can receive calls.</FormDescription>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </FormItem>
                )}
              />

              {form.formState.errors.root && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
                </Alert>
              )}

              <Separator />

              <div className="flex items-center justify-between">
                <Button type="button" variant="ghost" asChild>
                  <Link to="/voice/extensions/$extensionId" params={{ extensionId }}>Cancel</Link>
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

    {/* -- Unsaved changes dialog ---------------------------------------- */}
    <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
          <AlertDialogDescription>
            You have unsaved changes to this extension. Are you sure you want to leave? Your changes will be lost.
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
