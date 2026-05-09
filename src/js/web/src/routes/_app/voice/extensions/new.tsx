import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, Loader2 } from "lucide-react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
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
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useCreateExtension, usePhoneNumbers } from "@/lib/api/hooks/voice"
import type { ExtensionCreate } from "@/lib/generated/api"
import { extensionNumberRegex } from "@/lib/validation"

const PHONE_NONE = "__none__"

export const Route = createFileRoute("/_app/voice/extensions/new")({
  component: NewExtensionPage,
})

const createExtensionSchema = z.object({
  extensionNumber: z
    .string()
    .min(1, "Extension number is required")
    .min(2, "Extension number must be at least 2 digits")
    .max(6, "Extension number must be at most 6 digits")
    .regex(extensionNumberRegex, "Extension number must contain only digits"),
  displayName: z.string().max(100, "Display name must be 100 characters or fewer").optional(),
  isActive: z.boolean(),
  phoneNumberId: z.string().optional(),
})

type CreateExtensionFormData = z.infer<typeof createExtensionSchema>

function NewExtensionPage() {
  useDocumentTitle("New Extension")
  const router = useRouter()
  const createExtension = useCreateExtension()
  const { data: phoneNumbers } = usePhoneNumbers(1, 100)

  const form = useForm<CreateExtensionFormData>({
    resolver: zodResolver(createExtensionSchema),
    defaultValues: {
      extensionNumber: "",
      displayName: "",
      isActive: true,
      phoneNumberId: PHONE_NONE,
    },
  })

  // Unsaved changes detection
  const isFormDirty = form.formState.isDirty && !form.formState.isSubmitting

  // Router navigation blocker
  const blocker = useBlocker({
    shouldBlockFn: () => isFormDirty,
    withResolver: true,
  })

  const onSubmit = async (data: CreateExtensionFormData) => {
    const payload: Record<string, unknown> = {
      extensionNumber: data.extensionNumber,
    }
    if (data.displayName) payload.displayName = data.displayName
    if (data.phoneNumberId && data.phoneNumberId !== PHONE_NONE) payload.phoneNumberId = data.phoneNumberId
    payload.isActive = data.isActive

    try {
      await createExtension.mutateAsync(payload as ExtensionCreate)
      // Reset dirty state before navigating so blocker doesn't fire
      form.reset(data)
      toast.success("Extension created successfully")
      router.navigate({ to: "/voice/extensions" })
    } catch (error) {
      form.setError("root", {
        message: error instanceof Error ? error.message : "Failed to create extension",
      })
    }
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Voice"
          title="New Extension"
          description="Create a new internal extension for call routing."
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
                    <Link to="/voice/extensions">Extensions</Link>
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage>New Extension</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <SectionErrorBoundary name="Create Extension Form">
          <Card className="max-w-2xl">
            <CardHeader>
              <CardTitle className="text-lg">Extension Details</CardTitle>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <FormField
                    control={form.control}
                    name="extensionNumber"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Extension Number</FormLabel>
                        <FormControl>
                          <Input
                            placeholder="1001"
                            autoFocus
                            inputMode="numeric"
                            maxLength={6}
                            {...field}
                            onChange={(e) => {
                              field.onChange(e)
                              // Clear the error when the user starts fixing
                              if (form.formState.errors.extensionNumber) {
                                form.trigger("extensionNumber")
                              }
                            }}
                          />
                        </FormControl>
                        <FormDescription>A unique 2-6 digit number used to dial this extension internally.</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="displayName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Display Name</FormLabel>
                        <FormControl>
                          <Input
                            placeholder="Front Desk"
                            maxLength={100}
                            {...field}
                            onChange={(e) => {
                              field.onChange(e.target.value.slice(0, 100))
                            }}
                          />
                        </FormControl>
                        <div className="flex items-center justify-between">
                          <FormDescription>This name appears in the directory and call logs.</FormDescription>
                          {(field.value?.length ?? 0) > 0 && (
                            <span
                              className={`shrink-0 text-xs ${(field.value?.length ?? 0) >= 100 ? "text-destructive" : (field.value?.length ?? 0) >= 80 ? "text-amber-500" : "text-muted-foreground"}`}
                            >
                              {field.value?.length ?? 0}/100
                            </span>
                          )}
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
                            <SelectItem value={PHONE_NONE}>None</SelectItem>
                            {phoneNumbers?.items?.map((pn) => (
                              <SelectItem key={pn.id} value={pn.id}>
                                {pn.number}
                                {pn.label ? ` - ${pn.label}` : ""}
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
                      <Link to="/voice/extensions">Cancel</Link>
                    </Button>
                    <Button type="submit" disabled={form.formState.isSubmitting}>
                      {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      {form.formState.isSubmitting ? "Creating..." : "Create Extension"}
                    </Button>
                  </div>
                </form>
              </Form>
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageContainer>

      {/* Unsaved changes dialog */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={(open) => !open && blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Unsaved Changes
            </AlertDialogTitle>
            <AlertDialogDescription>You have unsaved changes on this form. If you leave now, your progress will be lost.</AlertDialogDescription>
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
