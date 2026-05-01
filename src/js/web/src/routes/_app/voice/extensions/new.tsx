import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import { AlertCircle, AlertTriangle, Loader2 } from "lucide-react"
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
import { Switch } from "@/components/ui/switch"
import { useCreateExtension, usePhoneNumbers } from "@/lib/api/hooks/voice"

const PHONE_NONE = "__none__"

export const Route = createFileRoute("/_app/voice/extensions/new")({
  component: NewExtensionPage,
})

const createExtensionSchema = z.object({
  extensionNumber: z.string().min(1, "Extension number is required"),
  displayName: z.string().optional(),
  isActive: z.boolean(),
  phoneNumberId: z.string().optional(),
})

type CreateExtensionFormData = z.infer<typeof createExtensionSchema>

function NewExtensionPage() {
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
      await createExtension.mutateAsync(payload)
      // Reset dirty state before navigating so blocker doesn't fire
      form.reset(data)
      router.navigate({ to: "/voice/extensions" })
    } catch (_error) {
      form.setError("root", {
        message: "Failed to create extension",
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
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbLink asChild><Link to="/voice/extensions">Extensions</Link></BreadcrumbLink></BreadcrumbItem>
              <BreadcrumbSeparator />
              <BreadcrumbItem><BreadcrumbPage>New Extension</BreadcrumbPage></BreadcrumbItem>
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
              <FormField
                control={form.control}
                name="extensionNumber"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Extension Number</FormLabel>
                    <FormControl>
                      <Input placeholder="1001" {...field} />
                    </FormControl>
                    <FormDescription>A unique number used to dial this extension internally.</FormDescription>
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
                      <Input placeholder="Front Desk" {...field} />
                    </FormControl>
                    <FormDescription>This name appears in the directory and call logs.</FormDescription>
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
