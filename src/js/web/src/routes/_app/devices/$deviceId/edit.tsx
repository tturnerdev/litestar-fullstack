import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  AlertCircle,
  Cable,
  Headset,
  Loader2,
  type LucideIcon,
  MoreHorizontal,
  Phone,
  Users,
} from "lucide-react"
import { useCallback, useRef } from "react"
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
import { useDevice, useUpdateDevice } from "@/lib/api/hooks/devices"
import { formatMacAddress } from "@/lib/format-utils"

export const Route = createFileRoute("/_app/devices/$deviceId/edit")({
  component: EditDevicePage,
})

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const deviceTypes: { value: string; label: string; icon: LucideIcon }[] = [
  { value: "desk_phone", label: "Desk Phone", icon: Phone },
  { value: "softphone", label: "Softphone", icon: Headset },
  { value: "ata", label: "ATA", icon: Cable },
  { value: "conference", label: "Conference", icon: Users },
  { value: "other", label: "Other", icon: MoreHorizontal },
]

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const MAC_REGEX = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/
const IPV4_REGEX = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const editDeviceSchema = z.object({
  name: z.string().min(1, "Device name is required"),
  deviceType: z.string().min(1, "Device type is required"),
  macAddress: z
    .string()
    .optional()
    .refine((v) => !v || MAC_REGEX.test(v), "Must be a valid MAC address (e.g. AA:BB:CC:DD:EE:FF)"),
  ipAddress: z
    .string()
    .optional()
    .refine((v) => !v || IPV4_REGEX.test(v), "Must be a valid IPv4 address (e.g. 192.168.1.100)"),
  deviceModel: z.string().optional(),
  manufacturer: z.string().optional(),
  firmwareVersion: z.string().optional(),
})

type EditDeviceFormData = z.infer<typeof editDeviceSchema>

// ---------------------------------------------------------------------------
// Required-field label
// ---------------------------------------------------------------------------

function RequiredLabel({ children }: { children: React.ReactNode }) {
  return (
    <FormLabel>
      {children}
      <span className="ml-0.5 text-destructive">*</span>
    </FormLabel>
  )
}

function EditDevicePage() {
  const { deviceId } = Route.useParams()
  const { data, isLoading, isError } = useDevice(deviceId)

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Devices" title="Edit Device" />
        <SkeletonCard />
      </PageContainer>
    )
  }

  if (isError || !data) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Devices"
          title="Edit Device"
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/devices">Back to devices</Link>
            </Button>
          }
        />
        <Card>
          <CardHeader>
            <CardTitle>Error</CardTitle>
          </CardHeader>
          <CardContent className="text-muted-foreground">We could not load this device.</CardContent>
        </Card>
      </PageContainer>
    )
  }

  return <EditDeviceForm deviceId={deviceId} initialData={data} />
}

// ---------------------------------------------------------------------------
// Edit Form (rendered after data loads)
// ---------------------------------------------------------------------------

interface EditDeviceFormProps {
  deviceId: string
  initialData: {
    name: string
    deviceType: string
    macAddress?: string | null
    deviceModel?: string | null
    manufacturer?: string | null
    firmwareVersion?: string | null
    ipAddress?: string | null
  }
}

function EditDeviceForm({ deviceId, initialData }: EditDeviceFormProps) {
  const router = useRouter()
  const updateDevice = useUpdateDevice(deviceId)
  const justSubmittedRef = useRef(false)

  const form = useForm<EditDeviceFormData>({
    resolver: zodResolver(editDeviceSchema),
    values: {
      name: initialData.name,
      deviceType: initialData.deviceType,
      macAddress: initialData.macAddress ?? "",
      deviceModel: initialData.deviceModel ?? "",
      manufacturer: initialData.manufacturer ?? "",
      firmwareVersion: initialData.firmwareVersion ?? "",
      ipAddress: initialData.ipAddress ?? "",
    },
  })

  const { isDirty, isSubmitting } = form.formState

  // Block navigation when form is dirty ---------------------------------
  const blocker = useBlocker({
    shouldBlockFn: () => isDirty && !justSubmittedRef.current,
    withResolver: true,
  })

  // MAC address auto-formatter ------------------------------------------
  const handleMacChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      form.setValue("macAddress", formatMacAddress(e.target.value), {
        shouldValidate: true,
        shouldDirty: true,
      })
    },
    [form],
  )

  // Submit handler — only send fields that actually changed ---------------
  const onSubmit = async (data: EditDeviceFormData) => {
    const payload: Record<string, unknown> = {}
    if (data.name !== initialData.name) payload.name = data.name
    if (data.deviceType !== initialData.deviceType) payload.deviceType = data.deviceType
    if ((data.macAddress || null) !== (initialData.macAddress || null)) payload.macAddress = data.macAddress || null
    if ((data.deviceModel || null) !== (initialData.deviceModel || null)) payload.deviceModel = data.deviceModel || null
    if ((data.manufacturer || null) !== (initialData.manufacturer || null)) payload.manufacturer = data.manufacturer || null
    if ((data.firmwareVersion || null) !== (initialData.firmwareVersion || null)) payload.firmwareVersion = data.firmwareVersion || null
    if ((data.ipAddress || null) !== (initialData.ipAddress || null)) payload.ipAddress = data.ipAddress || null

    if (Object.keys(payload).length === 0) {
      justSubmittedRef.current = true
      router.navigate({ to: "/devices/$deviceId", params: { deviceId } })
      return
    }

    try {
      justSubmittedRef.current = true
      await updateDevice.mutateAsync(payload)
      router.invalidate()
      router.navigate({ to: "/devices/$deviceId", params: { deviceId } })
    } catch (_error) {
      justSubmittedRef.current = false
      form.setError("root", {
        message: "Failed to update device. Please check your inputs and try again.",
      })
    }
  }

  return (
    <>
      <PageContainer className="flex-1 space-y-8">
        <PageHeader
          eyebrow="Devices"
          title={`Edit ${initialData.name}`}
          description="Update device information and hardware details."
          breadcrumbs={
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem><BreadcrumbLink asChild><Link to="/home">Home</Link></BreadcrumbLink></BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem><BreadcrumbLink asChild><Link to="/devices">Devices</Link></BreadcrumbLink></BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem><BreadcrumbLink asChild><Link to="/devices/$deviceId" params={{ deviceId }}>{initialData.name}</Link></BreadcrumbLink></BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem><BreadcrumbPage>Edit</BreadcrumbPage></BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          }
        />

        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle className="text-lg">Device Details</CardTitle>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                {/* -- Required fields ---------------------------------------- */}

                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <RequiredLabel>Device Name</RequiredLabel>
                      <FormControl>
                        <Input placeholder="Desk Phone - Office" {...field} />
                      </FormControl>
                      <FormDescription>A friendly label to identify this device.</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="deviceType"
                  render={({ field }) => (
                    <FormItem>
                      <RequiredLabel>Device Type</RequiredLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a device type" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {deviceTypes.map((type) => {
                            const Icon = type.icon
                            return (
                              <SelectItem key={type.value} value={type.value}>
                                <span className="flex items-center gap-2">
                                  <Icon className="h-4 w-4 text-muted-foreground" />
                                  {type.label}
                                </span>
                              </SelectItem>
                            )
                          })}
                        </SelectContent>
                      </Select>
                      <FormDescription>Determines provisioning and configuration options.</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <Separator />

                {/* -- Hardware details --------------------------------------- */}

                <FormField
                  control={form.control}
                  name="macAddress"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>MAC Address</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="AA:BB:CC:DD:EE:FF"
                          value={field.value ?? ""}
                          onChange={handleMacChange}
                          onBlur={field.onBlur}
                          name={field.name}
                          ref={field.ref}
                          maxLength={17}
                        />
                      </FormControl>
                      <FormDescription>
                        Hardware address used for auto-provisioning. Formatted automatically.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="ipAddress"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>IP Address</FormLabel>
                      <FormControl>
                        <Input placeholder="192.168.1.100" {...field} />
                      </FormControl>
                      <FormDescription>
                        Static IP of the device on your network, if known.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <div className="grid gap-6 sm:grid-cols-2">
                  <FormField
                    control={form.control}
                    name="manufacturer"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Manufacturer</FormLabel>
                        <FormControl>
                          <Input placeholder="Polycom" {...field} />
                        </FormControl>
                        <FormDescription>Brand or vendor of the device.</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="deviceModel"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Model</FormLabel>
                        <FormControl>
                          <Input placeholder="VVX 450" {...field} />
                        </FormControl>
                        <FormDescription>Specific model identifier.</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={form.control}
                  name="firmwareVersion"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Firmware Version</FormLabel>
                      <FormControl>
                        <Input placeholder="6.4.0.14" {...field} />
                      </FormControl>
                      <FormDescription>Current firmware running on the device.</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* -- Root error --------------------------------------------- */}

                {form.formState.errors.root && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
                  </Alert>
                )}

                <Separator />

                {/* -- Actions ------------------------------------------------ */}

                <div className="flex items-center justify-between">
                  <Button type="button" variant="ghost" asChild>
                    <Link to="/devices/$deviceId" params={{ deviceId }}>Cancel</Link>
                  </Button>
                  <Button type="submit" disabled={isSubmitting}>
                    {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    {isSubmitting ? "Saving..." : "Save Changes"}
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
              You have unsaved changes to this device. Are you sure you want to leave? Your changes will be lost.
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
