import { zodResolver } from "@hookform/resolvers/zod"
import { createFileRoute, Link, useRouter } from "@tanstack/react-router"
import { AlertCircle, Loader2 } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader } from "@/components/ui/page-layout"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useDevice, useUpdateDevice } from "@/lib/api/hooks/devices"

export const Route = createFileRoute("/_app/devices/$deviceId/edit")({
  component: EditDevicePage,
})

const deviceTypes = [
  { value: "desk_phone", label: "Desk Phone" },
  { value: "softphone", label: "Softphone" },
  { value: "ata", label: "ATA" },
  { value: "conference", label: "Conference" },
  { value: "other", label: "Other" },
]

const editDeviceSchema = z.object({
  name: z.string().min(1, "Device name is required"),
  deviceType: z.string().min(1, "Device type is required"),
  macAddress: z.string().optional(),
  deviceModel: z.string().optional(),
  manufacturer: z.string().optional(),
  firmwareVersion: z.string().optional(),
  ipAddress: z.string().optional(),
})

type EditDeviceFormData = z.infer<typeof editDeviceSchema>

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

  const form = useForm<EditDeviceFormData>({
    resolver: zodResolver(editDeviceSchema),
    defaultValues: {
      name: initialData.name,
      deviceType: initialData.deviceType,
      macAddress: initialData.macAddress ?? "",
      deviceModel: initialData.deviceModel ?? "",
      manufacturer: initialData.manufacturer ?? "",
      firmwareVersion: initialData.firmwareVersion ?? "",
      ipAddress: initialData.ipAddress ?? "",
    },
  })

  const onSubmit = async (data: EditDeviceFormData) => {
    // Only send fields that actually changed
    const payload: Record<string, unknown> = {}
    if (data.name !== initialData.name) payload.name = data.name
    if (data.deviceType !== initialData.deviceType) payload.deviceType = data.deviceType
    if ((data.macAddress || null) !== (initialData.macAddress || null)) payload.macAddress = data.macAddress || null
    if ((data.deviceModel || null) !== (initialData.deviceModel || null)) payload.deviceModel = data.deviceModel || null
    if ((data.manufacturer || null) !== (initialData.manufacturer || null)) payload.manufacturer = data.manufacturer || null
    if ((data.firmwareVersion || null) !== (initialData.firmwareVersion || null)) payload.firmwareVersion = data.firmwareVersion || null
    if ((data.ipAddress || null) !== (initialData.ipAddress || null)) payload.ipAddress = data.ipAddress || null

    if (Object.keys(payload).length === 0) {
      router.navigate({ to: "/devices/$deviceId", params: { deviceId } })
      return
    }

    try {
      await updateDevice.mutateAsync(payload)
      router.invalidate()
      router.navigate({ to: "/devices/$deviceId", params: { deviceId } })
    } catch (_error) {
      form.setError("root", {
        message: "Failed to update device",
      })
    }
  }

  return (
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
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Device Name</FormLabel>
                    <FormControl>
                      <Input placeholder="Desk Phone - Office" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="deviceType"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Device Type</FormLabel>
                    <Select onValueChange={field.onChange} value={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Select a device type" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {deviceTypes.map((type) => (
                          <SelectItem key={type.value} value={type.value}>
                            {type.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="macAddress"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>MAC Address</FormLabel>
                    <FormControl>
                      <Input placeholder="AA:BB:CC:DD:EE:FF" {...field} />
                    </FormControl>
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
                      <Input placeholder="Polycom VVX 450" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="manufacturer"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Manufacturer</FormLabel>
                    <FormControl>
                      <Input placeholder="Polycom" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="firmwareVersion"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Firmware Version</FormLabel>
                    <FormControl>
                      <Input placeholder="6.4.0.14location" {...field} />
                    </FormControl>
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
                    <FormMessage />
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
                  <Link to="/devices/$deviceId" params={{ deviceId }}>Cancel</Link>
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
  )
}
