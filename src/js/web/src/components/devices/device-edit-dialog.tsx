import { zodResolver } from "@hookform/resolvers/zod"
import { useEffect } from "react"
import { useForm } from "react-hook-form"
import * as z from "zod"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import type { Device } from "@/lib/api/hooks/devices"
import { useUpdateDevice } from "@/lib/api/hooks/devices"

const editSchema = z.object({
  name: z.string().min(1, "Name is required").max(255),
  model: z.string().max(100).optional().or(z.literal("")),
  manufacturer: z.string().max(100).optional().or(z.literal("")),
  macAddress: z
    .string()
    .regex(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/, "Invalid MAC address format (e.g. AA:BB:CC:DD:EE:FF)")
    .optional()
    .or(z.literal("")),
})

type EditFormData = z.infer<typeof editSchema>

interface DeviceEditDialogProps {
  device: Device
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function DeviceEditDialog({ device, open, onOpenChange }: DeviceEditDialogProps) {
  const updateDevice = useUpdateDevice(device.id)

  const form = useForm<EditFormData>({
    resolver: zodResolver(editSchema),
    defaultValues: {
      name: device.name,
      model: device.model ?? "",
      manufacturer: device.manufacturer ?? "",
      macAddress: device.macAddress ?? "",
    },
  })

  // Reset form values when the device prop changes (e.g. navigating between devices)
  useEffect(() => {
    if (open) {
      form.reset({
        name: device.name,
        model: device.model ?? "",
        manufacturer: device.manufacturer ?? "",
        macAddress: device.macAddress ?? "",
      })
    }
  }, [device, form, open])

  const onSubmit = async (data: EditFormData) => {
    await updateDevice.mutateAsync({
      name: data.name,
      model: data.model || null,
      manufacturer: data.manufacturer || null,
      macAddress: data.macAddress || null,
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Device</DialogTitle>
          <DialogDescription>Update device information. Changes take effect immediately.</DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="e.g. Desk Phone - Main Office" />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="model"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Model</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="e.g. Polycom VVX 450" />
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
                    <Input {...field} placeholder="e.g. Polycom" />
                  </FormControl>
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
                    <Input {...field} placeholder="AA:BB:CC:DD:EE:FF" />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.formState.errors.root && (
              <div className="rounded-md border border-destructive/20 bg-destructive/10 p-3">
                <p className="text-sm text-destructive">{form.formState.errors.root.message}</p>
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? "Saving..." : "Save Changes"}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
