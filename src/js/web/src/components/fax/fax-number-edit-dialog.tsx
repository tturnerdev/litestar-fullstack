import { zodResolver } from "@hookform/resolvers/zod"
import { Loader2, Pencil } from "lucide-react"
import { useEffect, useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { type FaxNumber, useUpdateFaxNumber } from "@/lib/api/hooks/fax"

const editFaxNumberSchema = z.object({
  label: z.string().max(100, "Label must be 100 characters or fewer").optional(),
  isActive: z.enum(["true", "false"]),
})

type EditFaxNumberFormData = z.infer<typeof editFaxNumberSchema>

interface FaxNumberEditDialogProps {
  faxNumber: FaxNumber
  trigger?: React.ReactNode
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function FaxNumberEditDialog({ faxNumber, trigger, open: controlledOpen, onOpenChange }: FaxNumberEditDialogProps) {
  const [internalOpen, setInternalOpen] = useState(false)
  const open = controlledOpen ?? internalOpen
  const setOpen = onOpenChange ?? setInternalOpen
  const updateFaxNumber = useUpdateFaxNumber(faxNumber.id)

  const form = useForm<EditFaxNumberFormData>({
    resolver: zodResolver(editFaxNumberSchema),
    defaultValues: {
      label: faxNumber.label ?? "",
      isActive: faxNumber.isActive ? "true" : "false",
    },
  })

  useEffect(() => {
    if (open) {
      form.reset({
        label: faxNumber.label ?? "",
        isActive: faxNumber.isActive ? "true" : "false",
      })
    }
  }, [open, faxNumber, form])

  const onSubmit = async (data: EditFaxNumberFormData) => {
    const trimmedLabel = data.label?.trim() || null
    const isActive = data.isActive === "true"

    const hasLabelChanged = trimmedLabel !== (faxNumber.label ?? null)
    const hasActiveChanged = isActive !== faxNumber.isActive

    if (!hasLabelChanged && !hasActiveChanged) {
      setOpen(false)
      return
    }

    const payload: Record<string, unknown> = {}
    if (hasLabelChanged) payload.label = trimmedLabel
    if (hasActiveChanged) payload.isActive = isActive

    updateFaxNumber.mutate(payload, {
      onSuccess: () => {
        setOpen(false)
      },
    })
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      {controlledOpen === undefined && (
        <DialogTrigger asChild>
          {trigger ?? (
            <Button variant="outline" size="sm">
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </Button>
          )}
        </DialogTrigger>
      )}
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Fax Number</DialogTitle>
          <DialogDescription>
            Update the label and status for{" "}
            <span className="font-mono font-medium text-foreground">{faxNumber.number}</span>.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
            <FormField
              control={form.control}
              name="label"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Label</FormLabel>
                  <FormControl>
                    <Input
                      {...field}
                      placeholder="e.g. Main Fax, Billing Dept"
                    />
                  </FormControl>
                  <FormDescription>
                    A friendly name to identify this fax number.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="isActive"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Status</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue>
                          <span className="flex items-center gap-2">
                            <Badge
                              variant={field.value === "true" ? "default" : "secondary"}
                              className="pointer-events-none"
                            >
                              {field.value === "true" ? "Active" : "Inactive"}
                            </Badge>
                          </span>
                        </SelectValue>
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="true">
                        <div className="flex items-center gap-2">
                          <Badge variant="default" className="pointer-events-none">Active</Badge>
                          <span className="text-xs text-muted-foreground">Number can send and receive faxes</span>
                        </div>
                      </SelectItem>
                      <SelectItem value="false">
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary" className="pointer-events-none">Inactive</Badge>
                          <span className="text-xs text-muted-foreground">Number is disabled</span>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            {form.formState.errors.root && (
              <div className="rounded-md bg-destructive/10 border border-destructive/20 p-3">
                <p className="text-destructive text-sm">
                  {form.formState.errors.root.message}
                </p>
              </div>
            )}
            <div className="flex justify-end gap-3 pt-2">
              <Button
                type="button"
                variant="ghost"
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={form.formState.isSubmitting || updateFaxNumber.isPending}
              >
                {(form.formState.isSubmitting || updateFaxNumber.isPending) && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {form.formState.isSubmitting || updateFaxNumber.isPending
                  ? "Saving..."
                  : "Save Changes"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
