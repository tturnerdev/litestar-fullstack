import { zodResolver } from "@hookform/resolvers/zod"
import { Link, useBlocker, useRouter } from "@tanstack/react-router"
import {
  AlertCircle,
  Cable,
  Headset,
  Loader2,
  type LucideIcon,
  MapPin,
  MoreHorizontal,
  Network,
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
import { Button } from "@/components/ui/button"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { useConnections } from "@/lib/api/hooks/connections"
import { useCreateDevice } from "@/lib/api/hooks/devices"
import { useLocations } from "@/lib/api/hooks/locations"
import { useAuthStore } from "@/lib/auth"
import { formatMacAddress } from "@/lib/format-utils"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NAME_MAX = 100

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

const createDeviceSchema = z.object({
  name: z.string().min(1, "Device name is required").max(NAME_MAX, "Name must be 100 characters or fewer"),
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
  teamId: z.string().optional(),
  locationId: z.string().optional(),
  connectionId: z.string().optional(),
})

type CreateDeviceFormData = z.infer<typeof createDeviceSchema>

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CreateDeviceForm() {
  const router = useRouter()
  const createDevice = useCreateDevice()
  const justSubmittedRef = useRef(false)

  const form = useForm<CreateDeviceFormData>({
    resolver: zodResolver(createDeviceSchema),
    defaultValues: {
      name: "",
      deviceType: "",
      macAddress: "",
      ipAddress: "",
      deviceModel: "",
      manufacturer: "",
      teamId: "",
      locationId: "",
      connectionId: "",
    },
  })

  const { currentTeam } = useAuthStore()
  const formTeamId = form.watch("teamId") ?? ""
  const effectiveTeamId = formTeamId || currentTeam?.id || ""
  const locationsQuery = useLocations({ teamId: effectiveTeamId, pageSize: 100 })
  const connectionsQuery = useConnections({ teamId: effectiveTeamId, pageSize: 100 })

  const { isDirty, isSubmitting } = form.formState
  const nameLength = (form.watch("name") ?? "").length

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

  // Submit handler ------------------------------------------------------
  const onSubmit = async (data: CreateDeviceFormData) => {
    try {
      justSubmittedRef.current = true
      const device = await createDevice.mutateAsync({
        name: data.name,
        deviceType: data.deviceType,
        macAddress: data.macAddress || undefined,
        deviceModel: data.deviceModel || undefined,
        manufacturer: data.manufacturer || undefined,
        teamId: data.teamId || undefined,
        locationId: data.locationId || undefined,
        connectionId: data.connectionId || undefined,
      })
      router.invalidate()
      router.navigate({ to: "/devices/$deviceId", params: { deviceId: device.id } })
    } catch (_error) {
      justSubmittedRef.current = false
      form.setError("root", {
        message: "Failed to create device. Please check your inputs and try again.",
      })
    }
  }

  return (
    <>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
          {/* ── Required fields ──────────────────────────────────────── */}

          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <RequiredLabel>Device Name</RequiredLabel>
                <FormControl>
                  <Input placeholder="Desk Phone - Office" maxLength={NAME_MAX} {...field} />
                </FormControl>
                <div className="flex items-center justify-between">
                  <FormDescription>A friendly label to identify this device.</FormDescription>
                  <p className={cn("shrink-0 text-xs", nameLength >= NAME_MAX ? "text-destructive" : nameLength >= NAME_MAX * 0.8 ? "text-amber-500" : "text-muted-foreground")}>
                    {nameLength}/{NAME_MAX}
                  </p>
                </div>
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
                <Select onValueChange={field.onChange} defaultValue={field.value}>
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

          {/* ── Hardware details ─────────────────────────────────────── */}

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

          <Separator />

          {/* ── Assignment ──────────────────────────────────────────── */}

          <FormField
            control={form.control}
            name="teamId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Team</FormLabel>
                <FormControl>
                  <Input placeholder="Team ID (optional)" {...field} />
                </FormControl>
                <FormDescription>
                  Assign this device to a team for shared access and reporting.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <div className="grid gap-6 sm:grid-cols-2">
            <FormField
              control={form.control}
              name="locationId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="flex items-center gap-1.5">
                    <MapPin className="h-4 w-4 text-muted-foreground" />
                    Location
                  </FormLabel>
                  <Select
                    onValueChange={(v) => field.onChange(v === "__none__" ? "" : v)}
                    defaultValue={field.value || "__none__"}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a location" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="__none__">None</SelectItem>
                      {(locationsQuery.data?.items ?? []).map((loc) => (
                        <SelectItem key={loc.id} value={loc.id}>
                          {loc.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Physical location where this device is installed.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="connectionId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="flex items-center gap-1.5">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    Connection
                  </FormLabel>
                  <Select
                    onValueChange={(v) => field.onChange(v === "__none__" ? "" : v)}
                    defaultValue={field.value || "__none__"}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a connection" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="__none__">None</SelectItem>
                      {(connectionsQuery.data?.items ?? []).map((conn) => (
                        <SelectItem key={conn.id} value={conn.id}>
                          {conn.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    SIP trunk or provider connection for this device.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {/* ── Root error ──────────────────────────────────────────── */}

          {form.formState.errors.root && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
            </Alert>
          )}

          <Separator />

          {/* ── Actions ─────────────────────────────────────────────── */}

          <div className="flex items-center justify-between">
            <Button type="button" variant="ghost" asChild>
              <Link to="/devices">Cancel</Link>
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isSubmitting ? "Creating..." : "Add Device"}
            </Button>
          </div>
        </form>
      </Form>

      {/* ── Unsaved changes dialog ──────────────────────────────────── */}
      <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
            <AlertDialogDescription>
              You have unsaved changes to this device form. Are you sure you want to leave? Your changes will be lost.
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
