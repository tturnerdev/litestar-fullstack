import { zodResolver } from "@hookform/resolvers/zod"
import { Link, useRouter } from "@tanstack/react-router"
import { AlertCircle, Loader2 } from "lucide-react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { useAuthStore } from "@/lib/auth"
import { useCreateLocation, useLocations } from "@/lib/api/hooks/locations"

const createLocationSchema = z
  .object({
    name: z.string().min(1, "Location name is required"),
    locationType: z.enum(["ADDRESSED", "PHYSICAL"], { message: "Location type is required" }),
    description: z.string().optional(),
    parentId: z.string().optional(),
    addressLine1: z.string().optional(),
    addressLine2: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    postalCode: z.string().optional(),
    country: z.string().optional(),
  })
  .refine(
    (data) => {
      if (data.locationType === "ADDRESSED") {
        return !!data.addressLine1 && !!data.city && !!data.state && !!data.postalCode
      }
      return true
    },
    { message: "Address fields are required for addressed locations", path: ["addressLine1"] },
  )
  .refine(
    (data) => {
      if (data.locationType === "PHYSICAL") {
        return !!data.parentId
      }
      return true
    },
    { message: "A parent location is required for physical locations", path: ["parentId"] },
  )

type CreateLocationFormData = z.infer<typeof createLocationSchema>

export function CreateLocationForm() {
  const router = useRouter()
  const { currentTeam } = useAuthStore()
  const createLocation = useCreateLocation()
  const teamId = currentTeam?.id ?? ""

  // Fetch addressed locations to use as parent options for physical locations
  const { data: addressedData } = useLocations({
    teamId,
    locationType: "ADDRESSED",
    pageSize: 100,
  })
  const addressedLocations = addressedData?.items ?? []

  const form = useForm<CreateLocationFormData>({
    resolver: zodResolver(createLocationSchema),
    defaultValues: {
      name: "",
      locationType: "ADDRESSED",
      description: "",
      parentId: "",
      addressLine1: "",
      addressLine2: "",
      city: "",
      state: "",
      postalCode: "",
      country: "",
    },
  })

  const locationType = form.watch("locationType")
  const isAddressed = locationType === "ADDRESSED"
  const isPhysical = locationType === "PHYSICAL"

  const onSubmit = async (data: CreateLocationFormData) => {
    if (!teamId) {
      form.setError("root", { message: "No team selected" })
      return
    }
    try {
      const location = await createLocation.mutateAsync({
        name: data.name,
        locationType: data.locationType,
        teamId,
        description: data.description || undefined,
        parentId: isPhysical && data.parentId ? data.parentId : undefined,
        addressLine1: isAddressed ? data.addressLine1 || undefined : undefined,
        addressLine2: isAddressed ? data.addressLine2 || undefined : undefined,
        city: isAddressed ? data.city || undefined : undefined,
        state: isAddressed ? data.state || undefined : undefined,
        postalCode: isAddressed ? data.postalCode || undefined : undefined,
        country: isAddressed ? data.country || undefined : undefined,
      })
      router.invalidate()
      router.navigate({ to: "/locations/$locationId", params: { locationId: location.id } })
    } catch (_error) {
      form.setError("root", { message: "Failed to create location" })
    }
  }

  if (!currentTeam) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <p>Please select a team from the sidebar to create a location.</p>
      </div>
    )
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Location Name</FormLabel>
              <FormControl>
                <Input placeholder="Main Office" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="locationType"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Location Type</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a location type" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="ADDRESSED">Addressed (has a mailing address)</SelectItem>
                  <SelectItem value="PHYSICAL">Physical (specific room or area within a location)</SelectItem>
                </SelectContent>
              </Select>
              <FormDescription>
                {isAddressed
                  ? "An addressed location is a top-level location with a mailing address, like an office or branch."
                  : "A physical location is a specific place within an addressed location, like a room or desk."}
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Textarea placeholder="Optional description of this location..." rows={3} {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {isPhysical && (
          <FormField
            control={form.control}
            name="parentId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Parent Location</FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a parent location" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {addressedLocations.map((loc) => (
                      <SelectItem key={loc.id} value={loc.id}>
                        {loc.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormDescription>
                  The addressed location this physical location belongs to.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        )}

        {isAddressed && (
          <>
            <Separator />
            <div className="space-y-4">
              <h4 className="text-sm font-medium">Address</h4>
              <FormField
                control={form.control}
                name="addressLine1"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Address Line 1</FormLabel>
                    <FormControl>
                      <Input placeholder="123 Main Street" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="addressLine2"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Address Line 2</FormLabel>
                    <FormControl>
                      <Input placeholder="Suite 200" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="city"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>City</FormLabel>
                      <FormControl>
                        <Input placeholder="Austin" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="state"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>State / Province</FormLabel>
                      <FormControl>
                        <Input placeholder="TX" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="postalCode"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Postal Code</FormLabel>
                      <FormControl>
                        <Input placeholder="78701" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="country"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Country</FormLabel>
                      <FormControl>
                        <Input placeholder="US" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            </div>
          </>
        )}

        {form.formState.errors.root && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{form.formState.errors.root.message}</AlertDescription>
          </Alert>
        )}

        <Separator />

        <div className="flex items-center justify-between">
          <Button type="button" variant="ghost" asChild>
            <Link to="/locations">Cancel</Link>
          </Button>
          <Button type="submit" disabled={form.formState.isSubmitting}>
            {form.formState.isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {form.formState.isSubmitting ? "Creating..." : "Create Location"}
          </Button>
        </div>
      </form>
    </Form>
  )
}
