import { zodResolver } from "@hookform/resolvers/zod"
import { Check } from "lucide-react"
import { useEffect, useState } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useUpdateProfile } from "@/lib/api/hooks/profile"
import type { User } from "@/lib/generated/api/types.gen"

const NAME_MAX = 120
const USERNAME_MAX = 30

function formatPhone(value: string): string {
  const digits = value.replace(/\D/g, "")
  if (digits.length <= 1) return digits ? `+${digits}` : ""
  if (digits.length <= 4) return `+${digits.slice(0, 1)} (${digits.slice(1)}`
  if (digits.length <= 7) return `+${digits.slice(0, 1)} (${digits.slice(1, 4)}) ${digits.slice(4)}`
  return `+${digits.slice(0, 1)} (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7, 11)}`
}

const personalInfoSchema = z.object({
  name: z.string().max(NAME_MAX, `Name must be ${NAME_MAX} characters or fewer`),
  username: z
    .string()
    .max(USERNAME_MAX, `Username must be ${USERNAME_MAX} characters or fewer`)
    .refine((val) => val === "" || val.length >= 3, { message: "Username must be at least 3 characters" })
    .refine((val) => val === "" || /^[a-z0-9_]+$/.test(val), {
      message: "Username must be lowercase letters, numbers, and underscores only",
    }),
  phone: z.string(),
})

type PersonalInfoValues = z.infer<typeof personalInfoSchema>

interface PersonalInfoFormProps {
  user: User
}

export function PersonalInfoForm({ user }: PersonalInfoFormProps) {
  const updateProfile = useUpdateProfile()
  const [showSuccess, setShowSuccess] = useState(false)

  const form = useForm<PersonalInfoValues>({
    resolver: zodResolver(personalInfoSchema),
    mode: "onChange",
    defaultValues: {
      name: user.name ?? "",
      username: user.username ?? "",
      phone: user.phone ?? "",
    },
  })

  useEffect(() => {
    form.reset({
      name: user.name ?? "",
      username: user.username ?? "",
      phone: user.phone ?? "",
    })
  }, [user, form])

  const onSubmit = (values: PersonalInfoValues) => {
    const updates: Record<string, string | null> = {}
    if (values.name !== (user.name ?? "")) {
      updates.name = values.name || null
    }
    if (values.username !== (user.username ?? "")) {
      updates.username = values.username || null
    }
    // Strip formatting before comparing/sending phone
    const rawPhone = values.phone.replace(/\D/g, "")
    const existingPhone = (user.phone ?? "").replace(/\D/g, "")
    if (rawPhone !== existingPhone) {
      updates.phone = rawPhone ? `+${rawPhone}` : null
    }

    if (Object.keys(updates).length === 0) {
      return
    }

    updateProfile.mutate(updates, {
      onSuccess: () => {
        setShowSuccess(true)
        setTimeout(() => setShowSuccess(false), 2000)
      },
    })
  }

  const handleCancel = () => {
    form.reset({
      name: user.name ?? "",
      username: user.username ?? "",
      phone: user.phone ?? "",
    })
  }

  const isDirty = form.formState.isDirty
  const nameValue = form.watch("name")
  const usernameValue = form.watch("username")

  return (
    <Card>
      <CardHeader>
        <CardTitle>Personal information</CardTitle>
        <CardDescription>Update your name, username, and phone number.</CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Full name</FormLabel>
                    <FormControl>
                      <Input placeholder="Jane Doe" maxLength={NAME_MAX} {...field} />
                    </FormControl>
                    <div className="flex items-center justify-between">
                      <FormMessage />
                      <p className="ml-auto text-xs text-muted-foreground">{NAME_MAX - nameValue.length} remaining</p>
                    </div>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input placeholder="janedoe" maxLength={USERNAME_MAX} {...field} />
                    </FormControl>
                    <div className="flex items-center justify-between">
                      <FormMessage />
                      <p className="ml-auto text-xs text-muted-foreground">{USERNAME_MAX - usernameValue.length} remaining</p>
                    </div>
                  </FormItem>
                )}
              />
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                control={form.control}
                name="phone"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Phone number</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="+1 (555) 123-4567"
                        {...field}
                        onChange={(e) => {
                          field.onChange(formatPhone(e.target.value))
                        }}
                      />
                    </FormControl>
                    <FormDescription>US format with country code</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormItem>
                <FormLabel>Email</FormLabel>
                <Input value={user.email} disabled className="bg-muted" />
                <FormDescription>Contact support to change your email</FormDescription>
              </FormItem>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              {isDirty && (
                <Button type="button" variant="ghost" onClick={handleCancel}>
                  Cancel
                </Button>
              )}
              <div className="flex items-center gap-2">
                <Button type="submit" disabled={!isDirty || updateProfile.isPending}>
                  {updateProfile.isPending ? "Saving..." : "Save changes"}
                </Button>
                {showSuccess && <Check className="h-5 w-5 animate-in fade-in zoom-in text-green-500" />}
              </div>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}
