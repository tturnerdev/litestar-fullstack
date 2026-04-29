import { zodResolver } from "@hookform/resolvers/zod"
import { useEffect } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useUpdateProfile } from "@/lib/api/hooks/profile"
import type { User } from "@/lib/generated/api/types.gen"

const personalInfoSchema = z.object({
  name: z.string().max(120, "Name must be 120 characters or fewer"),
  username: z.string().max(30, "Username must be 30 characters or fewer"),
  phone: z.string(),
})

type PersonalInfoValues = z.infer<typeof personalInfoSchema>

interface PersonalInfoFormProps {
  user: User
}

export function PersonalInfoForm({ user }: PersonalInfoFormProps) {
  const updateProfile = useUpdateProfile()

  const form = useForm<PersonalInfoValues>({
    resolver: zodResolver(personalInfoSchema),
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
    if (values.phone !== (user.phone ?? "")) {
      updates.phone = values.phone || null
    }

    if (Object.keys(updates).length === 0) {
      return
    }

    updateProfile.mutate(updates)
  }

  const isDirty = form.formState.isDirty

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
                      <Input placeholder="Jane Doe" {...field} />
                    </FormControl>
                    <FormMessage />
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
                      <Input placeholder="janedoe" {...field} />
                    </FormControl>
                    <FormMessage />
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
                      <Input placeholder="+15551234567" {...field} />
                    </FormControl>
                    <FormDescription>International format with country code</FormDescription>
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

            <div className="flex justify-end pt-2">
              <Button type="submit" disabled={!isDirty || updateProfile.isPending}>
                {updateProfile.isPending ? "Saving..." : "Save changes"}
              </Button>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}
