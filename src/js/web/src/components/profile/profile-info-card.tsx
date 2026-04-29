import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Loader2, Save } from "lucide-react"
import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuthStore } from "@/lib/auth"
import { accountProfileUpdate } from "@/lib/generated/api"
import { accountProfileQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"
import type { ProfileUpdate } from "@/lib/generated/api/types.gen"

function getInitials(name: string | null | undefined, email: string): string {
  if (name) {
    return name
      .split(" ")
      .map((part) => part[0])
      .filter(Boolean)
      .slice(0, 2)
      .join("")
      .toUpperCase()
  }
  return email.charAt(0).toUpperCase()
}

export function ProfileInfoCard() {
  const { user, checkAuth } = useAuthStore()
  const queryClient = useQueryClient()

  const [name, setName] = useState(user?.name ?? "")
  const [username, setUsername] = useState(user?.username ?? "")
  const [phone, setPhone] = useState(user?.phone ?? "")

  // Sync form state when user data changes (e.g. after auth refresh)
  useEffect(() => {
    if (user) {
      setName(user.name ?? "")
      setUsername(user.username ?? "")
      setPhone(user.phone ?? "")
    }
  }, [user])

  const updateProfile = useMutation({
    mutationFn: async (body: ProfileUpdate) => {
      const { data } = await accountProfileUpdate({
        body,
        throwOnError: true,
      })
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: accountProfileQueryKey() })
      void checkAuth()
      toast.success("Profile updated successfully")
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : "Failed to update profile"
      toast.error("Unable to update profile", { description: message })
    },
  })

  const hasChanges =
    name !== (user?.name ?? "") ||
    username !== (user?.username ?? "") ||
    phone !== (user?.phone ?? "")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!hasChanges) return

    const body: ProfileUpdate = {}
    if (name !== (user?.name ?? "")) body.name = name || null
    if (username !== (user?.username ?? "")) body.username = username || null
    if (phone !== (user?.phone ?? "")) body.phone = phone || null

    updateProfile.mutate(body)
  }

  if (!user) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle>Profile information</CardTitle>
        <CardDescription>Update your display name and contact details.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="flex items-center gap-4">
            <Avatar className="h-16 w-16 text-lg">
              <AvatarFallback className="bg-primary/10 text-primary font-semibold">
                {getInitials(user.name, user.email)}
              </AvatarFallback>
            </Avatar>
            <div className="min-w-0">
              <p className="truncate font-medium text-lg">{user.name || user.email}</p>
              <p className="truncate text-muted-foreground text-sm">{user.email}</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="profile-name">Display name</Label>
              <Input
                id="profile-name"
                placeholder="Your name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-email">Email</Label>
              <Input
                id="profile-email"
                value={user.email}
                disabled
                className="bg-muted/50"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-username">Username</Label>
              <Input
                id="profile-username"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-phone">Phone</Label>
              <Input
                id="profile-phone"
                type="tel"
                placeholder="+1 (555) 123-4567"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                autoComplete="tel"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <Button type="submit" disabled={!hasChanges || updateProfile.isPending}>
              {updateProfile.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Save className="mr-2 h-4 w-4" />
              )}
              Save changes
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
