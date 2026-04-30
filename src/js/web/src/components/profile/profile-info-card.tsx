import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Check, Copy, Crown, Loader2, Save, User } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useAuthStore } from "@/lib/auth"
import { accountProfileUpdate } from "@/lib/generated/api"
import { accountProfileQueryKey } from "@/lib/generated/api/@tanstack/react-query.gen"
import type { ProfileUpdate } from "@/lib/generated/api/types.gen"

const NAME_MAX = 100
const USERNAME_MAX = 30

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
  const [emailCopied, setEmailCopied] = useState(false)
  const [showSuccess, setShowSuccess] = useState(false)

  // Sync form state when user data changes (e.g. after auth refresh)
  useEffect(() => {
    if (user) {
      setName(user.name ?? "")
      setUsername(user.username ?? "")
      setPhone(user.phone ?? "")
    }
  }, [user])

  const resetForm = useCallback(() => {
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
      setShowSuccess(true)
      setTimeout(() => setShowSuccess(false), 1500)
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

  const handleCopyEmail = useCallback(() => {
    if (!user) return
    navigator.clipboard.writeText(user.email).then(() => {
      setEmailCopied(true)
      setTimeout(() => setEmailCopied(false), 2000)
    })
  }, [user])

  if (!user) return null

  return (
    <Card className="relative overflow-hidden">
      {/* Success overlay */}
      {showSuccess && (
        <div className="absolute inset-0 z-10 flex items-center justify-center bg-background/80 animate-in fade-in duration-200">
          <div className="flex items-center gap-2 rounded-full bg-green-500/10 px-4 py-2 text-green-600">
            <Check className="h-5 w-5" />
            <span className="text-sm font-medium">Saved</span>
          </div>
        </div>
      )}

      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Profile information
          {hasChanges && (
            <span className="inline-block h-2 w-2 rounded-full bg-amber-500" title="Unsaved changes" />
          )}
        </CardTitle>
        <CardDescription>Update your display name and contact details.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Avatar section with gradient banner */}
          <div className="relative -mx-6 -mt-2 px-6 pb-4 pt-6 bg-gradient-to-r from-primary/8 via-primary/5 to-background rounded-md">
            <div className="flex items-center gap-4">
              <Avatar className="h-16 w-16 text-lg ring-2 ring-background shadow-sm">
                <AvatarFallback className="bg-primary/10 text-primary font-semibold">
                  {getInitials(user.name, user.email)}
                </AvatarFallback>
              </Avatar>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <p className="truncate font-medium text-lg">{user.name || user.email}</p>
                    </TooltipTrigger>
                    <TooltipContent>{user.name || user.email}</TooltipContent>
                  </Tooltip>
                  <Badge variant={user.isSuperuser ? "default" : "secondary"} className="shrink-0">
                    {user.isSuperuser ? (
                      <><Crown className="mr-1 h-3 w-3" /> Admin</>
                    ) : (
                      <><User className="mr-1 h-3 w-3" /> Member</>
                    )}
                  </Badge>
                </div>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="truncate text-muted-foreground text-sm">{user.email}</p>
                  </TooltipTrigger>
                  <TooltipContent>{user.email}</TooltipContent>
                </Tooltip>
              </div>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="profile-name">Display name</Label>
                <span className="text-xs text-muted-foreground">{name.length}/{NAME_MAX}</span>
              </div>
              <Input
                id="profile-name"
                placeholder="Your name"
                value={name}
                onChange={(e) => setName(e.target.value.slice(0, NAME_MAX))}
                autoComplete="name"
                maxLength={NAME_MAX}
              />
              <p className="text-xs text-muted-foreground">How you'll appear to other team members</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="profile-email">Email</Label>
              <div className="flex gap-1">
                <Input
                  id="profile-email"
                  value={user.email}
                  disabled
                  className="bg-muted/50"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="shrink-0"
                  onClick={handleCopyEmail}
                  title="Copy email"
                  aria-label="Copy email"
                >
                  {emailCopied ? (
                    <Check className="h-4 w-4 text-green-600" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="profile-username">Username</Label>
                <span className="text-xs text-muted-foreground">{username.length}/{USERNAME_MAX}</span>
              </div>
              <Input
                id="profile-username"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value.slice(0, USERNAME_MAX))}
                autoComplete="username"
                maxLength={USERNAME_MAX}
              />
              <p className="text-xs text-muted-foreground">Used for @mentions and login</p>
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
              <p className="text-xs text-muted-foreground">Optional contact number</p>
            </div>
          </div>

          <div className="flex justify-end gap-2">
            {hasChanges && (
              <Button type="button" variant="outline" onClick={resetForm}>
                Cancel
              </Button>
            )}
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
