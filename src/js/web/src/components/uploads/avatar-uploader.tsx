import { Loader2, Trash2, Upload } from "lucide-react"
import { useRef, useState } from "react"
import { toast } from "sonner"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useClearAvatar, useSetAvatar } from "@/lib/api/hooks/uploads"
import { useAuthStore } from "@/lib/auth"

const AVATAR_ACCEPT = "image/png,image/jpeg,image/gif,image/webp,image/avif"

function deriveInitials(name: string): string {
  return (
    name
      .split(/\s+/)
      .filter(Boolean)
      .map((part) => part[0])
      .join("")
      .slice(0, 2)
      .toUpperCase() || "?"
  )
}

/**
 * Profile/account-settings widget for managing the current user's avatar.
 * Reads the user from the zustand auth store, mutates via
 * `useSetAvatar` / `useClearAvatar` and lets those hooks refresh the user
 * payload on success.
 */
export function AvatarUploader() {
  const user = useAuthStore((state) => state.user)
  const setAvatar = useSetAvatar()
  const clearAvatar = useClearAvatar()
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [progress, setProgress] = useState(0)

  if (!user) {
    return null
  }

  const displayName = user.name || user.username || user.email
  const initials = deriveInitials(displayName)
  const isPending = setAvatar.isPending || clearAvatar.isPending

  const onFileSelected = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    event.target.value = ""
    if (!file) {
      return
    }
    if (!file.type.startsWith("image/")) {
      toast.error("Avatar must be an image")
      return
    }
    setProgress(0)
    try {
      await setAvatar.mutateAsync({ file, onProgress: setProgress })
    } catch {
      // toast is raised by the hook
    } finally {
      setProgress(0)
    }
  }

  const onClear = async () => {
    try {
      await clearAvatar.mutateAsync()
    } catch {
      // toast is raised by the hook
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Profile photo</CardTitle>
        <CardDescription>PNG, JPEG, GIF, or WebP. Up to 25 MiB.</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
          <Avatar className="h-20 w-20 rounded-full">
            <AvatarImage src={user.avatarUrl ?? undefined} alt={displayName} />
            <AvatarFallback className="text-lg text-muted-foreground">{initials}</AvatarFallback>
          </Avatar>
          <div className="flex flex-1 flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <input ref={inputRef} type="file" accept={AVATAR_ACCEPT} className="sr-only" onChange={onFileSelected} disabled={isPending} />
              <Button type="button" variant="outline" onClick={() => inputRef.current?.click()} disabled={isPending}>
                {setAvatar.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                {setAvatar.isPending ? `Uploading… ${progress}%` : user.avatarUrl ? "Replace photo" : "Upload photo"}
              </Button>
              {user.avatarUrl && (
                <Button type="button" variant="ghost" onClick={onClear} disabled={isPending}>
                  {clearAvatar.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                  Remove
                </Button>
              )}
            </div>
            {setAvatar.isPending && (
              <div
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={progress}
                aria-label="Avatar upload progress"
                className="h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-muted"
              >
                <div className="h-full bg-primary transition-[width]" style={{ width: `${progress}%` }} />
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
