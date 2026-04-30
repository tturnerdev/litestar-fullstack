import {
  AlertTriangle,
  Check,
  Clock,
  Copy,
  Flag,
  Globe,
  Loader2,
  MapPin,
  Phone,
  PhoneForwarded,
  Trash2,
} from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { useDeletePhoneNumber } from "@/lib/api/hooks/voice"
import type { PhoneNumber } from "@/lib/api/hooks/voice"
import { formatPhoneNumber } from "@/lib/format-utils"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return a relative time string such as "Created 3 days ago" */
function relativeTime(iso: string): string {
  const now = Date.now()
  const then = new Date(iso).getTime()
  const diffMs = now - then
  if (diffMs < 0) return "just now"

  const seconds = Math.floor(diffMs / 1000)
  if (seconds < 60) return "just now"
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  const years = Math.floor(months / 12)
  return `${years}y ago`
}

// ---------------------------------------------------------------------------
// Type config
// ---------------------------------------------------------------------------

const TYPE_CONFIG: Record<
  string,
  { label: string; icon: typeof MapPin; color: string }
> = {
  local: { label: "Local", icon: MapPin, color: "text-blue-600 bg-blue-100 dark:text-blue-400 dark:bg-blue-900/40" },
  toll_free: { label: "Toll-Free", icon: Globe, color: "text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-900/40" },
  international: { label: "International", icon: Flag, color: "text-purple-600 bg-purple-100 dark:text-purple-400 dark:bg-purple-900/40" },
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface PhoneNumberCardProps {
  phoneNumber: PhoneNumber
}

export function PhoneNumberCard({ phoneNumber }: PhoneNumberCardProps) {
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [copied, setCopied] = useState(false)
  const deleteMutation = useDeletePhoneNumber()

  const typeConfig = TYPE_CONFIG[phoneNumber.numberType] ?? {
    label: phoneNumber.numberType,
    icon: Phone,
    color: "text-muted-foreground bg-muted",
  }
  const TypeIcon = typeConfig.icon

  function handleCopy() {
    void navigator.clipboard.writeText(phoneNumber.number).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <>
      <Card
        hover
        className={`transition-transform duration-200 hover:scale-[1.02] border-l-4 ${
          phoneNumber.isActive ? "border-l-green-500" : "border-l-muted-foreground/30"
        }`}
      >
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Phone className="h-5 w-5 text-primary" />
            </div>
            <div>
              <CardTitle className="text-base">{phoneNumber.label ?? "Unlabeled"}</CardTitle>
              <div className="flex items-center gap-1.5">
                <p className="font-mono text-sm text-muted-foreground">
                  {formatPhoneNumber(phoneNumber.number)}
                </p>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-6 w-6 opacity-0 group-hover:opacity-100 hover:opacity-100 focus:opacity-100 transition-opacity"
                  onClick={handleCopy}
                  title="Copy phone number"
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-green-500" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </Button>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={phoneNumber.isActive ? "default" : "outline"}>
              {phoneNumber.isActive ? "Active" : "Inactive"}
            </Badge>
            <Button
              size="icon"
              variant="ghost"
              className="h-8 w-8 text-destructive hover:bg-destructive hover:text-destructive-foreground"
              onClick={() => setShowDeleteDialog(true)}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Type</span>
            <span
              className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium ${typeConfig.color}`}
            >
              <TypeIcon className="h-3.5 w-3.5" />
              {typeConfig.label}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Caller ID</span>
            <span>{phoneNumber.callerIdName ?? "--"}</span>
          </div>
          {phoneNumber.teamId && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Shared</span>
              <Badge variant="secondary">Team</Badge>
            </div>
          )}
          {phoneNumber.extensionId && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Extension</span>
              <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                <PhoneForwarded className="h-3.5 w-3.5" />
                Assigned to extension
              </span>
            </div>
          )}
          {phoneNumber.createdAt && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground pt-1 border-t">
              <Clock className="h-3 w-3" />
              Created {relativeTime(phoneNumber.createdAt)}
            </div>
          )}
        </CardContent>
      </Card>

      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Phone Number
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete{" "}
              <span className="font-mono font-medium">
                {formatPhoneNumber(phoneNumber.number)}
              </span>
              ? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowDeleteDialog(false)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                deleteMutation.mutate(phoneNumber.id, {
                  onSuccess: () => setShowDeleteDialog(false),
                })
              }}
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
