import { AlertTriangle, Loader2, Phone, Trash2 } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useDeletePhoneNumber } from "@/lib/api/hooks/voice"
import type { PhoneNumber } from "@/lib/api/hooks/voice"

const TYPE_LABELS: Record<string, string> = {
  local: "Local",
  toll_free: "Toll-Free",
  international: "International",
}

interface PhoneNumberCardProps {
  phoneNumber: PhoneNumber
}

export function PhoneNumberCard({ phoneNumber }: PhoneNumberCardProps) {
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const deleteMutation = useDeletePhoneNumber()

  return (
    <>
      <Card hover>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
              <Phone className="h-5 w-5 text-primary" />
            </div>
            <div>
              <CardTitle className="text-base">{phoneNumber.label ?? "Unlabeled"}</CardTitle>
              <p className="font-mono text-sm text-muted-foreground">{phoneNumber.number}</p>
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
            <Badge variant="secondary">{TYPE_LABELS[phoneNumber.numberType] ?? phoneNumber.numberType}</Badge>
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
        </CardContent>
      </Card>

      <Dialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Phone Number
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete <span className="font-mono font-medium">{phoneNumber.number}</span>? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeleteDialog(false)} disabled={deleteMutation.isPending}>
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
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
