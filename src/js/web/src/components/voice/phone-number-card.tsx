import { Phone } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
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
  return (
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
        <Badge variant={phoneNumber.isActive ? "default" : "outline"}>
          {phoneNumber.isActive ? "Active" : "Inactive"}
        </Badge>
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
  )
}
