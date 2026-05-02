import { Shield, ShieldOff } from "lucide-react"
import { Badge } from "@/components/ui/badge"

export function E911StatusBadge({
  registered,
}: {
  registered: boolean
  registrationId?: string | null
}) {
  if (registered) {
    return (
      <Badge variant="default" className="bg-emerald-600 text-white shadow-sm">
        <Shield className="mr-1 h-3 w-3" />
        E911 Registered
      </Badge>
    )
  }
  return (
    <Badge variant="outline">
      <ShieldOff className="mr-1 h-3 w-3" />
      No E911
    </Badge>
  )
}
