import { Link } from "@tanstack/react-router"
import { Hash, Mail, Settings } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { FaxNumber } from "@/lib/api/hooks/fax"

interface FaxNumberCardProps {
  faxNumber: FaxNumber
}

export function FaxNumberCard({ faxNumber }: FaxNumberCardProps) {
  return (
    <Card hover>
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Hash className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <CardTitle className="text-sm truncate">
              {faxNumber.label ?? faxNumber.number}
            </CardTitle>
            {faxNumber.label && (
              <p className="text-xs text-muted-foreground font-mono">{faxNumber.number}</p>
            )}
          </div>
        </div>
        <Badge variant={faxNumber.isActive ? "default" : "secondary"}>
          {faxNumber.isActive ? "Active" : "Inactive"}
        </Badge>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Mail className="h-3.5 w-3.5" />
            <span>Email routes configured</span>
          </div>
          <Button asChild variant="outline" size="sm">
            <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
              <Settings className="mr-2 h-3.5 w-3.5" />
              Manage
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
