import { Link } from "@tanstack/react-router"
import { Monitor, MoreVertical, Phone, Power, Radio, RefreshCw, Settings } from "lucide-react"
import type { Device } from "@/lib/generated/api"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

const deviceTypeIcons: Record<string, typeof Phone> = {
  desk_phone: Phone,
  softphone: Monitor,
  ata: Radio,
  conference: Phone,
  other: Settings,
}

function formatLastSeen(value: string | null | undefined): string {
  if (!value) return "Never"
  const date = new Date(value)
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
}

interface DeviceCardProps {
  device: Device
  onReboot?: (deviceId: string) => void
  onToggleActive?: (deviceId: string, isActive: boolean) => void
}

export function DeviceCard({ device, onReboot, onToggleActive }: DeviceCardProps) {
  const Icon = deviceTypeIcons[device.deviceType] ?? Settings

  return (
    <Card className="group relative transition-shadow hover:shadow-md">
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Icon className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <Link
              to="/devices/$deviceId"
              params={{ deviceId: device.id }}
              className="font-semibold text-sm hover:underline"
            >
              {device.name}
            </Link>
            <p className="text-xs text-muted-foreground">{deviceTypeLabels[device.deviceType] ?? device.deviceType}</p>
          </div>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/devices/$deviceId" params={{ deviceId: device.id }}>
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {onReboot && (
              <DropdownMenuItem onClick={() => onReboot(device.id)}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Reboot
              </DropdownMenuItem>
            )}
            {onToggleActive && (
              <DropdownMenuItem onClick={() => onToggleActive(device.id, !device.isActive)}>
                <Power className="mr-2 h-4 w-4" />
                {device.isActive ? "Disable" : "Enable"}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2">
          <DeviceStatusBadge status={device.status} />
          {!device.isActive && (
            <Badge variant="outline" className="border-muted-foreground/30 text-muted-foreground">
              Disabled
            </Badge>
          )}
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {device.macAddress && (
            <div>
              <span className="text-muted-foreground">MAC</span>
              <p className="truncate font-mono">{device.macAddress}</p>
            </div>
          )}
          {device.deviceModel && (
            <div>
              <span className="text-muted-foreground">Model</span>
              <p className="truncate">{device.deviceModel}</p>
            </div>
          )}
          {device.ipAddress && (
            <div>
              <span className="text-muted-foreground">IP</span>
              <p className="truncate font-mono">{device.ipAddress}</p>
            </div>
          )}
          <div>
            <span className="text-muted-foreground">Last seen</span>
            <p className="truncate">{formatLastSeen(device.lastSeenAt)}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
