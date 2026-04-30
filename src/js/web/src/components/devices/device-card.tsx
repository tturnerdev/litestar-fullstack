import { useState } from "react"
import { Link } from "@tanstack/react-router"
import { Check, Copy, Monitor, MoreVertical, Phone, PhoneCall, Power, Radio, RefreshCw, Settings, Shield } from "lucide-react"
import type { Device } from "@/lib/generated/api"
import { DeviceStatusBadge } from "@/components/devices/device-status-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { formatRelativeTimeShort } from "@/lib/date-utils"
import { cn } from "@/lib/utils"

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
  conference: PhoneCall,
  other: Settings,
}

const deviceTypeIconBg: Record<string, string> = {
  desk_phone: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  softphone: "bg-violet-500/10 text-violet-600 dark:text-violet-400",
  ata: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
  conference: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  other: "bg-slate-500/10 text-slate-600 dark:text-slate-400",
}

interface DeviceCardProps {
  device: Device
  lineCount?: number
  onReboot?: (deviceId: string) => void
  onToggleActive?: (deviceId: string, isActive: boolean) => void
}

export function DeviceCard({ device, lineCount, onReboot, onToggleActive }: DeviceCardProps) {
  const Icon = deviceTypeIcons[device.deviceType] ?? Settings
  const iconBg = deviceTypeIconBg[device.deviceType] ?? deviceTypeIconBg.other
  const isPulsing = device.status === "provisioning" || device.status === "registering"
  const resolvedLineCount = lineCount ?? device.lines?.length ?? 0
  const [copied, setCopied] = useState(false)

  function handleCopyMac() {
    if (!device.macAddress) return
    navigator.clipboard.writeText(device.macAddress).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <Card
      className={cn(
        "group relative transition-all duration-200 hover:shadow-md hover:scale-[1.02] border-t-2",
        device.isActive !== false ? "border-t-emerald-500/60" : "border-t-muted-foreground/20",
      )}
    >
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div className="flex items-center gap-3">
          <div className={cn("relative flex h-10 w-10 items-center justify-center rounded-lg", iconBg)}>
            <Icon className="h-5 w-5" />
            {isPulsing && (
              <span className="absolute inset-0 animate-ping rounded-lg bg-current opacity-10" />
            )}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Link
                to="/devices/$deviceId"
                params={{ deviceId: device.id }}
                className="font-semibold text-sm hover:underline"
              >
                {device.name}
              </Link>
              {resolvedLineCount > 0 && (
                <Badge variant="secondary" className="h-5 px-1.5 text-[10px] font-medium">
                  {resolvedLineCount} {resolvedLineCount === 1 ? "line" : "lines"}
                </Badge>
              )}
            </div>
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
          {device.firmwareVersion && (
            <Badge variant="outline" className="h-5 gap-1 px-1.5 text-[10px] font-mono">
              <Shield className="h-3 w-3" />
              {device.firmwareVersion}
            </Badge>
          )}
        </div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
          {device.macAddress && (
            <div className="group/mac flex items-center gap-1">
              <div className="min-w-0">
                <span className="text-muted-foreground">MAC</span>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <p className="truncate font-mono">{device.macAddress}</p>
                  </TooltipTrigger>
                  <TooltipContent>{device.macAddress}</TooltipContent>
                </Tooltip>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 shrink-0 p-0 opacity-0 transition-opacity group-hover/mac:opacity-100"
                onClick={handleCopyMac}
              >
                {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                <span className="sr-only">Copy MAC address</span>
              </Button>
            </div>
          )}
          {device.deviceModel && (
            <div>
              <span className="text-muted-foreground">Model</span>
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="truncate">{device.deviceModel}</p>
                </TooltipTrigger>
                <TooltipContent>{device.deviceModel}</TooltipContent>
              </Tooltip>
            </div>
          )}
          {device.ipAddress && (
            <div>
              <span className="text-muted-foreground">IP</span>
              <Tooltip>
                <TooltipTrigger asChild>
                  <p className="truncate font-mono">{device.ipAddress}</p>
                </TooltipTrigger>
                <TooltipContent>{device.ipAddress}</TooltipContent>
              </Tooltip>
            </div>
          )}
          <div>
            <span className="text-muted-foreground">Last seen</span>
            <Tooltip>
              <TooltipTrigger asChild>
                <p className="truncate">{formatRelativeTimeShort(device.lastSeenAt)}</p>
              </TooltipTrigger>
              <TooltipContent>
                {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : "Never"}
              </TooltipContent>
            </Tooltip>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
