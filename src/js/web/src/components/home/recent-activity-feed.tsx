import { Link } from "@tanstack/react-router"
import { ArrowRight, Laptop, Loader2, TicketCheck, Users } from "lucide-react"
import { TicketStatusBadge } from "@/components/support/ticket-status-badge"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { Ticket } from "@/lib/api/hooks/support"
import type { Device, Team } from "@/lib/generated/api"
import { formatRelativeTimeShort } from "@/lib/date-utils"

// --- Recent Tickets Section ---

function RecentTicketsSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 3 }).map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
        <div key={`ticket-skel-${i}`} className="flex items-center gap-3 px-2 py-2">
          <Skeleton className="h-7 w-7 shrink-0 rounded-full" />
          <div className="flex-1 space-y-1">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/3" />
          </div>
          <Skeleton className="h-5 w-14" />
        </div>
      ))}
    </div>
  )
}

function RecentTicketsSection({
  tickets,
  isLoading,
}: {
  tickets: Ticket[]
  isLoading: boolean
}) {
  if (isLoading) return <RecentTicketsSkeleton />

  if (tickets.length === 0) {
    return (
      <p className="py-4 text-center text-sm text-muted-foreground">No recent tickets</p>
    )
  }

  return (
    <div className="space-y-0.5">
      {tickets.map((ticket) => (
        <Link
          key={ticket.id}
          to="/support/$ticketId"
          params={{ ticketId: ticket.id }}
          className="flex items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-muted/50"
        >
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-500/15">
            <TicketCheck className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{ticket.subject}</p>
            <p className="text-xs text-muted-foreground">
              #{ticket.ticketNumber}
              {ticket.createdAt ? ` · ${formatRelativeTimeShort(ticket.createdAt)}` : ""}
            </p>
          </div>
          <TicketStatusBadge status={ticket.status} />
        </Link>
      ))}
      <div className="pt-2">
        <Link
          to="/support"
          className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          View all tickets
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  )
}

// --- Recent Teams Section ---

function RecentTeamsSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 3 }).map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
        <div key={`team-skel-${i}`} className="flex items-center gap-3 px-2 py-2">
          <Skeleton className="h-7 w-7 shrink-0 rounded-full" />
          <div className="flex-1 space-y-1">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-3 w-1/4" />
          </div>
          <Skeleton className="h-3 w-10" />
        </div>
      ))}
    </div>
  )
}

function RecentTeamsSection({
  teams,
  isLoading,
}: {
  teams: Team[]
  isLoading: boolean
}) {
  if (isLoading) return <RecentTeamsSkeleton />

  if (teams.length === 0) {
    return (
      <p className="py-4 text-center text-sm text-muted-foreground">No recent teams</p>
    )
  }

  return (
    <div className="space-y-0.5">
      {teams.map((team) => (
        <Link
          key={team.id}
          to="/teams/$teamId"
          params={{ teamId: team.id }}
          className="flex items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-muted/50"
        >
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-cyan-500/15">
            <Users className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{team.name}</p>
            <p className="text-xs text-muted-foreground">
              {team.members ? `${team.members.length} member${team.members.length !== 1 ? "s" : ""}` : ""}
              {team.updatedAt ? ` · ${formatRelativeTimeShort(team.updatedAt)}` : ""}
            </p>
          </div>
          {team.isActive === false && (
            <Badge variant="secondary" className="h-5 px-1.5 py-0 text-[10px]">Inactive</Badge>
          )}
        </Link>
      ))}
      <div className="pt-2">
        <Link
          to="/teams"
          className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          View all teams
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  )
}

// --- Recent Devices Section ---

function RecentDevicesSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 3 }).map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
        <div key={`device-skel-${i}`} className="flex items-center gap-3 px-2 py-2">
          <Skeleton className="h-7 w-7 shrink-0 rounded-full" />
          <div className="flex-1 space-y-1">
            <Skeleton className="h-4 w-2/3" />
            <Skeleton className="h-3 w-1/3" />
          </div>
          <Skeleton className="h-5 w-14" />
        </div>
      ))}
    </div>
  )
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "online":
      return "default"
    case "offline":
      return "secondary"
    case "error":
      return "destructive"
    default:
      return "outline"
  }
}

function RecentDevicesSection({
  devices,
  isLoading,
}: {
  devices: Device[]
  isLoading: boolean
}) {
  if (isLoading) return <RecentDevicesSkeleton />

  if (devices.length === 0) {
    return (
      <p className="py-4 text-center text-sm text-muted-foreground">No recent devices</p>
    )
  }

  return (
    <div className="space-y-0.5">
      {devices.map((device) => (
        <Link
          key={device.id}
          to="/devices/$deviceId"
          params={{ deviceId: device.id }}
          className="flex items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-muted/50"
        >
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-blue-500/15">
            <Laptop className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{device.name}</p>
            <p className="text-xs text-muted-foreground">
              {device.deviceType}
              {device.manufacturer ? ` · ${device.manufacturer}` : ""}
            </p>
          </div>
          <Badge variant={statusBadgeVariant(device.status)} className="h-5 px-1.5 py-0 text-[10px] capitalize">
            {device.status}
          </Badge>
        </Link>
      ))}
      <div className="pt-2">
        <Link
          to="/devices"
          className="flex items-center justify-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          View all devices
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  )
}

// --- Main Feed Card ---

interface RecentActivityFeedProps {
  tickets: Ticket[]
  ticketsLoading: boolean
  teams: Team[]
  teamsLoading: boolean
  devices: Device[]
  devicesLoading: boolean
}

export function RecentActivityFeed({
  tickets,
  ticketsLoading,
  teams,
  teamsLoading,
  devices,
  devicesLoading,
}: RecentActivityFeedProps) {
  const allLoading = ticketsLoading && teamsLoading && devicesLoading

  return (
    <Card>
      <CardHeader className="space-y-1 pb-4">
        <div className="flex items-center gap-2">
          {allLoading ? (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          ) : (
            <TicketCheck className="h-4 w-4 text-muted-foreground" />
          )}
          <CardTitle className="text-lg">Recent Activity</CardTitle>
        </div>
        <CardDescription>Latest tickets, team changes, and device additions</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Recent Tickets */}
        <div>
          <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <TicketCheck className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
            Recent Tickets
          </h3>
          <RecentTicketsSection tickets={tickets} isLoading={ticketsLoading} />
        </div>

        <div className="border-t" />

        {/* Recent Teams */}
        <div>
          <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <Users className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
            Recent Teams
          </h3>
          <RecentTeamsSection teams={teams} isLoading={teamsLoading} />
        </div>

        <div className="border-t" />

        {/* Recent Devices */}
        <div>
          <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
            <Laptop className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
            Recent Devices
          </h3>
          <RecentDevicesSection devices={devices} isLoading={devicesLoading} />
        </div>
      </CardContent>
    </Card>
  )
}
