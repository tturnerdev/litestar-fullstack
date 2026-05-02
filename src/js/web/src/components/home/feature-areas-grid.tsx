import { useQuery } from "@tanstack/react-query"
import { Link } from "@tanstack/react-router"
import { Cable, Calendar, ChevronRight, FileText, Headset, type LucideIcon, MapPin, Monitor, Phone, Tag } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useConnections } from "@/lib/api/hooks/connections"
import { useDevices } from "@/lib/api/hooks/devices"
import { useFaxNumbers } from "@/lib/api/hooks/fax"
import { useSchedules } from "@/lib/api/hooks/schedules"
import { useTickets } from "@/lib/api/hooks/support"
import { usePhoneNumbers } from "@/lib/api/hooks/voice"
import { listTags } from "@/lib/generated/api"

interface FeatureArea {
  key: string
  label: string
  description: string
  icon: LucideIcon
  to: string
  iconBg: string
  iconBgHover: string
  iconText: string
  accentBorder: string
}

const featureAreas: FeatureArea[] = [
  {
    key: "devices",
    label: "Devices",
    description: "Phones, computers & hardware",
    icon: Monitor,
    to: "/devices",
    iconBg: "bg-blue-500/10",
    iconBgHover: "group-hover:bg-blue-500/20",
    iconText: "text-blue-600 dark:text-blue-400",
    accentBorder: "group-hover:border-b-blue-500",
  },
  {
    key: "voice",
    label: "Voice",
    description: "Phone numbers & extensions",
    icon: Phone,
    to: "/voice/phone-numbers",
    iconBg: "bg-green-500/10",
    iconBgHover: "group-hover:bg-green-500/20",
    iconText: "text-green-600 dark:text-green-400",
    accentBorder: "group-hover:border-b-green-500",
  },
  {
    key: "fax",
    label: "Fax",
    description: "Fax numbers & messages",
    icon: FileText,
    to: "/fax/numbers",
    iconBg: "bg-amber-500/10",
    iconBgHover: "group-hover:bg-amber-500/20",
    iconText: "text-amber-600 dark:text-amber-400",
    accentBorder: "group-hover:border-b-amber-500",
  },
  {
    key: "support",
    label: "Support",
    description: "Help tickets & requests",
    icon: Headset,
    to: "/support",
    iconBg: "bg-violet-500/10",
    iconBgHover: "group-hover:bg-violet-500/20",
    iconText: "text-violet-600 dark:text-violet-400",
    accentBorder: "group-hover:border-b-violet-500",
  },
  {
    key: "connections",
    label: "Connections",
    description: "External service integrations",
    icon: Cable,
    to: "/connections",
    iconBg: "bg-cyan-500/10",
    iconBgHover: "group-hover:bg-cyan-500/20",
    iconText: "text-cyan-600 dark:text-cyan-400",
    accentBorder: "group-hover:border-b-cyan-500",
  },
  {
    key: "schedules",
    label: "Schedules",
    description: "Business hours & time rules",
    icon: Calendar,
    to: "/schedules",
    iconBg: "bg-teal-500/10",
    iconBgHover: "group-hover:bg-teal-500/20",
    iconText: "text-teal-600 dark:text-teal-400",
    accentBorder: "group-hover:border-b-teal-500",
  },
  {
    key: "locations",
    label: "Locations",
    description: "Office sites & addresses",
    icon: MapPin,
    to: "/locations",
    iconBg: "bg-pink-500/10",
    iconBgHover: "group-hover:bg-pink-500/20",
    iconText: "text-pink-600 dark:text-pink-400",
    accentBorder: "group-hover:border-b-pink-500",
  },
  {
    key: "tags",
    label: "Tags",
    description: "Organize & categorize resources",
    icon: Tag,
    to: "/tags",
    iconBg: "bg-emerald-500/10",
    iconBgHover: "group-hover:bg-emerald-500/20",
    iconText: "text-emerald-600 dark:text-emerald-400",
    accentBorder: "group-hover:border-b-emerald-500",
  },
]

function useFeatureAreaCounts() {
  const connections = useConnections({ page: 1, pageSize: 1 })
  const devices = useDevices({ page: 1, pageSize: 1 })
  const phoneNumbers = usePhoneNumbers(1, 1)
  const faxNumbers = useFaxNumbers(1, 1)
  const tickets = useTickets(1, 1)
  const schedules = useSchedules({ page: 1, pageSize: 1 })
  const tags = useQuery({
    queryKey: ["home", "feature-tags-count"],
    queryFn: async () => {
      const response = await listTags({ query: { currentPage: 1, pageSize: 1 } })
      return response.data as { total?: number } | undefined
    },
  })

  return {
    connections: { total: connections.data?.total, isLoading: connections.isLoading },
    devices: { total: devices.data?.total, isLoading: devices.isLoading },
    voice: { total: phoneNumbers.data?.total, isLoading: phoneNumbers.isLoading },
    fax: { total: faxNumbers.data?.total, isLoading: faxNumbers.isLoading },
    support: { total: tickets.data?.total, isLoading: tickets.isLoading },
    schedules: { total: schedules.data?.total, isLoading: schedules.isLoading },
    locations: { total: undefined, isLoading: false },
    tags: { total: tags.data?.total, isLoading: tags.isLoading },
  } as Record<string, { total: number | undefined; isLoading: boolean }>
}

export function FeatureAreasGrid() {
  const counts = useFeatureAreaCounts()

  return (
    <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
      {featureAreas.map((area, index) => {
        const count = counts[area.key]
        return (
          <Link key={area.key} to={area.to}>
            <div
              className={`animate-in fade-in slide-in-from-bottom-2 fill-mode-both transition-transform duration-200 hover:scale-[1.02] rounded-lg border-b-2 border-b-transparent ${area.accentBorder}`}
              style={{ animationDelay: `${index * 60}ms` }}
            >
              <Card className="group cursor-pointer border-border/40 transition-all hover:border-border hover:shadow-sm">
                <CardContent className="flex items-center gap-4 p-4">
                  <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg transition-colors ${area.iconBg} ${area.iconBgHover} ${area.iconText}`}>
                    <area.icon className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold">{area.label}</p>
                      {count?.isLoading ? (
                        <Skeleton className="h-4 w-6 animate-pulse rounded" />
                      ) : count?.total != null ? (
                        count.total === 0 ? (
                          <span className="flex items-center gap-1 rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground/50 animate-in fade-in duration-500">
                            0 <span className="text-primary/60">Set up</span>
                          </span>
                        ) : (
                          <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground animate-in fade-in duration-500">{count.total}</span>
                        )
                      ) : null}
                    </div>
                    <p className="text-xs text-muted-foreground">{area.description}</p>
                  </div>
                  <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground/40 transition-transform group-hover:translate-x-0.5 group-hover:text-foreground" />
                </CardContent>
              </Card>
            </div>
          </Link>
        )
      })}
    </div>
  )
}
