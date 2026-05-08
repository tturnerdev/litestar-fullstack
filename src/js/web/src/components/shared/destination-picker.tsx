import { Link } from "@tanstack/react-router"
import { useMemo, useState } from "react"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useCallQueues, useIvrMenus, useRingGroups } from "@/lib/api/hooks/call-routing"
import { useExtensions } from "@/lib/api/hooks/voice"

// -- Destination Link ---------------------------------------------------------

/** Known destination prefixes and their corresponding route paths + param names. */
const destinationRoutes: Record<string, { to: string; paramKey: string; label: string }> = {
  ext: { to: "/voice/extensions/$extensionId", paramKey: "extensionId", label: "Extension" },
  extension: { to: "/voice/extensions/$extensionId", paramKey: "extensionId", label: "Extension" },
  "ring-group": { to: "/call-routing/ring-groups/$ringGroupId", paramKey: "ringGroupId", label: "Ring Group" },
  ringgroup: { to: "/call-routing/ring-groups/$ringGroupId", paramKey: "ringGroupId", label: "Ring Group" },
  "call-queue": { to: "/call-routing/call-queues/$callQueueId", paramKey: "callQueueId", label: "Call Queue" },
  callqueue: { to: "/call-routing/call-queues/$callQueueId", paramKey: "callQueueId", label: "Call Queue" },
  queue: { to: "/call-routing/call-queues/$callQueueId", paramKey: "callQueueId", label: "Call Queue" },
  ivr: { to: "/call-routing/ivr-menus/$ivrMenuId", paramKey: "ivrMenuId", label: "IVR Menu" },
  "ivr-menu": { to: "/call-routing/ivr-menus/$ivrMenuId", paramKey: "ivrMenuId", label: "IVR Menu" },
  voicemail: { to: "/voicemail/$boxId", paramKey: "boxId", label: "Voicemail" },
  vm: { to: "/voicemail/$boxId", paramKey: "boxId", label: "Voicemail" },
}

/** Render a destination string as a clickable link when possible, plain text otherwise. */
export function DestinationLink({ value, className }: { value: string; className?: string }) {
  const colonIdx = value.indexOf(":")
  if (colonIdx > 0) {
    const prefix = value.slice(0, colonIdx).toLowerCase()
    const id = value.slice(colonIdx + 1)
    const route = destinationRoutes[prefix]
    if (route && id) {
      return (
        <Link
          to={route.to as string}
          params={{ [route.paramKey]: id } as Record<string, string>}
          className={className ?? "text-sm text-primary hover:underline"}
          onClick={(e: React.MouseEvent) => e.stopPropagation()}
        >
          {value}
        </Link>
      )
    }
  }
  return <span className={className ?? "text-sm text-muted-foreground"}>{value}</span>
}

// -- Destination Picker -------------------------------------------------------

/** Destination type identifiers used in the picker UI. */
type DestinationType = "extension" | "ring-group" | "call-queue" | "ivr" | "external" | "voicemail" | ""

/** Map a destination type to the prefix used in destination strings. */
const destinationTypePrefixes: Record<Exclude<DestinationType, "" | "external">, string> = {
  extension: "ext",
  "ring-group": "ring-group",
  "call-queue": "call-queue",
  ivr: "ivr",
  voicemail: "voicemail",
}

/** Parse a raw destination string into its type and value parts. */
function parseDestination(raw: string): { type: DestinationType; value: string } {
  if (!raw) return { type: "", value: "" }
  const colonIdx = raw.indexOf(":")
  if (colonIdx <= 0) return { type: "external", value: raw }
  const prefix = raw.slice(0, colonIdx).toLowerCase()
  const id = raw.slice(colonIdx + 1)
  if (prefix === "ext" || prefix === "extension") return { type: "extension", value: id }
  if (prefix === "ring-group" || prefix === "ringgroup") return { type: "ring-group", value: id }
  if (prefix === "call-queue" || prefix === "callqueue" || prefix === "queue") return { type: "call-queue", value: id }
  if (prefix === "ivr" || prefix === "ivr-menu") return { type: "ivr", value: id }
  if (prefix === "voicemail" || prefix === "vm") return { type: "voicemail", value: id }
  return { type: "external", value: raw }
}

/** Build a destination string from type + value. */
function buildDestination(type: DestinationType, value: string): string {
  if (!type || !value) return ""
  if (type === "external") return value
  const prefix = destinationTypePrefixes[type]
  return `${prefix}:${value}`
}

const destinationTypeLabels: { value: DestinationType; label: string }[] = [
  { value: "extension", label: "Extension" },
  { value: "ring-group", label: "Ring Group" },
  { value: "call-queue", label: "Call Queue" },
  { value: "ivr", label: "IVR Menu" },
  { value: "external", label: "External Number" },
  { value: "voicemail", label: "Voicemail" },
]

export function DestinationPicker({ value, onChange, label, placeholder }: { value: string; onChange: (dest: string) => void; label?: string; placeholder?: string }) {
  const parsed = useMemo(() => parseDestination(value), [value])
  const [destType, setDestType] = useState<DestinationType>(parsed.type)
  const [destValue, setDestValue] = useState(parsed.value)

  // Fetch all entity lists for dropdowns
  const extensionsQuery = useExtensions(1, 200)
  const ringGroupsQuery = useRingGroups({ page: 1, pageSize: 200 })
  const callQueuesQuery = useCallQueues({ page: 1, pageSize: 200 })
  const ivrMenusQuery = useIvrMenus({ page: 1, pageSize: 200 })

  const extensions = extensionsQuery.data?.items ?? []
  const ringGroups = ringGroupsQuery.data?.items ?? []
  const callQueues = callQueuesQuery.data?.items ?? []
  const ivrMenus = ivrMenusQuery.data?.items ?? []

  const handleTypeChange = (newType: string) => {
    const t = newType as DestinationType
    setDestType(t)
    setDestValue("")
    onChange("")
  }

  const handleValueChange = (newValue: string) => {
    setDestValue(newValue)
    onChange(buildDestination(destType, newValue))
  }

  const needsEntityDropdown = destType === "extension" || destType === "ring-group" || destType === "call-queue" || destType === "ivr"

  return (
    <div className="space-y-2">
      {label && <Label>{label}</Label>}
      <div className="grid gap-2 sm:grid-cols-2">
        <Select value={destType} onValueChange={handleTypeChange}>
          <SelectTrigger>
            <SelectValue placeholder="Select type..." />
          </SelectTrigger>
          <SelectContent>
            {destinationTypeLabels.map((dt) => (
              <SelectItem key={dt.value} value={dt.value}>
                {dt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {needsEntityDropdown && destType === "extension" && (
          <Select value={destValue} onValueChange={handleValueChange}>
            <SelectTrigger>
              <SelectValue placeholder={extensionsQuery.isLoading ? "Loading..." : "Select extension..."} />
            </SelectTrigger>
            <SelectContent>
              {extensions.map((ext) => (
                <SelectItem key={ext.id} value={ext.id}>
                  {ext.extensionNumber} - {ext.displayName}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {needsEntityDropdown && destType === "ring-group" && (
          <Select value={destValue} onValueChange={handleValueChange}>
            <SelectTrigger>
              <SelectValue placeholder={ringGroupsQuery.isLoading ? "Loading..." : "Select ring group..."} />
            </SelectTrigger>
            <SelectContent>
              {ringGroups.map((rg) => (
                <SelectItem key={rg.id} value={rg.id}>
                  {rg.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {needsEntityDropdown && destType === "call-queue" && (
          <Select value={destValue} onValueChange={handleValueChange}>
            <SelectTrigger>
              <SelectValue placeholder={callQueuesQuery.isLoading ? "Loading..." : "Select call queue..."} />
            </SelectTrigger>
            <SelectContent>
              {callQueues.map((cq) => (
                <SelectItem key={cq.id} value={cq.id}>
                  {cq.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {needsEntityDropdown && destType === "ivr" && (
          <Select value={destValue} onValueChange={handleValueChange}>
            <SelectTrigger>
              <SelectValue placeholder={ivrMenusQuery.isLoading ? "Loading..." : "Select IVR menu..."} />
            </SelectTrigger>
            <SelectContent>
              {ivrMenus.map((m) => (
                <SelectItem key={m.id} value={m.id}>
                  {m.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {destType === "external" && <Input value={destValue} onChange={(e) => handleValueChange(e.target.value)} placeholder={placeholder ?? "Enter phone number..."} />}

        {destType === "voicemail" && <Input value={destValue} onChange={(e) => handleValueChange(e.target.value)} placeholder="Enter mailbox ID..." />}
      </div>
    </div>
  )
}
