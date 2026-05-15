import type { LucideIcon } from "lucide-react"
import {
  Clock,
  GitBranch,
  Headset,
  Inbox,
  LifeBuoy,
  List,
  Mail,
  MailPlus,
  MapPin,
  Monitor,
  Phone,
  PhoneForwarded,
  Printer,
  ShieldAlert,
  TicketCheck,
  Users,
  Voicemail,
} from "lucide-react"
import type { FeatureArea, TeamRolePermission, TeamRolePermissionEntry, TeamRoles } from "@/lib/generated/api"

export interface FeatureAreaNode {
  key: FeatureArea
  label: string
  icon: LucideIcon
  children?: { key: FeatureArea; label: string; icon: LucideIcon }[]
}

export const FEATURE_AREAS: readonly FeatureAreaNode[] = [
  { key: "DEVICES", label: "Devices", icon: Monitor },
  {
    key: "VOICE",
    label: "Voice",
    icon: Phone,
    children: [
      { key: "VOICE_PHONE_NUMBERS", label: "Phone Numbers", icon: Phone },
      { key: "VOICE_EXTENSIONS", label: "Extensions", icon: PhoneForwarded },
      { key: "VOICE_VOICEMAIL", label: "Voicemail", icon: Voicemail },
      { key: "VOICE_VOICEMAIL_BOXES", label: "Voicemail Boxes", icon: Inbox },
    ],
  },
  {
    key: "FAX",
    label: "Fax",
    icon: Printer,
    children: [
      { key: "FAX_NUMBERS", label: "Fax Numbers", icon: Printer },
      { key: "FAX_MESSAGES", label: "Fax Messages", icon: Mail },
      { key: "FAX_EMAIL_ROUTES", label: "Email Routes", icon: MailPlus },
    ],
  },
  {
    key: "SUPPORT",
    label: "Support",
    icon: LifeBuoy,
    children: [{ key: "SUPPORT_TICKETS", label: "Tickets", icon: TicketCheck }],
  },
  {
    key: "CALL_ROUTING",
    label: "Call Routing",
    icon: GitBranch,
    children: [
      { key: "CALL_ROUTING_QUEUES", label: "Call Queues", icon: Headset },
      { key: "CALL_ROUTING_RING_GROUPS", label: "Ring Groups", icon: Users },
      { key: "CALL_ROUTING_IVR_MENUS", label: "IVR Menus", icon: List },
      { key: "CALL_ROUTING_TIME_CONDITIONS", label: "Time Conditions", icon: Clock },
    ],
  },
  { key: "E911", label: "E911", icon: ShieldAlert },
  { key: "LOCATIONS", label: "Locations", icon: MapPin },
  { key: "SCHEDULES", label: "Schedules", icon: Clock },
  { key: "TEAMS", label: "Teams", icon: Users },
]

function allFeatureKeys(): FeatureArea[] {
  const keys: FeatureArea[] = []
  for (const area of FEATURE_AREAS) {
    keys.push(area.key)
    if (area.children) {
      for (const child of area.children) keys.push(child.key)
    }
  }
  return keys
}

export const ALL_FEATURE_KEYS = allFeatureKeys()

export const ROLES: TeamRoles[] = ["ADMIN", "MEMBER"]

export type PermissionMatrix = Record<string, Record<string, { canView: boolean; canEdit: boolean }>>

export function buildDefaultPermissions(): PermissionMatrix {
  const result: PermissionMatrix = {}
  for (const role of ROLES) {
    result[role] = {}
    for (const key of ALL_FEATURE_KEYS) {
      if (role === "ADMIN") {
        result[role][key] = { canView: true, canEdit: true }
      } else {
        result[role][key] = { canView: true, canEdit: false }
      }
    }
  }
  return result
}

export function mergeServerPermissions(rows: TeamRolePermission[]): PermissionMatrix {
  const matrix = buildDefaultPermissions()
  for (const row of rows) {
    if (matrix[row.role] && matrix[row.role][row.featureArea]) {
      matrix[row.role][row.featureArea] = {
        canView: row.canView,
        canEdit: row.canEdit,
      }
    }
  }
  return matrix
}

export function matrixToEntries(matrix: PermissionMatrix): TeamRolePermissionEntry[] {
  const entries: TeamRolePermissionEntry[] = []
  for (const role of ROLES) {
    for (const key of ALL_FEATURE_KEYS) {
      const perm = matrix[role]?.[key]
      if (perm) {
        entries.push({
          role: role as TeamRoles,
          featureArea: key,
          canView: perm.canView,
          canEdit: perm.canEdit,
        })
      }
    }
  }
  return entries
}

export function getParentArea(area: FeatureArea): FeatureArea | null {
  for (const node of FEATURE_AREAS) {
    if (node.children?.some((c) => c.key === area)) {
      return node.key
    }
  }
  return null
}
