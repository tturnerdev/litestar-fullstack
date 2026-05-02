import { createFileRoute, useBlocker } from "@tanstack/react-router"
import { Building2, CheckCircle2, Circle, Copy, Globe, Hash, Link2, Loader2, Mail, MapPin, MonitorSmartphone, MoreHorizontal, Pencil, Save, Sparkles, TicketCheck, Users, UsersRound, X } from "lucide-react"
import { useCallback, useEffect, useMemo, useState } from "react"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { DataFreshness } from "@/components/ui/data-freshness"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { CopyButton } from "@/components/ui/copy-button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import { toast } from "sonner"
import { OrganizationQuickLinks } from "@/components/organization/organization-quick-links"
import { OrganizationStats } from "@/components/organization/organization-stats"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAuthStore } from "@/lib/auth"
import { useOrganization, useOrganizationStats, useUpdateOrganization } from "@/lib/api/hooks/organization"
import type { DashboardStats, Organization } from "@/lib/generated/api/types.gen"

export const Route = createFileRoute("/_app/organization/")({
  component: OrganizationSettingsPage,
})

const TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "America/Anchorage",
  "Pacific/Honolulu",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Tokyo",
  "Asia/Shanghai",
  "Asia/Kolkata",
  "Australia/Sydney",
]

const LANGUAGES = [
  { value: "en", label: "English" },
  { value: "es", label: "Spanish" },
  { value: "fr", label: "French" },
  { value: "de", label: "German" },
  { value: "ja", label: "Japanese" },
  { value: "zh", label: "Chinese" },
  { value: "pt", label: "Portuguese" },
]

// ---------------------------------------------------------------------------
// Organization Overview (completeness + quick stats + setup checklist)
// ---------------------------------------------------------------------------

interface CompletionStep {
  label: string
  completed: boolean
}

function useOrgCompletionSteps(org: Organization | undefined, stats: DashboardStats | undefined): CompletionStep[] {
  return useMemo(() => {
    if (!org) return []
    return [
      { label: "Organization name set", completed: !!org.name && org.name.trim() !== "" },
      { label: "Address configured", completed: !!(org.addressLine1 && org.city && org.state) },
      { label: "Timezone set", completed: !!org.timezone && org.timezone !== "UTC" },
      { label: "Logo uploaded", completed: !!org.logoUrl },
      { label: "At least one team created", completed: (stats?.totalTeams ?? 0) > 0 },
    ]
  }, [org, stats])
}

function OrganizationOverview({ org, stats }: { org: Organization; stats: DashboardStats | undefined }) {
  const steps = useOrgCompletionSteps(org, stats)
  const completedCount = steps.filter((s) => s.completed).length
  const totalSteps = steps.length
  const percentage = totalSteps > 0 ? Math.round((completedCount / totalSteps) * 100) : 0

  const quickStats = [
    {
      label: "Total Users",
      value: stats?.totalUsers ?? 0,
      icon: Users,
      color: "text-blue-600 dark:text-blue-400",
      bgColor: "bg-blue-500/10",
    },
    {
      label: "Total Teams",
      value: stats?.totalTeams ?? 0,
      icon: UsersRound,
      color: "text-emerald-600 dark:text-emerald-400",
      bgColor: "bg-emerald-500/10",
    },
    {
      label: "Devices",
      value: stats?.totalDevices ?? 0,
      icon: MonitorSmartphone,
      color: "text-cyan-600 dark:text-cyan-400",
      bgColor: "bg-cyan-500/10",
    },
    {
      label: "Open Tickets",
      value: stats?.openTickets ?? 0,
      icon: TicketCheck,
      color: "text-rose-600 dark:text-rose-400",
      bgColor: "bg-rose-500/10",
    },
  ]

  return (
    <PageSection>
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Building2 className="h-5 w-5 text-muted-foreground" />
            <div>
              <CardTitle className="text-lg">Organization Overview</CardTitle>
              <CardDescription>Setup progress and platform summary</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Completeness indicator */}
          {percentage === 100 ? (
            <div className="flex items-center gap-3 rounded-lg border border-green-200 bg-green-50/50 px-4 py-3 dark:border-green-900 dark:bg-green-950/20">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50">
                <Sparkles className="h-5 w-5 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-green-800 dark:text-green-300">Setup complete</p>
                <p className="text-xs text-green-600 dark:text-green-400">Your organization is fully configured.</p>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">Setup completeness</span>
                <span className="text-muted-foreground">{percentage}% &mdash; {totalSteps - completedCount} {totalSteps - completedCount === 1 ? "item" : "items"} remaining</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-500"
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          )}

          {/* Quick stats row */}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {quickStats.map((stat) => (
              <div key={stat.label} className="flex items-center gap-3 rounded-lg border px-4 py-3">
                <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${stat.bgColor}`}>
                  <stat.icon className={`h-4 w-4 ${stat.color}`} />
                </div>
                <div>
                  <p className="text-2xl font-semibold tabular-nums">{stat.value.toLocaleString()}</p>
                  <p className="text-xs text-muted-foreground">{stat.label}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Setup checklist */}
          <div className="space-y-2">
            <p className="text-sm font-medium">Setup checklist</p>
            <ul className="grid gap-1.5 sm:grid-cols-2">
              {steps.map((step) => (
                <li key={step.label} className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm">
                  {step.completed ? (
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-green-600 dark:text-green-400" />
                  ) : (
                    <Circle className="h-4 w-4 shrink-0 text-muted-foreground/50" />
                  )}
                  <span className={step.completed ? "text-foreground" : "text-muted-foreground"}>{step.label}</span>
                </li>
              ))}
            </ul>
          </div>
        </CardContent>
      </Card>
    </PageSection>
  )
}

interface OrgFormData {
  name: string
  description: string
  logoUrl: string
  website: string
  email: string
  phone: string
  addressLine1: string
  addressLine2: string
  city: string
  state: string
  postalCode: string
  country: string
  timezone: string
  defaultLanguage: string
}

function OrganizationSettingsPage() {
  useDocumentTitle("Organization")
  const user = useAuthStore((s) => s.user)
  const isSuperuser = user?.isSuperuser ?? false
  const { data: org, isLoading, dataUpdatedAt, refetch: refetchOrg } = useOrganization()
  const { data: stats } = useOrganizationStats()
  const updateOrg = useUpdateOrganization()
  const [isRefreshingOrg, setIsRefreshingOrg] = useState(false)

  const handleRefreshOrg = useCallback(async () => {
    setIsRefreshingOrg(true)
    await refetchOrg()
    setIsRefreshingOrg(false)
  }, [refetchOrg])
  const [isEditing, setIsEditing] = useState(false)
  const [formData, setFormData] = useState<OrgFormData>({
    name: "",
    description: "",
    logoUrl: "",
    website: "",
    email: "",
    phone: "",
    addressLine1: "",
    addressLine2: "",
    city: "",
    state: "",
    postalCode: "",
    country: "",
    timezone: "UTC",
    defaultLanguage: "en",
  })

  const syncFormFromOrg = useCallback(() => {
    if (org) {
      setFormData({
        name: org.name ?? "",
        description: org.description ?? "",
        logoUrl: org.logoUrl ?? "",
        website: org.website ?? "",
        email: org.email ?? "",
        phone: org.phone ?? "",
        addressLine1: org.addressLine1 ?? "",
        addressLine2: org.addressLine2 ?? "",
        city: org.city ?? "",
        state: org.state ?? "",
        postalCode: org.postalCode ?? "",
        country: org.country ?? "",
        timezone: org.timezone ?? "UTC",
        defaultLanguage: org.defaultLanguage ?? "en",
      })
    }
  }, [org])

  useEffect(() => {
    syncFormFromOrg()
  }, [syncFormFromOrg])

  // Track whether the form has been modified relative to original data
  const formDirty = useMemo(() => {
    if (!isEditing || !org) return false
    return (
      formData.name !== (org.name ?? "") ||
      formData.description !== (org.description ?? "") ||
      formData.logoUrl !== (org.logoUrl ?? "") ||
      formData.website !== (org.website ?? "") ||
      formData.email !== (org.email ?? "") ||
      formData.phone !== (org.phone ?? "") ||
      formData.addressLine1 !== (org.addressLine1 ?? "") ||
      formData.addressLine2 !== (org.addressLine2 ?? "") ||
      formData.city !== (org.city ?? "") ||
      formData.state !== (org.state ?? "") ||
      formData.postalCode !== (org.postalCode ?? "") ||
      formData.country !== (org.country ?? "") ||
      formData.timezone !== (org.timezone ?? "UTC") ||
      formData.defaultLanguage !== (org.defaultLanguage ?? "en")
    )
  }, [isEditing, org, formData])

  // Block navigation when form has unsaved changes
  const blocker = useBlocker({
    shouldBlockFn: () => formDirty,
    withResolver: true,
  })

  const handleSave = async () => {
    const payload: Record<string, unknown> = {}
    if (formData.name !== (org?.name ?? "")) payload.name = formData.name
    if (formData.description !== (org?.description ?? "")) payload.description = formData.description || null
    if (formData.logoUrl !== (org?.logoUrl ?? "")) payload.logoUrl = formData.logoUrl || null
    if (formData.website !== (org?.website ?? "")) payload.website = formData.website || null
    if (formData.email !== (org?.email ?? "")) payload.email = formData.email || null
    if (formData.phone !== (org?.phone ?? "")) payload.phone = formData.phone || null
    if (formData.addressLine1 !== (org?.addressLine1 ?? "")) payload.addressLine1 = formData.addressLine1 || null
    if (formData.addressLine2 !== (org?.addressLine2 ?? "")) payload.addressLine2 = formData.addressLine2 || null
    if (formData.city !== (org?.city ?? "")) payload.city = formData.city || null
    if (formData.state !== (org?.state ?? "")) payload.state = formData.state || null
    if (formData.postalCode !== (org?.postalCode ?? "")) payload.postalCode = formData.postalCode || null
    if (formData.country !== (org?.country ?? "")) payload.country = formData.country || null
    if (formData.timezone !== (org?.timezone ?? "UTC")) payload.timezone = formData.timezone
    if (formData.defaultLanguage !== (org?.defaultLanguage ?? "en")) payload.defaultLanguage = formData.defaultLanguage

    if (Object.keys(payload).length === 0) {
      setIsEditing(false)
      return
    }

    try {
      await updateOrg.mutateAsync(payload)
      toast.success("Organization settings saved")
      setIsEditing(false)
    } catch (err) {
      toast.error("Failed to save organization settings", {
        description: err instanceof Error ? err.message : undefined,
      })
    }
  }

  const handleCancel = () => {
    syncFormFromOrg()
    setIsEditing(false)
  }

  const updateField = (field: keyof OrgFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  if (isLoading) {
    return (
      <PageContainer className="flex-1 space-y-8">
        <PageHeader eyebrow="Settings" title="Organization" description="Loading organization settings..." />
        <PageSection>
          <div className="grid gap-6 lg:grid-cols-2">
            <Skeleton className="h-64 rounded-xl" />
            <Skeleton className="h-64 rounded-xl" />
          </div>
        </PageSection>
      </PageContainer>
    )
  }

  return (
    <>
    <PageContainer className="flex-1 space-y-8">
      <div className="-mx-4 -mt-8 mb-2 rounded-b-xl bg-gradient-to-br from-primary/5 via-primary/3 to-transparent px-4 pb-2 pt-8 md:-mx-6 md:-mt-10 md:px-6 md:pt-10">
        <PageHeader
          eyebrow="Settings"
          title={
            <span className="flex items-center gap-3">
              Organization
              <Badge variant="outline" className="text-xs font-normal text-green-600 border-green-200 bg-green-50 dark:text-green-400 dark:border-green-800 dark:bg-green-950/30">
                Active
              </Badge>
            </span>
          }
          description="View and manage your organization profile, contact information, and preferences."
          actions={
          <div className="flex items-center gap-2">
            <DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={handleRefreshOrg} isRefreshing={isRefreshingOrg} />
            {isSuperuser &&
              (isEditing ? (
                <>
                  <Button size="sm" variant="outline" onClick={handleCancel} disabled={updateOrg.isPending}>
                    <X className="mr-2 h-4 w-4" /> Cancel
                  </Button>
                  <Button size="sm" onClick={handleSave} disabled={updateOrg.isPending}>
                    {updateOrg.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />} {updateOrg.isPending ? "Saving..." : "Save changes"}
                  </Button>
                </>
              ) : (
                <Button size="sm" onClick={() => setIsEditing(true)}>
                  <Pencil className="mr-2 h-4 w-4" /> Edit settings
                </Button>
              ))}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="sm">
                  <MoreHorizontal className="h-4 w-4" />
                  <span className="sr-only">Actions</span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onClick={() => {
                    if (org?.id) {
                      navigator.clipboard.writeText(org.id)
                      toast.success("Organization ID copied")
                    }
                  }}
                  disabled={!org?.id}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  Copy Organization ID
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={() => {
                    if (org?.slug) {
                      navigator.clipboard.writeText(org.slug)
                      toast.success("Organization slug copied")
                    }
                  }}
                  disabled={!org?.slug}
                >
                  <Link2 className="mr-2 h-4 w-4" />
                  Copy Slug
                </DropdownMenuItem>
                {org?.website && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem asChild>
                      <a href={org.website} target="_blank" rel="noopener noreferrer">
                        <Globe className="mr-2 h-4 w-4" />
                        Visit Website
                      </a>
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        }
      />
      </div>

      {!isSuperuser && (
        <PageSection>
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-900 dark:bg-amber-950/30">
            <p className="text-sm text-amber-800 dark:text-amber-200">
              You have read-only access to organization settings. Contact a superuser to make changes.
            </p>
          </div>
        </PageSection>
      )}

      <SectionErrorBoundary name="Organization Overview">
        {org && <OrganizationOverview org={org} stats={stats} />}
      </SectionErrorBoundary>

      <PageSection delay={0.1}>
        <div className="grid gap-6 lg:grid-cols-2">
          {/* General Information */}
          <SectionErrorBoundary name="General Information">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Building2 className="h-5 w-5 text-muted-foreground" />
                <div>
                  <CardTitle className="text-lg">General Information</CardTitle>
                  <CardDescription>Basic details about your organization</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="org-name">Organization name</Label>
                {isEditing ? (
                  <Input id="org-name" value={formData.name} onChange={(e) => updateField("name", e.target.value)} placeholder="Organization name" disabled={updateOrg.isPending} />
                ) : (
                  <p className="text-sm">{org?.name || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-description">Description</Label>
                {isEditing ? (
                  <Textarea id="org-description" value={formData.description} onChange={(e) => updateField("description", e.target.value)} placeholder="A brief description of your organization" rows={3} disabled={updateOrg.isPending} />
                ) : (
                  <p className="text-sm">{org?.description || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <Separator />
              <div className="space-y-2">
                <Label htmlFor="org-logo">Logo URL</Label>
                {isEditing ? (
                  <Input id="org-logo" value={formData.logoUrl} onChange={(e) => updateField("logoUrl", e.target.value)} placeholder="https://example.com/logo.png" type="url" disabled={updateOrg.isPending} />
                ) : (
                  <div className="flex items-center gap-3">
                    {org?.logoUrl ? (
                      <>
                        <img src={org.logoUrl} alt="Organization logo" className="h-10 w-10 rounded-lg border object-cover" onError={(e) => { (e.target as HTMLImageElement).style.display = "none" }} />
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="text-sm text-muted-foreground truncate max-w-xs" title={org.logoUrl}>{org.logoUrl}</span>
                          </TooltipTrigger>
                          <TooltipContent>{org.logoUrl}</TooltipContent>
                        </Tooltip>
                      </>
                    ) : (
                      <span className="text-sm text-muted-foreground italic">Not set</span>
                    )}
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-website">Website</Label>
                {isEditing ? (
                  <Input id="org-website" value={formData.website} onChange={(e) => updateField("website", e.target.value)} placeholder="https://example.com" type="url" disabled={updateOrg.isPending} />
                ) : (
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm">
                      {org?.website ? (
                        <a href={org.website} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          {org.website}
                        </a>
                      ) : (
                        <span className="text-muted-foreground italic">Not set</span>
                      )}
                    </p>
                    {org?.website && <CopyButton value={org.website} label="Website" />}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
          </SectionErrorBoundary>

          {/* Contact Details */}
          <SectionErrorBoundary name="Contact Details">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Mail className="h-5 w-5 text-muted-foreground" />
                <div>
                  <CardTitle className="text-lg">Contact Details</CardTitle>
                  <CardDescription>How to reach your organization</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="org-email">Email</Label>
                {isEditing ? (
                  <Input id="org-email" value={formData.email} onChange={(e) => updateField("email", e.target.value)} placeholder="contact@example.com" type="email" disabled={updateOrg.isPending} />
                ) : (
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm">
                      {org?.email ? (
                        <a href={`mailto:${org.email}`} className="text-primary hover:underline">{org.email}</a>
                      ) : (
                        <span className="text-muted-foreground italic">Not set</span>
                      )}
                    </p>
                    {org?.email && <CopyButton value={org.email} label="Email" />}
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-phone">Phone</Label>
                {isEditing ? (
                  <Input id="org-phone" value={formData.phone} onChange={(e) => updateField("phone", e.target.value)} placeholder="+1 (555) 000-0000" type="tel" disabled={updateOrg.isPending} />
                ) : (
                  <div className="flex items-center gap-1.5">
                    <p className="text-sm">{org?.phone || <span className="text-muted-foreground italic">Not set</span>}</p>
                    {org?.phone && <CopyButton value={org.phone} label="Phone" />}
                  </div>
                )}
              </div>
              <Separator />
              <div className="flex items-center gap-2 text-muted-foreground">
                <MapPin className="h-4 w-4" />
                <span className="text-sm font-medium">Address</span>
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-address1">Address line 1</Label>
                {isEditing ? (
                  <Input id="org-address1" value={formData.addressLine1} onChange={(e) => updateField("addressLine1", e.target.value)} placeholder="123 Main Street" disabled={updateOrg.isPending} />
                ) : (
                  <p className="text-sm">{org?.addressLine1 || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-address2">Address line 2</Label>
                {isEditing ? (
                  <Input id="org-address2" value={formData.addressLine2} onChange={(e) => updateField("addressLine2", e.target.value)} placeholder="Suite 100" disabled={updateOrg.isPending} />
                ) : (
                  <p className="text-sm">{org?.addressLine2 || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="org-city">City</Label>
                  {isEditing ? (
                    <Input id="org-city" value={formData.city} onChange={(e) => updateField("city", e.target.value)} placeholder="City" disabled={updateOrg.isPending} />
                  ) : (
                    <p className="text-sm">{org?.city || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-state">State / Province</Label>
                  {isEditing ? (
                    <Input id="org-state" value={formData.state} onChange={(e) => updateField("state", e.target.value)} placeholder="State" disabled={updateOrg.isPending} />
                  ) : (
                    <p className="text-sm">{org?.state || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="org-postal">Postal code</Label>
                  {isEditing ? (
                    <Input id="org-postal" value={formData.postalCode} onChange={(e) => updateField("postalCode", e.target.value)} placeholder="12345" disabled={updateOrg.isPending} />
                  ) : (
                    <p className="text-sm">{org?.postalCode || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-country">Country</Label>
                  {isEditing ? (
                    <Input id="org-country" value={formData.country} onChange={(e) => updateField("country", e.target.value)} placeholder="Country" disabled={updateOrg.isPending} />
                  ) : (
                    <p className="text-sm">{org?.country || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
          </SectionErrorBoundary>

          {/* Preferences */}
          <SectionErrorBoundary name="Preferences">
          <Card className="lg:col-span-2">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-muted-foreground" />
                <div>
                  <CardTitle className="text-lg">Preferences</CardTitle>
                  <CardDescription>Timezone and language settings</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-6 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="org-timezone">Timezone</Label>
                  {isEditing ? (
                    <Select value={formData.timezone} onValueChange={(val) => updateField("timezone", val)} disabled={updateOrg.isPending}>
                      <SelectTrigger id="org-timezone">
                        <SelectValue placeholder="Select timezone" />
                      </SelectTrigger>
                      <SelectContent>
                        {TIMEZONES.map((tz) => (
                          <SelectItem key={tz} value={tz}>{tz}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">{org?.timezone || "UTC"}</Badge>
                    </div>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-language">Default language</Label>
                  {isEditing ? (
                    <Select value={formData.defaultLanguage} onValueChange={(val) => updateField("defaultLanguage", val)} disabled={updateOrg.isPending}>
                      <SelectTrigger id="org-language">
                        <SelectValue placeholder="Select language" />
                      </SelectTrigger>
                      <SelectContent>
                        {LANGUAGES.map((lang) => (
                          <SelectItem key={lang.value} value={lang.value}>{lang.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">
                        {LANGUAGES.find((l) => l.value === (org?.defaultLanguage || "en"))?.label || org?.defaultLanguage || "English"}
                      </Badge>
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
          </SectionErrorBoundary>
          {/* Metadata */}
          <SectionErrorBoundary name="Organization Details">
          <Card className="lg:col-span-2">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Hash className="h-5 w-5 text-muted-foreground" />
                <div>
                  <CardTitle className="text-lg">Organization Details</CardTitle>
                  <CardDescription>System identifiers and membership overview</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Organization ID</p>
                  <div className="flex items-center gap-1.5">
                    <code className="text-xs font-mono text-foreground bg-muted px-1.5 py-0.5 rounded">{org?.id ? `${org.id.slice(0, 8)}...` : "--"}</code>
                    {org?.id && <CopyButton value={org.id} label="Organization ID" />}
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Slug</p>
                  <p className="text-sm">{org?.slug || "--"}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Total Members</p>
                  <div className="flex items-center gap-1.5">
                    <Users className="h-3.5 w-3.5 text-muted-foreground" />
                    <p className="text-sm font-medium">{stats?.totalUsers?.toLocaleString() ?? "--"}</p>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-xs font-medium text-muted-foreground">Total Teams</p>
                  <div className="flex items-center gap-1.5">
                    <Users className="h-3.5 w-3.5 text-muted-foreground" />
                    <p className="text-sm font-medium">{stats?.totalTeams?.toLocaleString() ?? "--"}</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
          </SectionErrorBoundary>
        </div>
      </PageSection>
      <PageSection>
        <SectionErrorBoundary name="Organization Stats">
          <OrganizationStats />
        </SectionErrorBoundary>
      </PageSection>
      <PageSection>
        <SectionErrorBoundary name="Quick Links">
          <OrganizationQuickLinks />
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>

    {/* -- Unsaved changes dialog ---------------------------------------- */}
    <AlertDialog open={blocker.status === "blocked"} onOpenChange={() => blocker.reset?.()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Unsaved changes</AlertDialogTitle>
          <AlertDialogDescription>
            You have unsaved changes to organization settings. Are you sure you want to leave? Your changes will be lost.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={() => blocker.reset?.()}>Stay on page</AlertDialogCancel>
          <AlertDialogAction onClick={() => blocker.proceed?.()}>Discard changes</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}
