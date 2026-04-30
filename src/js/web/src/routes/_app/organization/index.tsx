import { createFileRoute } from "@tanstack/react-router"
import { Building2, Check, Copy, Globe, Hash, Mail, MapPin, Pencil, Save, Users, X } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
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
import { OrganizationQuickLinks } from "@/components/organization/organization-quick-links"
import { OrganizationStats } from "@/components/organization/organization-stats"
import { useAuthStore } from "@/lib/auth"
import { useOrganization, useOrganizationStats, useUpdateOrganization } from "@/lib/api/hooks/organization"

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

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      toast.success(`${label} copied!`)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error("Failed to copy to clipboard")
    }
  }

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-6 w-6 text-muted-foreground hover:text-foreground"
      onClick={handleCopy}
      title={`Copy ${label.toLowerCase()}`}
      aria-label="Copy to clipboard"
    >
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  )
}

function OrganizationSettingsPage() {
  const user = useAuthStore((s) => s.user)
  const isSuperuser = user?.isSuperuser ?? false
  const { data: org, isLoading } = useOrganization()
  const { data: stats } = useOrganizationStats()
  const updateOrg = useUpdateOrganization()
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

    await updateOrg.mutateAsync(payload)
    setIsEditing(false)
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
          isSuperuser &&
          (isEditing ? (
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={handleCancel} disabled={updateOrg.isPending}>
                <X className="mr-2 h-4 w-4" /> Cancel
              </Button>
              <Button size="sm" onClick={handleSave} disabled={updateOrg.isPending}>
                <Save className="mr-2 h-4 w-4" /> {updateOrg.isPending ? "Saving..." : "Save changes"}
              </Button>
            </div>
          ) : (
            <Button size="sm" onClick={() => setIsEditing(true)}>
              <Pencil className="mr-2 h-4 w-4" /> Edit settings
            </Button>
          ))
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

      <PageSection delay={0.1}>
        <div className="grid gap-6 lg:grid-cols-2">
          {/* General Information */}
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
                  <Input id="org-name" value={formData.name} onChange={(e) => updateField("name", e.target.value)} placeholder="Organization name" />
                ) : (
                  <p className="text-sm">{org?.name || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-description">Description</Label>
                {isEditing ? (
                  <Textarea id="org-description" value={formData.description} onChange={(e) => updateField("description", e.target.value)} placeholder="A brief description of your organization" rows={3} />
                ) : (
                  <p className="text-sm">{org?.description || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <Separator />
              <div className="space-y-2">
                <Label htmlFor="org-logo">Logo URL</Label>
                {isEditing ? (
                  <Input id="org-logo" value={formData.logoUrl} onChange={(e) => updateField("logoUrl", e.target.value)} placeholder="https://example.com/logo.png" type="url" />
                ) : (
                  <div className="flex items-center gap-3">
                    {org?.logoUrl ? (
                      <>
                        <img src={org.logoUrl} alt="Organization logo" className="h-10 w-10 rounded-lg border object-cover" onError={(e) => { (e.target as HTMLImageElement).style.display = "none" }} />
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="text-sm text-muted-foreground truncate max-w-xs">{org.logoUrl}</span>
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
                  <Input id="org-website" value={formData.website} onChange={(e) => updateField("website", e.target.value)} placeholder="https://example.com" type="url" />
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

          {/* Contact Details */}
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
                  <Input id="org-email" value={formData.email} onChange={(e) => updateField("email", e.target.value)} placeholder="contact@example.com" type="email" />
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
                  <Input id="org-phone" value={formData.phone} onChange={(e) => updateField("phone", e.target.value)} placeholder="+1 (555) 000-0000" type="tel" />
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
                  <Input id="org-address1" value={formData.addressLine1} onChange={(e) => updateField("addressLine1", e.target.value)} placeholder="123 Main Street" />
                ) : (
                  <p className="text-sm">{org?.addressLine1 || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="org-address2">Address line 2</Label>
                {isEditing ? (
                  <Input id="org-address2" value={formData.addressLine2} onChange={(e) => updateField("addressLine2", e.target.value)} placeholder="Suite 100" />
                ) : (
                  <p className="text-sm">{org?.addressLine2 || <span className="text-muted-foreground italic">Not set</span>}</p>
                )}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="org-city">City</Label>
                  {isEditing ? (
                    <Input id="org-city" value={formData.city} onChange={(e) => updateField("city", e.target.value)} placeholder="City" />
                  ) : (
                    <p className="text-sm">{org?.city || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-state">State / Province</Label>
                  {isEditing ? (
                    <Input id="org-state" value={formData.state} onChange={(e) => updateField("state", e.target.value)} placeholder="State" />
                  ) : (
                    <p className="text-sm">{org?.state || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="org-postal">Postal code</Label>
                  {isEditing ? (
                    <Input id="org-postal" value={formData.postalCode} onChange={(e) => updateField("postalCode", e.target.value)} placeholder="12345" />
                  ) : (
                    <p className="text-sm">{org?.postalCode || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="org-country">Country</Label>
                  {isEditing ? (
                    <Input id="org-country" value={formData.country} onChange={(e) => updateField("country", e.target.value)} placeholder="Country" />
                  ) : (
                    <p className="text-sm">{org?.country || <span className="text-muted-foreground italic">Not set</span>}</p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Preferences */}
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
                    <Select value={formData.timezone} onValueChange={(val) => updateField("timezone", val)}>
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
                    <Select value={formData.defaultLanguage} onValueChange={(val) => updateField("defaultLanguage", val)}>
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
          {/* Metadata */}
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
        </div>
      </PageSection>
      <PageSection>
        <OrganizationStats />
      </PageSection>
      <PageSection>
        <OrganizationQuickLinks />
      </PageSection>
    </PageContainer>
  )
}
