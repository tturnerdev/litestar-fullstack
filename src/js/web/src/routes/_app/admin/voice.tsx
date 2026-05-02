import { createFileRoute, Link, useNavigate } from "@tanstack/react-router"
import { AlertCircle, ArrowRight, Download, Hash, Phone, PhoneOff, Search, Signal, X } from "lucide-react"
import { useCallback, useState } from "react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { DataFreshness } from "@/components/ui/data-freshness"
import { EmptyState } from "@/components/ui/empty-state"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SectionErrorBoundary } from "@/components/ui/section-error-boundary"
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useAdminExtensions, useAdminPhoneNumbers, useAdminVoiceStats } from "@/lib/api/hooks/admin"
import { type CsvHeader, exportToCsv } from "@/lib/csv-export"
import type { AdminExtensionSummary, AdminPhoneNumberSummary } from "@/lib/generated/api"
import { cn } from "@/lib/utils"

export const Route = createFileRoute("/_app/admin/voice")({
  component: AdminVoicePage,
})

const PAGE_SIZE = 25

const phoneNumberCsvHeaders: CsvHeader<AdminPhoneNumberSummary>[] = [
  { label: "Number", accessor: (p) => p.number },
  { label: "Label", accessor: (p) => p.label ?? "" },
  { label: "Type", accessor: (p) => p.numberType },
  { label: "Active", accessor: (p) => (p.isActive ? "Yes" : "No") },
  { label: "Owner", accessor: (p) => p.ownerEmail ?? "" },
  { label: "Team", accessor: (p) => p.teamName ?? "" },
  { label: "Created At", accessor: (p) => p.createdAt },
]

const extensionCsvHeaders: CsvHeader<AdminExtensionSummary>[] = [
  { label: "Extension #", accessor: (e) => e.extensionNumber },
  { label: "Display Name", accessor: (e) => e.displayName },
  { label: "Active", accessor: (e) => (e.isActive ? "Yes" : "No") },
  { label: "Owner", accessor: (e) => e.ownerEmail ?? "" },
  { label: "Phone Number", accessor: (e) => e.phoneNumber ?? "" },
  { label: "Created At", accessor: (e) => e.createdAt },
]

const statConfig = [
  {
    key: "totalPhoneNumbers" as const,
    label: "Phone Numbers",
    subtitle: "All registered numbers",
    icon: Phone,
    color: "text-blue-600 dark:text-blue-400",
    bg: "bg-blue-500/10",
    hoverBg: "group-hover:bg-blue-500",
    to: "/voice/phone-numbers" as const,
  },
  {
    key: "activePhoneNumbers" as const,
    label: "Active Numbers",
    subtitle: "Currently in service",
    icon: Signal,
    color: "text-emerald-600 dark:text-emerald-400",
    bg: "bg-emerald-500/10",
    hoverBg: "group-hover:bg-emerald-500",
    to: "/voice/phone-numbers" as const,
  },
  {
    key: "totalExtensions" as const,
    label: "Extensions",
    subtitle: "All configured extensions",
    icon: Hash,
    color: "text-violet-600 dark:text-violet-400",
    bg: "bg-violet-500/10",
    hoverBg: "group-hover:bg-violet-500",
    to: "/voice/extensions" as const,
  },
  {
    key: "activeDnd" as const,
    label: "Active DND",
    subtitle: "Do not disturb enabled",
    icon: PhoneOff,
    color: "text-amber-600 dark:text-amber-400",
    bg: "bg-amber-500/10",
    hoverBg: "group-hover:bg-amber-500",
    to: "/voice/extensions" as const,
  },
]

function StatsCardSkeleton() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-9 w-9 rounded-lg" />
      </CardHeader>
      <CardContent>
        <Skeleton className="h-8 w-16" />
        <Skeleton className="mt-2 h-3 w-32" />
      </CardContent>
    </Card>
  )
}

function AdminVoicePage() {
  useDocumentTitle("Admin Voice")
  const navigate = useNavigate()
  const [phoneNumberPage, setPhoneNumberPage] = useState(1)
  const [phoneSearch, setPhoneSearch] = useState("")

  const { data: stats, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useAdminVoiceStats()
  const {
    data: phoneData,
    isLoading: phonesLoading,
    isError: phonesError,
    refetch: refetchPhones,
    dataUpdatedAt,
    isRefetching,
  } = useAdminPhoneNumbers(phoneNumberPage, PAGE_SIZE, phoneSearch || undefined)
  const { data: extensions, isLoading: extensionsLoading, isError: extensionsError, refetch: refetchExtensions } = useAdminExtensions()

  const handleRefreshAll = useCallback(() => {
    refetchStats()
    refetchPhones()
    refetchExtensions()
  }, [refetchStats, refetchPhones, refetchExtensions])

  const phoneNumbers = phoneData?.items ?? []
  const phoneTotal = phoneData?.total ?? 0
  const phoneTotalPages = Math.max(1, Math.ceil(phoneTotal / PAGE_SIZE))

  const typedExtensions = (Array.isArray(extensions) ? extensions : []) as AdminExtensionSummary[]
  const recentExtensions = typedExtensions.slice(0, 8)

  const handleExportPhoneNumbers = useCallback(() => {
    if (!phoneNumbers.length) return
    exportToCsv("admin-phone-numbers", phoneNumberCsvHeaders, phoneNumbers)
  }, [phoneNumbers])

  const handleExportExtensions = useCallback(() => {
    if (!typedExtensions.length) return
    exportToCsv("admin-extensions", extensionCsvHeaders, typedExtensions)
  }, [typedExtensions])

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Voice"
        description="Manage phone numbers and extensions across the organization."
        breadcrumbs={<AdminBreadcrumbs />}
        actions={<DataFreshness dataUpdatedAt={dataUpdatedAt} onRefresh={handleRefreshAll} isRefreshing={isRefetching} />}
      />
      <AdminNav />

      {/* Stat cards */}
      <PageSection>
        <SectionErrorBoundary name="Voice Statistics">
          {statsLoading ? (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {Array.from({ length: 4 }).map((_, i) => (
                // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
                <StatsCardSkeleton key={`voice-stat-skeleton-${i}`} />
              ))}
            </div>
          ) : statsError ? (
            <EmptyState
              icon={AlertCircle}
              title="Unable to load voice statistics"
              description="Something went wrong. Please try again."
              action={
                <Button variant="outline" size="sm" onClick={() => refetchStats()}>
                  Try again
                </Button>
              }
            />
          ) : (
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {statConfig.map((stat) => {
                const Icon = stat.icon
                const value = stats?.[stat.key] ?? 0
                return (
                  <Link key={stat.key} to={stat.to} className="group">
                    <Card className="transition-all duration-200 group-hover:shadow-md group-hover:border-primary/30 group-hover:-translate-y-0.5">
                      <CardHeader className="flex flex-row items-center justify-between pb-2">
                        <CardTitle className="text-sm font-medium text-muted-foreground">{stat.label}</CardTitle>
                        <div
                          className={`flex h-9 w-9 items-center justify-center rounded-lg ${stat.bg} ${stat.color} transition-colors ${stat.hoverBg} group-hover:text-primary-foreground`}
                        >
                          <Icon className="h-4 w-4" />
                        </div>
                      </CardHeader>
                      <CardContent>
                        <span className="text-3xl font-semibold tracking-tight">{value}</span>
                        <p className="mt-1.5 text-xs text-muted-foreground">{stat.subtitle}</p>
                      </CardContent>
                    </Card>
                  </Link>
                )
              })}
            </div>
          )}
        </SectionErrorBoundary>
      </PageSection>

      {/* Phone numbers */}
      <PageSection delay={0.1}>
        <SectionErrorBoundary name="Phone Numbers">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10">
                    <Phone className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <CardTitle>Phone Numbers</CardTitle>
                    <CardDescription>
                      {phoneTotal} number{phoneTotal !== 1 ? "s" : ""} total
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="relative max-w-sm">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Search numbers..."
                      value={phoneSearch}
                      onChange={(e) => {
                        setPhoneSearch(e.target.value)
                        setPhoneNumberPage(1)
                      }}
                      className="pl-9 pr-8"
                    />
                    {phoneSearch && (
                      <button
                        type="button"
                        onClick={() => {
                          setPhoneSearch("")
                          setPhoneNumberPage(1)
                        }}
                        className="absolute right-2 top-1/2 -translate-y-1/2 rounded-sm p-0.5 text-muted-foreground hover:text-foreground"
                      >
                        <X className="h-3.5 w-3.5" />
                        <span className="sr-only">Clear search</span>
                      </button>
                    )}
                  </div>
                  <Button variant="outline" size="sm" onClick={handleExportPhoneNumbers} disabled={!phoneNumbers.length} className="gap-1.5">
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </Button>
                  <Link to="/voice/phone-numbers">
                    <Button variant="outline" size="sm" className="gap-1.5">
                      Manage
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Button>
                  </Link>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {phonesLoading ? (
                <SkeletonTable rows={5} />
              ) : phonesError ? (
                <EmptyState
                  icon={AlertCircle}
                  title="Unable to load phone numbers"
                  description="Something went wrong. Please try again."
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetchPhones()}>
                      Try again
                    </Button>
                  }
                />
              ) : phoneNumbers.length === 0 ? (
                <EmptyState
                  icon={Search}
                  variant="no-results"
                  title="No phone numbers found"
                  description="No phone numbers match your search. Try a different search term."
                  action={
                    <Button variant="outline" size="sm" onClick={() => setPhoneSearch("")}>
                      Clear search
                    </Button>
                  }
                />
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <Table aria-label="Phone numbers">
                      <TableHeader>
                        <TableRow>
                          <TableHead>Number</TableHead>
                          <TableHead>Label</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Team</TableHead>
                          <TableHead>Owner</TableHead>
                          <TableHead>Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {phoneNumbers.map((pn, index) => (
                          <TableRow key={pn.id} className={cn("hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}>
                            <TableCell className="font-mono font-medium">{pn.number}</TableCell>
                            <TableCell className="text-muted-foreground">{pn.label ?? "—"}</TableCell>
                            <TableCell className="text-muted-foreground capitalize">{pn.numberType}</TableCell>
                            <TableCell className="text-muted-foreground">{pn.teamName ?? "—"}</TableCell>
                            <TableCell className="text-muted-foreground">{pn.ownerEmail ?? "Unassigned"}</TableCell>
                            <TableCell>
                              <Badge variant={pn.isActive ? "default" : "secondary"} className="gap-1.5">
                                <span className={cn("h-1.5 w-1.5 rounded-full", pn.isActive ? "bg-emerald-500" : "bg-gray-400")} />
                                {pn.isActive ? "Active" : "Inactive"}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {phoneTotalPages > 1 && (
                    <div className="flex items-center justify-between">
                      <p className="text-xs text-muted-foreground">
                        Page {phoneNumberPage} of {phoneTotalPages} ({phoneTotal} total)
                      </p>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" onClick={() => setPhoneNumberPage((p) => Math.max(1, p - 1))} disabled={phoneNumberPage <= 1}>
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setPhoneNumberPage((p) => Math.min(phoneTotalPages, p + 1))}
                          disabled={phoneNumberPage >= phoneTotalPages}
                        >
                          Next
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>

      {/* Extensions */}
      <PageSection delay={0.2}>
        <SectionErrorBoundary name="Extensions">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-violet-500/10">
                    <Hash className="h-4 w-4 text-violet-600 dark:text-violet-400" />
                  </div>
                  <div>
                    <CardTitle>Extensions</CardTitle>
                    <CardDescription>
                      {typedExtensions.length} extension{typedExtensions.length !== 1 ? "s" : ""} configured
                    </CardDescription>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Button variant="outline" size="sm" onClick={handleExportExtensions} disabled={!typedExtensions.length} className="gap-1.5">
                    <Download className="h-3.5 w-3.5" />
                    Export
                  </Button>
                  <Link to="/voice/extensions">
                    <Button variant="outline" size="sm" className="gap-1.5">
                      View all
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Button>
                  </Link>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {extensionsLoading ? (
                <SkeletonTable rows={5} />
              ) : extensionsError ? (
                <EmptyState
                  icon={AlertCircle}
                  title="Unable to load extensions"
                  description="Something went wrong. Please try again."
                  action={
                    <Button variant="outline" size="sm" onClick={() => refetchExtensions()}>
                      Try again
                    </Button>
                  }
                />
              ) : recentExtensions.length === 0 ? (
                <EmptyState icon={Hash} title="No extensions found" description="Extensions will appear here once configured." />
              ) : (
                <div className="overflow-x-auto">
                  <Table aria-label="Extensions">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Extension</TableHead>
                        <TableHead>Display Name</TableHead>
                        <TableHead>Owner</TableHead>
                        <TableHead>Phone Number</TableHead>
                        <TableHead>Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {recentExtensions.map((ext, index) => (
                        <TableRow
                          key={ext.id}
                          className={cn("cursor-pointer hover:bg-muted/50 transition-colors", index % 2 === 1 && "bg-muted/20")}
                          onClick={() => navigate({ to: "/voice/extensions/$extensionId", params: { extensionId: ext.id } })}
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") navigate({ to: "/voice/extensions/$extensionId", params: { extensionId: ext.id } })
                          }}
                        >
                          <TableCell className="font-mono font-medium">{ext.extensionNumber}</TableCell>
                          <TableCell className="text-muted-foreground">{ext.displayName}</TableCell>
                          <TableCell className="text-muted-foreground">{ext.ownerEmail ?? "—"}</TableCell>
                          <TableCell className="font-mono text-muted-foreground">{ext.phoneNumber ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant={ext.isActive ? "default" : "secondary"} className="gap-1.5">
                              <span className={cn("h-1.5 w-1.5 rounded-full", ext.isActive ? "bg-emerald-500" : "bg-gray-400")} />
                              {ext.isActive ? "Active" : "Inactive"}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </SectionErrorBoundary>
      </PageSection>
    </PageContainer>
  )
}
