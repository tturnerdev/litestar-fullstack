import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { Search } from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAdminExtensions, useAdminPhoneNumbers, useAdminVoiceStats } from "@/lib/api/hooks/admin"

export const Route = createFileRoute("/_app/admin/voice")({
  component: AdminVoicePage,
})

const PAGE_SIZE = 25

function AdminVoicePage() {
  const [phoneNumberPage, setPhoneNumberPage] = useState(1)
  const [phoneSearch, setPhoneSearch] = useState("")

  const { data: stats, isLoading: statsLoading } = useAdminVoiceStats()
  const { data: phoneData, isLoading: phonesLoading } = useAdminPhoneNumbers(phoneNumberPage, PAGE_SIZE, phoneSearch || undefined)
  const { data: extensions, isLoading: extensionsLoading } = useAdminExtensions()

  const phoneNumbers = phoneData?.items ?? []
  const phoneTotal = phoneData?.total ?? 0
  const phoneTotalPages = Math.max(1, Math.ceil(phoneTotal / PAGE_SIZE))

  const statCards = [
    { label: "Phone numbers", value: stats?.totalPhoneNumbers ?? 0 },
    { label: "Active numbers", value: stats?.activePhoneNumbers ?? 0 },
    { label: "Extensions", value: stats?.totalExtensions ?? 0 },
    { label: "Active DND", value: stats?.activeDnd ?? 0 },
  ]

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Voice" description="Manage phone numbers and extensions across the organization." breadcrumbs={<AdminBreadcrumbs />} />
      <AdminNav />

      <PageSection>
        {statsLoading ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {statCards.map((item) => (
              <Card key={item.label}>
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">{item.label}</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-semibold">{item.value}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-4">
              <CardTitle>Phone numbers</CardTitle>
              <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Search numbers..."
                  value={phoneSearch}
                  onChange={(e) => {
                    setPhoneSearch(e.target.value)
                    setPhoneNumberPage(1)
                  }}
                  className="pl-9"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
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
                {phonesLoading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : phoneNumbers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-muted-foreground">
                      {phoneSearch ? "No numbers match your search." : "No phone numbers found."}
                    </TableCell>
                  </TableRow>
                ) : (
                  phoneNumbers.map((pn) => (
                    <TableRow key={pn.id}>
                      <TableCell className="font-mono font-medium">{pn.number}</TableCell>
                      <TableCell className="text-muted-foreground">{pn.label ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground capitalize">{pn.numberType}</TableCell>
                      <TableCell className="text-muted-foreground">{pn.teamName ?? "—"}</TableCell>
                      <TableCell className="text-muted-foreground">{pn.ownerEmail ?? "Unassigned"}</TableCell>
                      <TableCell>
                        <Badge variant={pn.isActive ? "default" : "secondary"}>{pn.isActive ? "Active" : "Inactive"}</Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {phoneTotalPages > 1 && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {phoneNumberPage} of {phoneTotalPages} ({phoneTotal} total)
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setPhoneNumberPage((p) => Math.max(1, p - 1))} disabled={phoneNumberPage <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setPhoneNumberPage((p) => Math.min(phoneTotalPages, p + 1))} disabled={phoneNumberPage >= phoneTotalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>

      <PageSection delay={0.2}>
        <Card>
          <CardHeader>
            <CardTitle>Extensions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Extension</TableHead>
                  <TableHead>Display name</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Phone number</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensionsLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      <div className="flex items-center justify-center">
                        <div className="h-5 w-5 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent" />
                      </div>
                    </TableCell>
                  </TableRow>
                ) : !extensions || (extensions as unknown[]).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No extensions found.
                    </TableCell>
                  </TableRow>
                ) : (
                  (extensions as { id: string; extensionNumber: string; displayName: string; ownerEmail: string | null; phoneNumber: string | null; isActive: boolean }[]).map((ext) => (
                    <TableRow key={ext.id}>
                      <TableCell className="font-mono font-medium">{ext.extensionNumber}</TableCell>
                      <TableCell className="text-muted-foreground">{ext.displayName}</TableCell>
                      <TableCell className="text-muted-foreground">{ext.ownerEmail ?? "—"}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">{ext.phoneNumber ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant={ext.isActive ? "default" : "secondary"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
