import { useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AdminNav } from "@/components/admin/admin-nav"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

export const Route = createFileRoute("/_app/admin/voice")({
  component: AdminVoicePage,
})

// Placeholder data until backend aggregation endpoints are available
const stats = [
  { label: "Total phone numbers", value: 0 },
  { label: "Total extensions", value: 0 },
  { label: "Active DND", value: 0 },
  { label: "Unassigned numbers", value: 0 },
]

interface PhoneNumberRow {
  id: string
  number: string
  label: string
  teamName: string
  assignedTo: string | null
  status: "active" | "inactive"
}

interface ExtensionRow {
  id: string
  extension: string
  displayName: string
  teamName: string
  dnd: boolean
  status: "active" | "inactive"
}

// Placeholder -- will be replaced by API data
const placeholderPhoneNumbers: PhoneNumberRow[] = []
const placeholderExtensions: ExtensionRow[] = []

const PAGE_SIZE = 25

function AdminVoicePage() {
  const [phoneNumberPage, setPhoneNumberPage] = useState(1)
  const [extensionPage, setExtensionPage] = useState(1)

  // TODO: replace with admin API hooks once backend endpoints exist
  const phoneNumbers = placeholderPhoneNumbers
  const phoneTotal = phoneNumbers.length
  const phoneTotalPages = Math.max(1, Math.ceil(phoneTotal / PAGE_SIZE))
  const pagedPhoneNumbers = phoneNumbers.slice((phoneNumberPage - 1) * PAGE_SIZE, phoneNumberPage * PAGE_SIZE)

  const extensions = placeholderExtensions
  const extTotal = extensions.length
  const extTotalPages = Math.max(1, Math.ceil(extTotal / PAGE_SIZE))
  const pagedExtensions = extensions.slice((extensionPage - 1) * PAGE_SIZE, extensionPage * PAGE_SIZE)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader eyebrow="Administration" title="Voice" description="Manage phone numbers and extensions across the organization." />
      <AdminNav />

      <PageSection>
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {stats.map((item) => (
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
      </PageSection>

      <PageSection delay={0.1}>
        <Card>
          <CardHeader>
            <CardTitle>Phone numbers</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Label</TableHead>
                  <TableHead>Team</TableHead>
                  <TableHead>Assigned to</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pagedPhoneNumbers.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No phone numbers found. Numbers will appear here once the voice backend is connected.
                    </TableCell>
                  </TableRow>
                )}
                {pagedPhoneNumbers.map((pn) => (
                  <TableRow key={pn.id}>
                    <TableCell className="font-mono font-medium">{pn.number}</TableCell>
                    <TableCell className="text-muted-foreground">{pn.label}</TableCell>
                    <TableCell className="text-muted-foreground">{pn.teamName}</TableCell>
                    <TableCell className="text-muted-foreground">{pn.assignedTo ?? "Unassigned"}</TableCell>
                    <TableCell>
                      <Badge variant={pn.status === "active" ? "default" : "secondary"}>{pn.status}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {phoneTotal > PAGE_SIZE && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {phoneNumberPage} of {phoneTotalPages}
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
                  <TableHead>Team</TableHead>
                  <TableHead>DND</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pagedExtensions.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground">
                      No extensions found. Extensions will appear here once the voice backend is connected.
                    </TableCell>
                  </TableRow>
                )}
                {pagedExtensions.map((ext) => (
                  <TableRow key={ext.id}>
                    <TableCell className="font-mono font-medium">{ext.extension}</TableCell>
                    <TableCell className="text-muted-foreground">{ext.displayName}</TableCell>
                    <TableCell className="text-muted-foreground">{ext.teamName}</TableCell>
                    <TableCell>
                      <Badge variant={ext.dnd ? "destructive" : "outline"}>{ext.dnd ? "On" : "Off"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={ext.status === "active" ? "default" : "secondary"}>{ext.status}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {extTotal > PAGE_SIZE && (
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Page {extensionPage} of {extTotalPages}
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setExtensionPage((p) => Math.max(1, p - 1))} disabled={extensionPage <= 1}>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setExtensionPage((p) => Math.min(extTotalPages, p + 1))} disabled={extensionPage >= extTotalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </PageSection>
    </PageContainer>
  )
}
