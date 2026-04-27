import { Link } from "@tanstack/react-router"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useExtensions } from "@/lib/api/hooks/voice"

const PAGE_SIZE = 25

export function ExtensionTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useExtensions(page, PAGE_SIZE)

  if (isLoading) return <SkeletonTable rows={6} />

  if (isError || !data) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Extensions</CardTitle>
        </CardHeader>
        <CardContent className="text-muted-foreground">We could not load extensions.</CardContent>
      </Card>
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Extensions</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Extension</TableHead>
              <TableHead>Display Name</TableHead>
              <TableHead>Phone Number</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                  No extensions found.
                </TableCell>
              </TableRow>
            ) : (
              data.items.map((ext) => (
                <TableRow key={ext.id}>
                  <TableCell className="font-mono">{ext.extensionNumber}</TableCell>
                  <TableCell>{ext.displayName}</TableCell>
                  <TableCell>{ext.phoneNumberId ? <Badge variant="secondary">Assigned</Badge> : <span className="text-muted-foreground">--</span>}</TableCell>
                  <TableCell>
                    <Badge variant={ext.isActive ? "default" : "outline"}>{ext.isActive ? "Active" : "Inactive"}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button asChild variant="outline" size="sm">
                      <Link to="/voice/extensions/$extensionId" params={{ extensionId: ext.id }}>
                        Settings
                      </Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Page {page} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                Previous
              </Button>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
