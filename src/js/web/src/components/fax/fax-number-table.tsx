import { Link } from "@tanstack/react-router"
import { AlertCircle, Printer } from "lucide-react"
import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useFaxNumbers } from "@/lib/api/hooks/fax"

const PAGE_SIZE = 25

export function FaxNumberTable() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = useFaxNumbers(page, PAGE_SIZE)

  if (isLoading) {
    return <SkeletonTable rows={6} />
  }

  if (isError || !data) {
    return (
      <EmptyState
        icon={AlertCircle}
        title="Unable to load fax numbers"
        description="Something went wrong while fetching your fax numbers. Please try refreshing the page."
        action={
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            Refresh page
          </Button>
        }
      />
    )
  }

  const totalPages = Math.max(1, Math.ceil(data.total / PAGE_SIZE))

  return (
    <Card>
      <CardHeader>
        <CardTitle>Fax Numbers</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Number</TableHead>
              <TableHead>Label</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Email Routes</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.items.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="p-0">
                  <EmptyState
                    icon={Printer}
                    title="No fax numbers yet"
                    description="Add a fax number to start sending and receiving faxes."
                    className="border-0 rounded-none"
                  />
                </TableCell>
              </TableRow>
            )}
            {data.items.map((faxNumber) => (
              <TableRow key={faxNumber.id}>
                <TableCell className="font-mono">{faxNumber.number}</TableCell>
                <TableCell className="text-muted-foreground">{faxNumber.label ?? "—"}</TableCell>
                <TableCell>
                  <Badge variant={faxNumber.isActive ? "default" : "secondary"}>
                    {faxNumber.isActive ? "Active" : "Inactive"}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">—</TableCell>
                <TableCell className="text-right">
                  <Button asChild variant="outline" size="sm">
                    <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                      Manage
                    </Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Page {page} of {totalPages}
            </p>
            <div className="flex gap-2">
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
