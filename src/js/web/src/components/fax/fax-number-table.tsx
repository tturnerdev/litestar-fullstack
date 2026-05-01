import { Link, useNavigate } from "@tanstack/react-router"
import { AlertCircle, ArrowRight, Check, Copy, Printer } from "lucide-react"
import { useState } from "react"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useFaxNumbers } from "@/lib/api/hooks/fax"
import { formatPhoneNumber } from "@/lib/format-utils"

const PAGE_SIZE = 25

function CopyNumberButton({ number }: { number: string }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(number)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={handleCopy}>
          {copied ? (
            <Check className="h-3.5 w-3.5 text-green-500" />
          ) : (
            <Copy className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </Button>
      </TooltipTrigger>
      <TooltipContent>Copy number</TooltipContent>
    </Tooltip>
  )
}

export function FaxNumberTable() {
  const navigate = useNavigate()
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
        <CardTitle>Fax Numbers ({data.total})</CardTitle>
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
            {data.items.map((faxNumber, index) => (
              <TableRow
                key={faxNumber.id}
                className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 0 ? "bg-muted/20" : ""}`}
                onClick={(e) => {
                  const target = e.target as HTMLElement
                  if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
                    return
                  }
                  navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId: faxNumber.id } })
                }}
              >
                <TableCell>
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono">{formatPhoneNumber(faxNumber.number)}</span>
                    <CopyNumberButton number={faxNumber.number} />
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">{faxNumber.label ?? "—"}</TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className={`inline-block h-2 w-2 rounded-full ${faxNumber.isActive ? "bg-green-500" : "bg-gray-400"}`} />
                    <Badge variant={faxNumber.isActive ? "default" : "secondary"}>
                      {faxNumber.isActive ? "Active" : "Inactive"}
                    </Badge>
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground">{"—"}</TableCell>
                <TableCell className="text-right">
                  <div className="flex items-center justify-end gap-2">
                    <FaxNumberEditDialog faxNumber={faxNumber} />
                    <Button asChild variant="outline" size="sm">
                      <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                        Manage
                        <ArrowRight className="ml-1.5 h-4 w-4" />
                      </Link>
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {data.items.length} of {data.total} fax numbers
          </p>
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
                Previous
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
                Next
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
