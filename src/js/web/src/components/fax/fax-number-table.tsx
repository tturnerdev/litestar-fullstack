import { Link, useNavigate } from "@tanstack/react-router"
import { AlertCircle, Check, Copy, Eye, MoreVertical, Pencil, Printer, Trash2 } from "lucide-react"
import { useCallback, useState } from "react"
import { FaxNumberEditDialog } from "@/components/fax/fax-number-edit-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { EmptyState } from "@/components/ui/empty-state"
import { SkeletonTable } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { type FaxNumber, useDeleteFaxNumber, useFaxNumbers } from "@/lib/api/hooks/fax"
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
  const deleteMutation = useDeleteFaxNumber()

  const handleRowClick = useCallback(
    (faxNumberId: string) => {
      navigate({ to: "/fax/numbers/$faxNumberId", params: { faxNumberId } })
    },
    [navigate],
  )

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
              <TableHead className="w-16 text-right">Actions</TableHead>
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
              <FaxNumberRow
                key={faxNumber.id}
                faxNumber={faxNumber}
                index={index}
                onRowClick={() => handleRowClick(faxNumber.id)}
                onDelete={() => deleteMutation.mutate(faxNumber.id)}
              />
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

// ---------------------------------------------------------------------------
// Fax Number Row
// ---------------------------------------------------------------------------

function FaxNumberRow({
  faxNumber,
  index,
  onRowClick,
  onDelete,
}: {
  faxNumber: FaxNumber
  index: number
  onRowClick: () => void
  onDelete: () => void
}) {
  const [editOpen, setEditOpen] = useState(false)

  return (
    <TableRow
      className={`cursor-pointer hover:bg-muted/50 transition-colors ${index % 2 === 1 ? "bg-muted/20" : ""}`}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (target.closest("[role=checkbox]") || target.closest("[data-slot=dropdown]") || target.closest("button") || target.closest("a")) {
          return
        }
        onRowClick()
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
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0"
              data-slot="dropdown"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Actions for {faxNumber.number}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <Link to="/fax/numbers/$faxNumberId" params={{ faxNumberId: faxNumber.id }}>
                <Eye className="mr-2 h-4 w-4" />
                View details
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => setEditOpen(true)}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={onDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <FaxNumberEditDialog faxNumber={faxNumber} open={editOpen} onOpenChange={setEditOpen} />
      </TableCell>
    </TableRow>
  )
}
