import { useCallback, useEffect, useRef, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  ArrowRight,
  Check,
  CheckCircle2,
  Columns3,
  Download,
  FileSpreadsheet,
  HardDrive,
  Hash,
  Loader2,
  MapPin,
  Phone,
  Upload,
  Users,
  X,
} from "lucide-react"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import type { BulkImportPreview, BulkImportResult } from "@/lib/generated/api"
import {
  useImportDevices,
  useImportExtensions,
  usePreviewDeviceImport,
  usePreviewExtensionImport,
} from "@/lib/api/hooks/bulk-import"

export const Route = createFileRoute("/_app/admin/bulk-import")({
  component: BulkImportPage,
})

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A column expected by the import schema. */
interface ExpectedColumn {
  name: string
  required: boolean
  description: string
}

/** The result of client-side CSV parsing. */
interface ClientCsvParse {
  headers: string[]
  rows: string[][]
  totalRows: number
}

// ---------------------------------------------------------------------------
// Sample CSV templates
// ---------------------------------------------------------------------------

const DEVICE_CSV_TEMPLATE =
  "name,mac_address,model,manufacturer,device_type,sip_username,sip_password,ip_address\n" +
  "Lobby Phone,00:1A:2B:3C:4D:5E,T54W,Yealink,desk_phone,lobby_001,,192.168.1.100\n" +
  "Conference Room,AA:BB:CC:DD:EE:FF,CP960,Yealink,conference_phone,conf_001,,192.168.1.101\n"

const EXTENSION_CSV_TEMPLATE =
  "extension_number,display_name\n" +
  "1001,Front Desk\n" +
  "1002,Sales Team\n"

const USER_CSV_TEMPLATE =
  "email,name,role\n" +
  "jdoe@example.com,Jane Doe,member\n" +
  "asmith@example.com,Alex Smith,admin\n"

const LOCATION_CSV_TEMPLATE =
  "name,address,city,state,zip,country\n" +
  "HQ,123 Main St,New York,NY,10001,US\n" +
  "Branch,456 Oak Ave,Chicago,IL,60601,US\n"

const PHONE_NUMBER_CSV_TEMPLATE =
  "number,label,type,assigned_to\n" +
  "+15551234567,Main Line,local,\n" +
  "+18005551234,Toll Free,toll_free,\n"

function downloadCsv(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

// ---------------------------------------------------------------------------
// Client-side CSV parser
// ---------------------------------------------------------------------------

function parseCsvText(text: string): ClientCsvParse {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0)
  if (lines.length === 0) return { headers: [], rows: [], totalRows: 0 }

  const parseRow = (line: string): string[] => {
    const cells: string[] = []
    let current = ""
    let inQuotes = false
    for (let i = 0; i < line.length; i++) {
      const ch = line[i]
      if (inQuotes) {
        if (ch === '"' && line[i + 1] === '"') {
          current += '"'
          i++
        } else if (ch === '"') {
          inQuotes = false
        } else {
          current += ch
        }
      } else {
        if (ch === '"') {
          inQuotes = true
        } else if (ch === ",") {
          cells.push(current.trim())
          current = ""
        } else {
          current += ch
        }
      }
    }
    cells.push(current.trim())
    return cells
  }

  const headers = parseRow(lines[0])
  const dataLines = lines.slice(1)
  const previewRows = dataLines.slice(0, 5).map(parseRow)

  return { headers, rows: previewRows, totalRows: dataLines.length }
}

async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result as string)
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

// ---------------------------------------------------------------------------
// Step Indicator
// ---------------------------------------------------------------------------

type ImportStep = "upload" | "preview" | "import"

const STEPS: { key: ImportStep; label: string; number: number }[] = [
  { key: "upload", label: "Upload", number: 1 },
  { key: "preview", label: "Preview & Validate", number: 2 },
  { key: "import", label: "Import", number: 3 },
]

function StepIndicator({ current }: { current: ImportStep }) {
  const currentIdx = STEPS.findIndex((s) => s.key === current)

  return (
    <div className="flex items-center gap-2">
      {STEPS.map((step, idx) => {
        const isComplete = idx < currentIdx
        const isCurrent = idx === currentIdx
        return (
          <div key={step.key} className="flex items-center gap-2">
            {idx > 0 && (
              <ArrowRight
                className={cn(
                  "h-3.5 w-3.5",
                  isComplete ? "text-emerald-500" : "text-muted-foreground/30",
                )}
              />
            )}
            <div className="flex items-center gap-1.5">
              <div
                className={cn(
                  "flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium transition-colors",
                  isComplete && "bg-emerald-500 text-white",
                  isCurrent && "bg-primary text-primary-foreground",
                  !isComplete && !isCurrent && "bg-muted text-muted-foreground",
                )}
              >
                {isComplete ? <Check className="h-3.5 w-3.5" /> : step.number}
              </div>
              <span
                className={cn(
                  "text-sm",
                  isCurrent ? "font-medium text-foreground" : "text-muted-foreground",
                )}
              >
                {step.label}
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// File Drop Zone
// ---------------------------------------------------------------------------

interface FileDropZoneProps {
  file: File | null
  onFileSelect: (file: File | null) => void
  disabled?: boolean
}

function FileDropZone({ file, onFileSelect, disabled }: FileDropZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [isDragging, setIsDragging] = useState(false)

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setIsDragging(false)
      if (disabled) return
      const dropped = e.dataTransfer.files[0]
      if (dropped && dropped.name.toLowerCase().endsWith(".csv")) {
        onFileSelect(dropped)
      } else if (dropped) {
        toast.error("Invalid file type", { description: "Please upload a .csv file" })
      }
    },
    [disabled, onFileSelect],
  )

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files?.[0]
      if (selected) onFileSelect(selected)
    },
    [onFileSelect],
  )

  return (
    <div
      className={cn(
        "relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 transition-colors",
        isDragging && !disabled ? "border-primary bg-primary/5" : "border-border/60",
        disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer hover:border-primary/50 hover:bg-muted/30",
      )}
      onDragOver={(e) => {
        e.preventDefault()
        if (!disabled) setIsDragging(true)
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={handleDrop}
      onClick={() => !disabled && inputRef.current?.click()}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          if (!disabled) inputRef.current?.click()
        }
      }}
      role="button"
      tabIndex={disabled ? -1 : 0}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".csv"
        className="hidden"
        onChange={handleChange}
        disabled={disabled}
      />
      {file ? (
        <div className="flex items-center gap-3">
          <FileSpreadsheet className="h-8 w-8 text-emerald-500" />
          <div>
            <p className="font-medium">{file.name}</p>
            <p className="text-xs text-muted-foreground">
              {(file.size / 1024).toFixed(1)} KB
            </p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7"
            aria-label="Remove file"
            onClick={(e) => {
              e.stopPropagation()
              onFileSelect(null)
            }}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      ) : (
        <>
          <Upload className="mb-3 h-8 w-8 text-muted-foreground/60" />
          <p className="text-sm font-medium">
            Drop a CSV file here, or click to browse
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Accepts .csv files up to 5 MB
          </p>
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Column Mapping Card
// ---------------------------------------------------------------------------

interface ColumnMappingCardProps {
  detectedHeaders: string[]
  expectedColumns: ExpectedColumn[]
}

function ColumnMappingCard({ detectedHeaders, expectedColumns }: ColumnMappingCardProps) {
  const normalizedDetected = detectedHeaders.map((h) => h.toLowerCase().trim())

  const matched: { expected: ExpectedColumn; detected: string }[] = []
  const missing: ExpectedColumn[] = []
  const extra: string[] = []

  for (const col of expectedColumns) {
    const idx = normalizedDetected.indexOf(col.name.toLowerCase())
    if (idx !== -1) {
      matched.push({ expected: col, detected: detectedHeaders[idx] })
    } else {
      missing.push(col)
    }
  }

  const expectedNames = new Set(expectedColumns.map((c) => c.name.toLowerCase()))
  for (const header of detectedHeaders) {
    if (!expectedNames.has(header.toLowerCase().trim())) {
      extra.push(header)
    }
  }

  const requiredMissing = missing.filter((c) => c.required)
  const optionalMissing = missing.filter((c) => !c.required)

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <Columns3 className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm">Column Mapping</CardTitle>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              {matched.length} matched
            </Badge>
            {requiredMissing.length > 0 && (
              <Badge variant="destructive" className="text-xs">
                {requiredMissing.length} required missing
              </Badge>
            )}
            {extra.length > 0 && (
              <Badge variant="secondary" className="text-xs">
                {extra.length} extra
              </Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-1.5">
          {matched.map(({ expected, detected }) => (
            <div key={expected.name} className="flex items-center gap-2 text-sm">
              <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
              <span className="font-mono text-xs">{detected}</span>
              <ArrowRight className="h-3 w-3 text-muted-foreground/40" />
              <span className="text-muted-foreground">{expected.description}</span>
              {expected.required && (
                <Badge variant="outline" className="ml-auto text-[10px]">required</Badge>
              )}
            </div>
          ))}
          {requiredMissing.map((col) => (
            <div key={col.name} className="flex items-center gap-2 text-sm">
              <AlertCircle className="h-3.5 w-3.5 shrink-0 text-destructive" />
              <span className="font-mono text-xs text-destructive">{col.name}</span>
              <ArrowRight className="h-3 w-3 text-muted-foreground/40" />
              <span className="text-muted-foreground">{col.description}</span>
              <Badge variant="destructive" className="ml-auto text-[10px]">required</Badge>
            </div>
          ))}
          {optionalMissing.map((col) => (
            <div key={col.name} className="flex items-center gap-2 text-sm text-muted-foreground">
              <div className="h-3.5 w-3.5 shrink-0" />
              <span className="font-mono text-xs">{col.name}</span>
              <ArrowRight className="h-3 w-3 text-muted-foreground/40" />
              <span>{col.description}</span>
              <Badge variant="outline" className="ml-auto text-[10px]">optional</Badge>
            </div>
          ))}
          {extra.map((header) => (
            <div key={header} className="flex items-center gap-2 text-sm text-muted-foreground/60">
              <div className="h-3.5 w-3.5 shrink-0" />
              <span className="font-mono text-xs">{header}</span>
              <ArrowRight className="h-3 w-3 text-muted-foreground/40" />
              <span className="italic">ignored</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Client-side CSV Preview Table (first 5 rows)
// ---------------------------------------------------------------------------

interface CsvPreviewTableProps {
  parsed: ClientCsvParse
}

function CsvPreviewTable({ parsed }: CsvPreviewTableProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm">CSV Preview</CardTitle>
          </div>
          <span className="text-xs text-muted-foreground">
            Showing {parsed.rows.length} of {parsed.totalRows} row{parsed.totalRows !== 1 ? "s" : ""}
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="max-h-[240px] overflow-auto rounded-md border">
          <Table aria-label="CSV file preview">
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">#</TableHead>
                {parsed.headers.map((h) => (
                  <TableHead key={h} className="text-xs">
                    {h}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {parsed.rows.map((row, rowIdx) => (
                <TableRow key={rowIdx}>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {rowIdx + 1}
                  </TableCell>
                  {parsed.headers.map((_, colIdx) => (
                    <TableCell key={colIdx} className="text-sm">
                      {row[colIdx] || (
                        <span className="text-muted-foreground/40">--</span>
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Validation Summary Card
// ---------------------------------------------------------------------------

interface ValidationSummaryProps {
  preview: BulkImportPreview
}

function ValidationSummary({ preview }: ValidationSummaryProps) {
  const validPercent =
    preview.totalRows > 0
      ? Math.round((preview.validRows / preview.totalRows) * 100)
      : 0

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
          <CardTitle className="text-sm">Validation Summary</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Stats row */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="rounded-lg border bg-muted/30 px-4 py-3 text-center">
            <p className="text-2xl font-semibold">{preview.totalRows}</p>
            <p className="text-xs text-muted-foreground">Total Rows</p>
          </div>
          <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-center dark:border-emerald-900 dark:bg-emerald-950">
            <p className="text-2xl font-semibold text-emerald-600 dark:text-emerald-400">
              {preview.validRows}
            </p>
            <p className="text-xs text-emerald-600 dark:text-emerald-400">Valid</p>
          </div>
          <div
            className={cn(
              "rounded-lg border px-4 py-3 text-center",
              preview.errorRows > 0
                ? "border-red-200 bg-red-50 dark:border-red-900 dark:bg-red-950"
                : "border-emerald-200 bg-emerald-50 dark:border-emerald-900 dark:bg-emerald-950",
            )}
          >
            <p
              className={cn(
                "text-2xl font-semibold",
                preview.errorRows > 0
                  ? "text-destructive"
                  : "text-emerald-600 dark:text-emerald-400",
              )}
            >
              {preview.errorRows}
            </p>
            <p
              className={cn(
                "text-xs",
                preview.errorRows > 0
                  ? "text-destructive"
                  : "text-emerald-600 dark:text-emerald-400",
              )}
            >
              Errors
            </p>
          </div>
        </div>

        {/* Validation progress bar */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Validation rate</span>
            <span>{validPercent}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                validPercent === 100
                  ? "bg-emerald-500"
                  : validPercent >= 80
                    ? "bg-amber-500"
                    : "bg-destructive",
              )}
              style={{ width: `${validPercent}%` }}
            />
          </div>
        </div>

        {/* Error rows breakdown */}
        {preview.errorRows > 0 && (
          <div className="rounded-md border border-destructive/20 bg-destructive/5 p-3">
            <p className="mb-2 text-xs font-medium text-destructive">
              Rows with errors will be skipped during import:
            </p>
            <ul className="space-y-1">
              {preview.rows
                .filter((row) => row.errors && row.errors.length > 0)
                .map((row) => (
                  <li key={row.rowNumber} className="text-xs text-destructive">
                    <span className="font-mono">Row {row.rowNumber}:</span>{" "}
                    {row.errors?.join("; ")}
                  </li>
                ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Import Progress Indicator
// ---------------------------------------------------------------------------

interface ImportProgressProps {
  isPending: boolean
  result: BulkImportResult | null
}

function ImportProgress({ isPending, result }: ImportProgressProps) {
  const [progress, setProgress] = useState(0)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (isPending) {
      setProgress(0)
      // Simulate progress that slows down as it approaches 90%
      intervalRef.current = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) return prev
          const increment = prev < 30 ? 6 : prev < 60 ? 3 : prev < 80 ? 1.5 : 0.5
          return Math.min(prev + increment, 90)
        })
      }, 200)
    } else if (result) {
      // Snap to 100 on completion
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
      setProgress(100)
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [isPending, result])

  if (!isPending && !result) return null

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          {isPending ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              <span className="font-medium">Importing records...</span>
            </>
          ) : result ? (
            <>
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              <span className="font-medium text-emerald-600 dark:text-emerald-400">
                Import complete
              </span>
            </>
          ) : null}
        </div>
        <span className="font-mono text-xs text-muted-foreground">
          {Math.round(progress)}%
        </span>
      </div>
      <div className="h-2.5 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={cn(
            "h-full rounded-full transition-all",
            isPending ? "bg-primary duration-200" : "bg-emerald-500 duration-300",
          )}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Server Preview Table
// ---------------------------------------------------------------------------

const actionBadgeVariant: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  create: "default",
  update: "secondary",
  skip: "destructive",
}

interface PreviewTableProps {
  preview: BulkImportPreview
  columns: string[]
}

function PreviewTable({ preview, columns }: PreviewTableProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">Server Validation Results</CardTitle>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted-foreground">
              {preview.totalRows} row{preview.totalRows !== 1 ? "s" : ""} parsed
            </span>
            <Separator orientation="vertical" className="h-4" />
            <span className="text-emerald-600 dark:text-emerald-400">
              {preview.validRows} valid
            </span>
            {preview.errorRows > 0 && (
              <>
                <Separator orientation="vertical" className="h-4" />
                <span className="text-destructive">
                  {preview.errorRows} with errors
                </span>
              </>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="max-h-[400px] overflow-auto rounded-md border">
          <Table aria-label="Import preview">
            <TableHeader>
              <TableRow>
                <TableHead className="w-16">Row</TableHead>
                <TableHead className="w-24">Action</TableHead>
                {columns.map((col) => (
                  <TableHead key={col}>{col}</TableHead>
                ))}
                <TableHead>Errors</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {preview.rows.map((row) => (
                <TableRow
                  key={row.rowNumber}
                  className={cn(row.errors && row.errors.length > 0 && "bg-destructive/5")}
                >
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {row.rowNumber}
                  </TableCell>
                  <TableCell>
                    <Badge variant={actionBadgeVariant[row.action] ?? "outline"}>
                      {row.action}
                    </Badge>
                  </TableCell>
                  {columns.map((col) => (
                    <TableCell key={col} className="text-sm">
                      {(row.data as Record<string, string>)[col] || (
                        <span className="text-muted-foreground/40">--</span>
                      )}
                    </TableCell>
                  ))}
                  <TableCell>
                    {row.errors && row.errors.length > 0 && (
                      <ul className="space-y-0.5">
                        {row.errors.map((err) => (
                          <li key={err} className="flex items-start gap-1.5 text-xs text-destructive">
                            <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
                            {err}
                          </li>
                        ))}
                      </ul>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Result Summary
// ---------------------------------------------------------------------------

interface ResultSummaryProps {
  result: BulkImportResult
}

function ResultSummary({ result }: ResultSummaryProps) {
  const hasErrors = result.errors.length > 0
  const total = result.created + result.updated + result.skipped

  return (
    <div className="space-y-4">
      <Alert variant={hasErrors ? "warning" : "success"}>
        {hasErrors ? (
          <AlertCircle className="h-4 w-4" />
        ) : (
          <CheckCircle2 className="h-4 w-4" />
        )}
        <AlertTitle>
          {hasErrors ? "Import completed with warnings" : "Import completed successfully"}
        </AlertTitle>
        <AlertDescription>
          {result.created} created, {result.updated} updated, {result.skipped} skipped
          {total > 0 && ` out of ${total} total`}
        </AlertDescription>
      </Alert>

      {/* Result breakdown */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="rounded-lg border bg-emerald-50 px-3 py-2 text-center dark:bg-emerald-950">
          <p className="text-lg font-semibold text-emerald-600 dark:text-emerald-400">{result.created}</p>
          <p className="text-xs text-emerald-600 dark:text-emerald-400">Created</p>
        </div>
        <div className="rounded-lg border bg-blue-50 px-3 py-2 text-center dark:bg-blue-950">
          <p className="text-lg font-semibold text-blue-600 dark:text-blue-400">{result.updated}</p>
          <p className="text-xs text-blue-600 dark:text-blue-400">Updated</p>
        </div>
        <div className="rounded-lg border bg-muted/30 px-3 py-2 text-center">
          <p className="text-lg font-semibold text-muted-foreground">{result.skipped}</p>
          <p className="text-xs text-muted-foreground">Skipped</p>
        </div>
      </div>

      {hasErrors && (
        <div className="max-h-[200px] overflow-auto rounded-md border bg-muted/30 p-4">
          <p className="mb-2 text-xs font-medium text-destructive">Errors encountered:</p>
          <ul className="space-y-1">
            {result.errors.map((err) => (
              <li key={err} className="flex items-start gap-1.5 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" />
                {err}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Import Section (shared UI for each entity type)
// ---------------------------------------------------------------------------

interface ImportSectionProps {
  title: string
  description: string
  icon: React.ElementType
  iconColor: string
  iconBg: string
  columns: string[]
  expectedColumns: ExpectedColumn[]
  templateCsv: string
  templateFilename: string
  usePreview: () => ReturnType<typeof usePreviewDeviceImport>
  useImport: () => ReturnType<typeof useImportDevices>
  available?: boolean
}

function ImportSection({
  title,
  description,
  icon: Icon,
  iconColor,
  iconBg,
  columns,
  expectedColumns,
  templateCsv,
  templateFilename,
  usePreview: usePreviewHook,
  useImport: useImportHook,
  available = true,
}: ImportSectionProps) {
  const [file, setFile] = useState<File | null>(null)
  const [clientParse, setClientParse] = useState<ClientCsvParse | null>(null)
  const [preview, setPreview] = useState<BulkImportPreview | null>(null)
  const [result, setResult] = useState<BulkImportResult | null>(null)

  const previewMutation = usePreviewHook()
  const importMutation = useImportHook()

  // Determine current step
  const currentStep: ImportStep = result
    ? "import"
    : preview
      ? "import"
      : clientParse
        ? "preview"
        : "upload"

  const handleFileSelect = useCallback(
    async (selected: File | null) => {
      setFile(selected)
      setClientParse(null)
      setPreview(null)
      setResult(null)

      if (selected) {
        try {
          const text = await readFileAsText(selected)
          const parsed = parseCsvText(text)
          setClientParse(parsed)
          if (parsed.totalRows === 0) {
            toast.error("Empty CSV", { description: "The file contains no data rows" })
          }
        } catch {
          toast.error("Failed to read file", { description: "Could not parse the CSV file" })
        }
      }
    },
    [],
  )

  const handlePreview = useCallback(() => {
    if (!file) return
    previewMutation.mutate(file, {
      onSuccess: (data) => {
        setPreview(data)
        toast.success(`Preview ready -- ${data.validRows} valid row${data.validRows !== 1 ? "s" : ""}`)
      },
      onError: (err) => {
        toast.error("Preview failed", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }, [file, previewMutation])

  const handleImport = useCallback(() => {
    if (!file) return
    importMutation.mutate(file, {
      onSuccess: (data) => {
        setResult(data)
        setPreview(null)
        toast.success("Import completed", {
          description: `${data.created} created, ${data.updated} updated, ${data.skipped} skipped`,
        })
      },
      onError: (err) => {
        toast.error("Import failed", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }, [file, importMutation])

  const handleReset = useCallback(() => {
    setFile(null)
    setClientParse(null)
    setPreview(null)
    setResult(null)
  }, [])

  const canPreview = file && clientParse && clientParse.totalRows > 0 && !previewMutation.isPending && !importMutation.isPending
  const canImport = preview && preview.validRows > 0 && !importMutation.isPending

  // Unavailable entity type
  if (!available) {
    return (
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className={cn("flex h-9 w-9 items-center justify-center rounded-lg", iconBg)}>
              <Icon className={cn("h-4 w-4", iconColor)} />
            </div>
            <div>
              <CardTitle>{title}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border/60 py-12">
            <Icon className="mb-3 h-10 w-10 text-muted-foreground/30" />
            <p className="text-sm font-medium text-muted-foreground">Coming soon</p>
            <p className="mt-1 text-xs text-muted-foreground/60">
              Bulk import for {title.toLowerCase().replace("import ", "")} is not yet available.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-4 gap-1.5"
              onClick={() => downloadCsv(templateCsv, templateFilename)}
            >
              <Download className="h-3.5 w-3.5" />
              Download Template
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={cn("flex h-9 w-9 items-center justify-center rounded-lg", iconBg)}>
              <Icon className={cn("h-4 w-4", iconColor)} />
            </div>
            <div>
              <CardTitle>{title}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => downloadCsv(templateCsv, templateFilename)}
          >
            <Download className="h-3.5 w-3.5" />
            Sample CSV
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Step indicator */}
        <StepIndicator current={currentStep} />

        {/* File drop zone */}
        <FileDropZone
          file={file}
          onFileSelect={handleFileSelect}
          disabled={importMutation.isPending}
        />

        {/* Client-side CSV preview (immediate, first 5 rows) */}
        {clientParse && clientParse.rows.length > 0 && (
          <CsvPreviewTable parsed={clientParse} />
        )}

        {/* Column mapping display */}
        {clientParse && clientParse.headers.length > 0 && (
          <ColumnMappingCard
            detectedHeaders={clientParse.headers}
            expectedColumns={expectedColumns}
          />
        )}

        {/* Action buttons */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            onClick={handlePreview}
            disabled={!canPreview}
          >
            {previewMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Validating...
              </>
            ) : (
              "Validate & Preview"
            )}
          </Button>
          <Button
            onClick={handleImport}
            disabled={!canImport}
          >
            {importMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Importing...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Import {preview ? `${preview.validRows} Row${preview.validRows !== 1 ? "s" : ""}` : ""}
              </>
            )}
          </Button>
          {(clientParse || preview || result) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleReset}
              disabled={importMutation.isPending}
            >
              Reset
            </Button>
          )}
        </div>

        {/* Validation summary card */}
        {preview && <ValidationSummary preview={preview} />}

        {/* Server-validated preview table */}
        {preview && <PreviewTable preview={preview} columns={columns} />}

        {/* Import progress */}
        <ImportProgress
          isPending={importMutation.isPending}
          result={result}
        />

        {/* Result summary */}
        {result && <ResultSummary result={result} />}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Column definitions per entity type
// ---------------------------------------------------------------------------

const DEVICE_COLUMNS = [
  "name",
  "mac_address",
  "model",
  "manufacturer",
  "device_type",
  "sip_username",
  "ip_address",
]

const DEVICE_EXPECTED_COLUMNS: ExpectedColumn[] = [
  { name: "name", required: true, description: "Device display name" },
  { name: "mac_address", required: true, description: "Hardware MAC address" },
  { name: "model", required: false, description: "Device model (e.g. T54W)" },
  { name: "manufacturer", required: false, description: "Device manufacturer (e.g. Yealink)" },
  { name: "device_type", required: false, description: "Type: desk_phone, conference_phone, etc." },
  { name: "sip_username", required: false, description: "SIP registration username" },
  { name: "sip_password", required: false, description: "SIP registration password" },
  { name: "ip_address", required: false, description: "Static IP address" },
]

const EXTENSION_COLUMNS = ["extension_number", "display_name"]

const EXTENSION_EXPECTED_COLUMNS: ExpectedColumn[] = [
  { name: "extension_number", required: true, description: "Extension number (e.g. 1001)" },
  { name: "display_name", required: true, description: "Display name for caller ID" },
]

const USER_COLUMNS = ["email", "name", "role"]

const USER_EXPECTED_COLUMNS: ExpectedColumn[] = [
  { name: "email", required: true, description: "User email address" },
  { name: "name", required: true, description: "Full name" },
  { name: "role", required: false, description: "Role: member or admin" },
]

const LOCATION_COLUMNS = ["name", "address", "city", "state", "zip", "country"]

const LOCATION_EXPECTED_COLUMNS: ExpectedColumn[] = [
  { name: "name", required: true, description: "Location name" },
  { name: "address", required: true, description: "Street address" },
  { name: "city", required: true, description: "City" },
  { name: "state", required: false, description: "State or province" },
  { name: "zip", required: false, description: "Postal / ZIP code" },
  { name: "country", required: false, description: "Country code (e.g. US)" },
]

const PHONE_NUMBER_COLUMNS = ["number", "label", "type", "assigned_to"]

const PHONE_NUMBER_EXPECTED_COLUMNS: ExpectedColumn[] = [
  { name: "number", required: true, description: "Phone number in E.164 format" },
  { name: "label", required: false, description: "Friendly label (e.g. Main Line)" },
  { name: "type", required: false, description: "Number type: local, toll_free, etc." },
  { name: "assigned_to", required: false, description: "User or extension to assign to" },
]

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function BulkImportPage() {
  useDocumentTitle("Bulk Import")

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Bulk Import"
        description="Import devices, extensions, users, locations, and phone numbers from CSV files."
        breadcrumbs={<AdminBreadcrumbs />}
      />
      <AdminNav />

      <PageSection>
        <Tabs defaultValue="devices">
          <TabsList>
            <TabsTrigger value="devices" className="gap-1.5">
              <HardDrive className="h-3.5 w-3.5" />
              Devices
            </TabsTrigger>
            <TabsTrigger value="extensions" className="gap-1.5">
              <Phone className="h-3.5 w-3.5" />
              Extensions
            </TabsTrigger>
            <TabsTrigger value="users" className="gap-1.5">
              <Users className="h-3.5 w-3.5" />
              Users
            </TabsTrigger>
            <TabsTrigger value="locations" className="gap-1.5">
              <MapPin className="h-3.5 w-3.5" />
              Locations
            </TabsTrigger>
            <TabsTrigger value="phone-numbers" className="gap-1.5">
              <Hash className="h-3.5 w-3.5" />
              Phone Numbers
            </TabsTrigger>
          </TabsList>

          <TabsContent value="devices" className="mt-4">
            <ImportSection
              title="Import Devices"
              description="Upload a CSV file to create or update devices in bulk."
              icon={HardDrive}
              iconColor="text-blue-600 dark:text-blue-400"
              iconBg="bg-blue-500/10"
              columns={DEVICE_COLUMNS}
              expectedColumns={DEVICE_EXPECTED_COLUMNS}
              templateCsv={DEVICE_CSV_TEMPLATE}
              templateFilename="devices_template.csv"
              usePreview={usePreviewDeviceImport}
              useImport={useImportDevices}
            />
          </TabsContent>

          <TabsContent value="extensions" className="mt-4">
            <ImportSection
              title="Import Extensions"
              description="Upload a CSV file to create or update extensions in bulk."
              icon={Phone}
              iconColor="text-violet-600 dark:text-violet-400"
              iconBg="bg-violet-500/10"
              columns={EXTENSION_COLUMNS}
              expectedColumns={EXTENSION_EXPECTED_COLUMNS}
              templateCsv={EXTENSION_CSV_TEMPLATE}
              templateFilename="extensions_template.csv"
              usePreview={usePreviewExtensionImport}
              useImport={useImportExtensions}
            />
          </TabsContent>

          <TabsContent value="users" className="mt-4">
            <ImportSection
              title="Import Users"
              description="Upload a CSV file to create or update user accounts in bulk."
              icon={Users}
              iconColor="text-amber-600 dark:text-amber-400"
              iconBg="bg-amber-500/10"
              columns={USER_COLUMNS}
              expectedColumns={USER_EXPECTED_COLUMNS}
              templateCsv={USER_CSV_TEMPLATE}
              templateFilename="users_template.csv"
              usePreview={usePreviewDeviceImport}
              useImport={useImportDevices}
              available={false}
            />
          </TabsContent>

          <TabsContent value="locations" className="mt-4">
            <ImportSection
              title="Import Locations"
              description="Upload a CSV file to create or update office locations in bulk."
              icon={MapPin}
              iconColor="text-teal-600 dark:text-teal-400"
              iconBg="bg-teal-500/10"
              columns={LOCATION_COLUMNS}
              expectedColumns={LOCATION_EXPECTED_COLUMNS}
              templateCsv={LOCATION_CSV_TEMPLATE}
              templateFilename="locations_template.csv"
              usePreview={usePreviewDeviceImport}
              useImport={useImportDevices}
              available={false}
            />
          </TabsContent>

          <TabsContent value="phone-numbers" className="mt-4">
            <ImportSection
              title="Import Phone Numbers"
              description="Upload a CSV file to provision and assign phone numbers in bulk."
              icon={Hash}
              iconColor="text-rose-600 dark:text-rose-400"
              iconBg="bg-rose-500/10"
              columns={PHONE_NUMBER_COLUMNS}
              expectedColumns={PHONE_NUMBER_EXPECTED_COLUMNS}
              templateCsv={PHONE_NUMBER_CSV_TEMPLATE}
              templateFilename="phone_numbers_template.csv"
              usePreview={usePreviewDeviceImport}
              useImport={useImportDevices}
              available={false}
            />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
