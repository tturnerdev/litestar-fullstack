import { useCallback, useRef, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import {
  AlertCircle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  HardDrive,
  Phone,
  Upload,
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
// Sample CSV generators
// ---------------------------------------------------------------------------

const DEVICE_CSV_TEMPLATE =
  "name,mac_address,model,manufacturer,device_type,sip_username,sip_password,ip_address\n" +
  "Lobby Phone,00:1A:2B:3C:4D:5E,T54W,Yealink,desk_phone,lobby_001,,192.168.1.100\n" +
  "Conference Room,AA:BB:CC:DD:EE:FF,CP960,Yealink,conference_phone,conf_001,,192.168.1.101\n"

const EXTENSION_CSV_TEMPLATE =
  "extension_number,display_name\n" +
  "1001,Front Desk\n" +
  "1002,Sales Team\n"

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
            onClick={(e) => {
              e.stopPropagation()
              onFileSelect(null)
            }}
          >
            <X className="h-4 w-4" />
            <span className="sr-only">Remove file</span>
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
// Preview Table
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
    <div className="space-y-4">
      <div className="flex items-center gap-4 text-sm">
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

      <div className="max-h-[400px] overflow-auto rounded-md border">
        <Table>
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
    </div>
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
        </AlertDescription>
      </Alert>

      {hasErrors && (
        <div className="max-h-[200px] overflow-auto rounded-md border bg-muted/30 p-4">
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
// Import Section (shared UI for devices / extensions)
// ---------------------------------------------------------------------------

interface ImportSectionProps {
  title: string
  description: string
  icon: React.ElementType
  iconColor: string
  iconBg: string
  columns: string[]
  templateCsv: string
  templateFilename: string
  usePreview: () => ReturnType<typeof usePreviewDeviceImport>
  useImport: () => ReturnType<typeof useImportDevices>
}

function ImportSection({
  title,
  description,
  icon: Icon,
  iconColor,
  iconBg,
  columns,
  templateCsv,
  templateFilename,
  usePreview: usePreviewHook,
  useImport: useImportHook,
}: ImportSectionProps) {
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<BulkImportPreview | null>(null)
  const [result, setResult] = useState<BulkImportResult | null>(null)

  const previewMutation = usePreviewHook()
  const importMutation = useImportHook()

  const handleFileSelect = (selected: File | null) => {
    setFile(selected)
    setPreview(null)
    setResult(null)
  }

  const handlePreview = () => {
    if (!file) return
    previewMutation.mutate(file, {
      onSuccess: (data) => {
        setPreview(data)
        toast.success(`Preview ready — ${data.validRows} valid row${data.validRows !== 1 ? "s" : ""}`)
      },
      onError: (err) => {
        toast.error("Preview failed", {
          description: err instanceof Error ? err.message : undefined,
        })
      },
    })
  }

  const handleImport = () => {
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
  }

  const handleReset = () => {
    setFile(null)
    setPreview(null)
    setResult(null)
  }

  const canImport = preview && preview.validRows > 0 && !importMutation.isPending

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
        <FileDropZone
          file={file}
          onFileSelect={handleFileSelect}
          disabled={importMutation.isPending}
        />

        {/* Action buttons */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            onClick={handlePreview}
            disabled={!file || previewMutation.isPending || importMutation.isPending}
          >
            {previewMutation.isPending ? "Analyzing..." : "Preview"}
          </Button>
          <Button
            onClick={handleImport}
            disabled={!canImport}
          >
            {importMutation.isPending ? "Importing..." : "Import"}
          </Button>
          {(preview || result) && (
            <Button variant="ghost" size="sm" onClick={handleReset}>
              Reset
            </Button>
          )}
        </div>

        {/* Preview table */}
        {preview && <PreviewTable preview={preview} columns={columns} />}

        {/* Result summary */}
        {result && <ResultSummary result={result} />}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Page
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

const EXTENSION_COLUMNS = ["extension_number", "display_name"]

function BulkImportPage() {
  useDocumentTitle("Bulk Import")

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Bulk Import"
        description="Import devices and extensions from CSV files."
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
          </TabsList>

          <TabsContent value="devices" className="mt-4">
            <ImportSection
              title="Import Devices"
              description="Upload a CSV file to create or update devices in bulk."
              icon={HardDrive}
              iconColor="text-blue-600 dark:text-blue-400"
              iconBg="bg-blue-500/10"
              columns={DEVICE_COLUMNS}
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
              templateCsv={EXTENSION_CSV_TEMPLATE}
              templateFilename="extensions_template.csv"
              usePreview={usePreviewExtensionImport}
              useImport={useImportExtensions}
            />
          </TabsContent>
        </Tabs>
      </PageSection>
    </PageContainer>
  )
}
