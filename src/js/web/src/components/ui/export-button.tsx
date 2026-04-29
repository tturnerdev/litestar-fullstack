import { Download } from "lucide-react"
import { useCallback, useState } from "react"

import { Button } from "@/components/ui/button"
import { type CsvColumn, exportToCSV } from "@/lib/csv-export"

interface ExportButtonProps {
  /** Row data to export */
  data: Record<string, unknown>[]
  /** Base filename (date suffix + .csv added automatically) */
  filename: string
  /** Optional column definitions to control which keys are exported and their headers */
  columns?: CsvColumn[]
  /** Disable the button (e.g. while data is loading) */
  disabled?: boolean
}

export function ExportButton({ data, filename, columns, disabled }: ExportButtonProps) {
  const [exporting, setExporting] = useState(false)

  const handleExport = useCallback(() => {
    if (data.length === 0) return
    setExporting(true)
    // Brief visual feedback, then trigger download
    setTimeout(() => {
      exportToCSV(data, filename, columns)
      setExporting(false)
    }, 150)
  }, [data, filename, columns])

  return (
    <Button variant="outline" size="sm" onClick={handleExport} disabled={disabled || exporting || data.length === 0}>
      <Download />
      {exporting ? "Exporting..." : "Export"}
    </Button>
  )
}
