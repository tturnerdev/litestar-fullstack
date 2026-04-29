/**
 * Escape a cell value for CSV output.
 * Wraps in double-quotes if the value contains a comma, double-quote, or newline.
 * Inner double-quotes are escaped by doubling them (RFC 4180).
 */
function escapeCell(value: unknown): string {
  if (value === null || value === undefined) return ""
  const str = String(value)
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

export interface CsvHeader<T> {
  /** Column header label */
  label: string
  /** Accessor function that extracts the cell value from a row */
  accessor: (row: T) => unknown
}

/**
 * Generate a CSV string from headers and row data.
 */
export function generateCsv<T>(headers: CsvHeader<T>[], rows: T[]): string {
  const headerLine = headers.map((h) => escapeCell(h.label)).join(",")
  const dataLines = rows.map((row) =>
    headers.map((h) => escapeCell(h.accessor(row))).join(","),
  )
  return [headerLine, ...dataLines].join("\r\n")
}

/**
 * Trigger a browser download of a CSV file.
 *
 * @param filename  - Name for the downloaded file (should end in `.csv`).
 * @param headers   - Column definitions with labels and accessor functions.
 * @param rows      - Array of data objects to export.
 */
export function exportToCsv<T>(filename: string, headers: CsvHeader<T>[], rows: T[]): void {
  const csv = generateCsv(headers, rows)
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)

  const link = document.createElement("a")
  link.href = url
  link.download = filename.endsWith(".csv") ? filename : `${filename}.csv`
  link.style.display = "none"
  document.body.appendChild(link)
  link.click()

  // Cleanup
  setTimeout(() => {
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }, 100)
}
