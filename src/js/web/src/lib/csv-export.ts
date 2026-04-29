/**
 * CSV export utility.
 *
 * Handles proper escaping (commas, quotes, newlines) and triggers a browser
 * download via a temporary anchor element.
 */

export interface CsvColumn {
  /** Property key to read from each data row */
  key: string
  /** Column header label in the exported file */
  header: string
}

export interface CsvHeader<T> {
  label: string
  accessor: (item: T) => unknown
}

function escapeCell(value: unknown): string {
  if (value === null || value === undefined) {
    return ""
  }
  const str = String(value)
  // Wrap in quotes if the value contains a comma, double-quote, or newline
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

function todaySuffix(): string {
  const d = new Date()
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, "0")
  const dd = String(d.getDate()).padStart(2, "0")
  return `${yyyy}-${mm}-${dd}`
}

/**
 * Export an array of objects to a CSV file and trigger a download.
 *
 * @param data     Array of row objects.
 * @param filename Base filename (without extension). A date suffix and `.csv`
 *                 extension are appended automatically.
 * @param columns  Optional column definitions. When provided only the listed
 *                 keys are exported using the given header labels. When omitted
 *                 every key found across the data rows is exported.
 */
export function exportToCSV(data: Record<string, unknown>[], filename: string, columns?: CsvColumn[]): void {
  if (data.length === 0) {
    return
  }

  const cols: CsvColumn[] =
    columns ??
    Object.keys(data[0]).map((key) => ({
      key,
      header: key,
    }))

  const headerRow = cols.map((c) => escapeCell(c.header)).join(",")

  const bodyRows = data.map((row) => cols.map((c) => escapeCell(row[c.key])).join(","))

  const csv = [headerRow, ...bodyRows].join("\n")

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)

  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = `${filename}-${todaySuffix()}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export function exportToCsv<T>(filename: string, headers: CsvHeader<T>[], items: T[]): void {
  if (items.length === 0) return

  const headerRow = headers.map((h) => escapeCell(h.label)).join(",")
  const bodyRows = items.map((item) => headers.map((h) => escapeCell(h.accessor(item))).join(","))
  const csv = [headerRow, ...bodyRows].join("\n")

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = `${filename}-${todaySuffix()}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}
