/**
 * CSV export utility.
 *
 * Handles proper escaping (commas, quotes, newlines) and triggers a browser
 * download via a temporary anchor element.
 */

export interface CsvHeader<T> {
  label: string
  accessor: (item: T) => unknown
}

export { escapeCell as escapeCSVCell }

function escapeCell(value: unknown): string {
  if (value === null || value === undefined) {
    return ""
  }
  const str = String(value)
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

export function buildCsvString<T extends Record<string, unknown>>(data: T[], keys: string[]): string {
  const headerRow = keys.join(",")
  const bodyRows = data.map((row) => keys.map((k) => escapeCell(row[k])).join(","))
  return [headerRow, ...bodyRows].join("\n")
}

export function buildCsvStringWithAccessors<T>(data: T[], columns: { header: string; accessor: (row: T) => unknown }[]): string {
  const headerRow = columns.map((c) => escapeCell(c.header)).join(",")
  const bodyRows = data.map((row) => columns.map((c) => escapeCell(c.accessor(row))).join(","))
  return [headerRow, ...bodyRows].join("\n")
}

function todaySuffix(): string {
  const d = new Date()
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, "0")
  const dd = String(d.getDate()).padStart(2, "0")
  return `${yyyy}-${mm}-${dd}`
}

export function exportToCsv<T>(filename: string, headers: CsvHeader<T>[], items: T[]): void {
  if (items.length === 0) return

  const headerRow = headers.map((h) => escapeCell(h.label)).join(",")
  const bodyRows = items.map((item) => headers.map((h) => escapeCell(h.accessor(item))).join(","))
  const csv = [headerRow, ...bodyRows].join("\n")

  const blob = new Blob(["﻿", csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = `${filename}-${todaySuffix()}.csv`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}

export function exportToCSV<T extends Record<string, unknown>>(data: T[], filename: string): void {
  if (data.length === 0) return
  const keys = Object.keys(data[0])
  const headers: CsvHeader<T> = keys.map((k) => ({ label: k, accessor: (row: T) => row[k] })) as unknown as CsvHeader<T>
  exportToCsv(filename, headers as unknown as CsvHeader<T>[], data)
}
