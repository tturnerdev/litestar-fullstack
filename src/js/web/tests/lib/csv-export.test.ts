import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import {
  buildCsvString,
  buildCsvStringWithAccessors,
  escapeCSVCell,
  exportToCsv,
  exportToCSV,
} from "@/lib/csv-export"

describe("escapeCSVCell", () => {
  it("returns plain values unchanged", () => {
    expect(escapeCSVCell("hello")).toBe("hello")
    expect(escapeCSVCell(42)).toBe("42")
  })

  it("wraps values containing commas in double quotes", () => {
    expect(escapeCSVCell("hello, world")).toBe('"hello, world"')
  })

  it("escapes double quotes by doubling them", () => {
    expect(escapeCSVCell('she said "hi"')).toBe('"she said ""hi"""')
  })

  it("wraps values containing newlines in double quotes", () => {
    expect(escapeCSVCell("line1\nline2")).toBe('"line1\nline2"')
  })

  it("treats null and undefined as empty strings", () => {
    expect(escapeCSVCell(null)).toBe("")
    expect(escapeCSVCell(undefined)).toBe("")
  })
})

describe("buildCsvString (key-based)", () => {
  it("builds a CSV with header and data rows", () => {
    const data = [
      { name: "Alice", age: 30 },
      { name: "Bob", age: 25 },
    ]

    const csv = buildCsvString(data, ["name", "age"])
    const lines = csv.split("\n")

    expect(lines[0]).toBe("name,age")
    expect(lines[1]).toBe("Alice,30")
    expect(lines[2]).toBe("Bob,25")
  })

  it("only exports listed columns", () => {
    const data = [{ name: "Alice", age: 30, secret: "hidden" }]

    const csv = buildCsvString(data, ["name", "age"])

    expect(csv).toContain("name,age")
    expect(csv).toContain("Alice,30")
    expect(csv).not.toContain("secret")
    expect(csv).not.toContain("hidden")
  })

  it("escapes values containing commas", () => {
    const data = [{ note: "hello, world" }]
    const csv = buildCsvString(data, ["note"])

    expect(csv).toContain('"hello, world"')
  })

  it("escapes values containing double quotes", () => {
    const data = [{ note: 'she said "hi"' }]
    const csv = buildCsvString(data, ["note"])

    expect(csv).toContain('"she said ""hi"""')
  })

  it("handles null and undefined values as empty strings", () => {
    const data = [{ a: null, b: undefined, c: "ok" }]
    const csv = buildCsvString(data as Record<string, unknown>[], ["a", "b", "c"])
    const lines = csv.split("\n")

    expect(lines[1]).toBe(",,ok")
  })
})

describe("buildCsvStringWithAccessors", () => {
  it("uses accessor functions to extract values", () => {
    interface User {
      firstName: string
      lastName: string
      age: number
    }

    const data: User[] = [
      { firstName: "Alice", lastName: "Smith", age: 30 },
      { firstName: "Bob", lastName: "Jones", age: 25 },
    ]

    const columns = [
      { header: "Full Name", accessor: (row: User) => `${row.firstName} ${row.lastName}` },
      { header: "Age", accessor: (row: User) => row.age },
    ]

    const csv = buildCsvStringWithAccessors(data, columns)
    const lines = csv.split("\n")

    expect(lines[0]).toBe("Full Name,Age")
    expect(lines[1]).toBe("Alice Smith,30")
    expect(lines[2]).toBe("Bob Jones,25")
  })

  it("escapes header labels that contain special characters", () => {
    const data = [{ v: 1 }]
    const columns = [{ header: 'Name, "Quoted"', accessor: (row: { v: number }) => row.v }]

    const csv = buildCsvStringWithAccessors(data, columns)

    expect(csv).toContain('"Name, ""Quoted"""')
  })
})

describe("exportToCSV / exportToCsv (download behaviour)", () => {
  let clickSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    clickSpy = vi.fn()

    vi.spyOn(document, "createElement").mockReturnValue({
      href: "",
      download: "",
      click: clickSpy,
    } as unknown as HTMLElement)

    vi.spyOn(document.body, "appendChild").mockImplementation((node) => node)
    vi.spyOn(document.body, "removeChild").mockImplementation((node) => node)

    globalThis.URL.createObjectURL = vi.fn().mockReturnValue("blob:mock-url")
    globalThis.URL.revokeObjectURL = vi.fn()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it("exportToCSV triggers a download when data is non-empty", () => {
    const data = [{ name: "Alice" }]

    exportToCSV(data, "users")

    expect(globalThis.URL.createObjectURL).toHaveBeenCalledOnce()
    expect(clickSpy).toHaveBeenCalledOnce()
    expect(globalThis.URL.revokeObjectURL).toHaveBeenCalledOnce()
  })

  it("exportToCSV does not throw or download when data is empty", () => {
    expect(() => exportToCSV([], "empty")).not.toThrow()
    expect(globalThis.URL.createObjectURL).not.toHaveBeenCalled()
  })

  it("exportToCsv triggers a download when data is non-empty", () => {
    const data = [{ v: 1 }]
    const columns = [{ label: "Value", accessor: (row: { v: number }) => row.v }]

    exportToCsv("values", columns, data)

    expect(globalThis.URL.createObjectURL).toHaveBeenCalledOnce()
    expect(clickSpy).toHaveBeenCalledOnce()
  })

  it("exportToCsv does not throw or download when data is empty", () => {
    expect(() =>
      exportToCsv("empty", [{ label: "X", accessor: () => "" }], []),
    ).not.toThrow()
    expect(globalThis.URL.createObjectURL).not.toHaveBeenCalled()
  })
})
