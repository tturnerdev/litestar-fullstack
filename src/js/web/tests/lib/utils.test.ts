import { describe, expect, it } from "vitest"
import { cn } from "@/lib/utils"

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar")
  })

  it("handles conditional classes", () => {
    expect(cn("foo", false && "bar", "baz")).toBe("foo baz")
  })

  it("handles undefined and null inputs", () => {
    expect(cn("foo", undefined, null, "bar")).toBe("foo bar")
  })

  it("returns empty string when given no arguments", () => {
    expect(cn()).toBe("")
  })

  it("deduplicates tailwind classes, keeping the last one", () => {
    expect(cn("p-4", "p-2")).toBe("p-2")
  })

  it("merges conflicting tailwind utilities", () => {
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500")
  })

  it("preserves non-conflicting tailwind utilities", () => {
    const result = cn("p-4", "m-2", "text-sm")
    expect(result).toContain("p-4")
    expect(result).toContain("m-2")
    expect(result).toContain("text-sm")
  })

  it("handles array inputs", () => {
    expect(cn(["foo", "bar"])).toBe("foo bar")
  })

  it("handles object inputs with truthy/falsy values", () => {
    expect(cn({ foo: true, bar: false, baz: true })).toBe("foo baz")
  })

  it("handles mixed types", () => {
    const result = cn("base", ["arr1", "arr2"], { obj: true })
    expect(result).toContain("base")
    expect(result).toContain("arr1")
    expect(result).toContain("arr2")
    expect(result).toContain("obj")
  })
})
