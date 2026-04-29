import { beforeEach, describe, expect, it } from "vitest"
import { DEFAULT_AUTH_REDIRECT, buildRedirectUrl, getSafeRedirectUrl, validateRedirectUrl } from "@/lib/redirect-utils"

describe("validateRedirectUrl", () => {
  it("accepts valid relative paths", () => {
    expect(validateRedirectUrl("/home")).toBe("/home")
    expect(validateRedirectUrl("/dashboard/settings")).toBe("/dashboard/settings")
  })

  it("preserves query strings and hashes", () => {
    expect(validateRedirectUrl("/page?foo=bar")).toBe("/page?foo=bar")
    expect(validateRedirectUrl("/page#section")).toBe("/page#section")
    expect(validateRedirectUrl("/page?a=1#top")).toBe("/page?a=1#top")
  })

  it("returns null for null/undefined/empty inputs", () => {
    expect(validateRedirectUrl(null)).toBeNull()
    expect(validateRedirectUrl(undefined)).toBeNull()
    expect(validateRedirectUrl("")).toBeNull()
  })

  it("rejects absolute URLs (no leading slash)", () => {
    expect(validateRedirectUrl("https://evil.com")).toBeNull()
    expect(validateRedirectUrl("http://evil.com")).toBeNull()
    expect(validateRedirectUrl("example.com/path")).toBeNull()
  })

  it("rejects protocol-relative URLs", () => {
    expect(validateRedirectUrl("//evil.com")).toBeNull()
  })

  it("rejects javascript: protocol", () => {
    expect(validateRedirectUrl("/path?javascript:alert(1)")).toBeNull()
  })

  it("rejects data: protocol", () => {
    expect(validateRedirectUrl("/path?data:text/html,<script>")).toBeNull()
  })

  it("rejects vbscript: protocol", () => {
    expect(validateRedirectUrl("/path?vbscript:exec")).toBeNull()
  })
})

describe("getSafeRedirectUrl", () => {
  it("returns validated URL when valid", () => {
    expect(getSafeRedirectUrl("/dashboard")).toBe("/dashboard")
  })

  it("returns default redirect for invalid URL", () => {
    expect(getSafeRedirectUrl("https://evil.com")).toBe(DEFAULT_AUTH_REDIRECT)
  })

  it("returns default redirect for null", () => {
    expect(getSafeRedirectUrl(null)).toBe(DEFAULT_AUTH_REDIRECT)
  })

  it("returns custom fallback when provided", () => {
    expect(getSafeRedirectUrl(null, "/custom")).toBe("/custom")
  })

  it("uses DEFAULT_AUTH_REDIRECT which is /home", () => {
    expect(DEFAULT_AUTH_REDIRECT).toBe("/home")
  })
})

describe("buildRedirectUrl", () => {
  it("appends encoded redirect parameter for valid URLs", () => {
    const result = buildRedirectUrl("/login", "/dashboard")
    expect(result).toBe("/login?redirect=%2Fdashboard")
  })

  it("returns base path alone for invalid redirect URL", () => {
    expect(buildRedirectUrl("/login", "https://evil.com")).toBe("/login")
  })

  it("returns base path alone for null redirect", () => {
    expect(buildRedirectUrl("/login", null)).toBe("/login")
  })

  it("returns base path alone for undefined redirect", () => {
    expect(buildRedirectUrl("/login", undefined)).toBe("/login")
  })

  it("properly encodes special characters in redirect", () => {
    const result = buildRedirectUrl("/login", "/page?foo=bar&baz=1")
    expect(result).toContain("/login?redirect=")
    expect(result).toContain(encodeURIComponent("/page?foo=bar&baz=1"))
  })
})
