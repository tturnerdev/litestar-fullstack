/**
 * Shared formatting utilities for phone numbers, file sizes, etc.
 */

/**
 * Format a US phone number as (XXX) XXX-XXXX.
 * Handles raw digits, +1-prefixed, and already-formatted inputs.
 * Non-US numbers are returned as-is.
 */
export function formatPhoneNumber(phone: string | null | undefined): string {
  if (!phone) return "—"
  const digits = phone.replace(/\D/g, "")
  const national =
    digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits
  if (national.length === 10) {
    return `(${national.slice(0, 3)}) ${national.slice(3, 6)}-${national.slice(6)}`
  }
  return phone
}

/**
 * Format a byte count into a human-readable string (e.g. "1.5 MB").
 */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || bytes === 0) return "0 B"
  const k = 1024
  const sizes = ["B", "KB", "MB", "GB"]
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${Number.parseFloat((bytes / k ** i).toFixed(1))} ${sizes[i]}`
}
