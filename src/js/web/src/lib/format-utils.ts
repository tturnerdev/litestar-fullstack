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

/**
 * Format a duration in seconds as MM:SS (e.g. "2:05").
 */
export function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  return `${mins}:${secs.toString().padStart(2, "0")}`
}

/**
 * Format a duration in seconds as human-readable text.
 * Examples: "45 seconds", "2 minutes", "1m 30s"
 */
export function formatDurationHuman(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  if (secs === 0) return mins === 1 ? "1 minute" : `${mins} minutes`
  return `${mins}m ${secs}s`
}

/**
 * Auto-format a raw MAC string into XX:XX:XX:XX:XX:XX as the user types.
 * Strips non-hex characters, uppercases, and inserts colons every 2 chars.
 */
export function formatMacAddress(raw: string): string {
  const hex = raw.replace(/[^0-9A-Fa-f]/g, "").toUpperCase().slice(0, 12)
  const parts: string[] = []
  for (let i = 0; i < hex.length; i += 2) {
    parts.push(hex.slice(i, i + 2))
  }
  return parts.join(":")
}
