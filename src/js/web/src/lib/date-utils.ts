interface TimeDifferences {
  seconds: number
  minutes: number
  hours: number
  days: number
}

function getTimeDifferences(dateStr: string): TimeDifferences {
  const diffMs = Date.now() - new Date(dateStr).getTime()
  const seconds = Math.floor(diffMs / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  return { seconds, minutes, hours, days }
}

export function formatRelativeTime(dateStr: string | null | undefined): string {
  if (!dateStr) return "Never"
  const { seconds, minutes, hours, days } = getTimeDifferences(dateStr)

  if (seconds < 60) return "Just now"
  if (minutes === 1) return "1 minute ago"
  if (minutes < 60) return `${minutes} minutes ago`
  if (hours === 1) return "1 hour ago"
  if (hours < 24) return `${hours} hours ago`
  if (days === 1) return "1 day ago"
  if (days < 30) return `${days} days ago`
  const months = Math.floor(days / 30)
  if (months === 1) return "1 month ago"
  return `${months} months ago`
}

export function formatRelativeTimeShort(dateStr: string | null | undefined): string {
  if (!dateStr) return "Never"
  const { seconds, minutes, hours, days } = getTimeDifferences(dateStr)

  if (seconds < 60) return "Just now"
  if (minutes < 60) return `${minutes}m ago`
  if (hours < 24) return `${hours}h ago`
  if (days < 7) return `${days}d ago`
  const weeks = Math.floor(days / 7)
  if (weeks < 5) return `${weeks}w ago`
  const months = Math.floor(days / 30)
  return `${months}mo ago`
}

export function formatFullDateTime(dateStr: string): string {
  return new Date(dateStr).toLocaleString(undefined, {
    weekday: "short",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  })
}

/**
 * Format a date string using the browser's default locale string.
 * Returns "---" (or a custom fallback) for null/undefined input.
 */
export function formatDateTime(dateStr: string | null | undefined, fallback = "---", options?: Intl.DateTimeFormatOptions): string {
  if (!dateStr) return fallback
  return new Date(dateStr).toLocaleString(undefined, options)
}

/**
 * Format a future date as a relative duration (e.g. "in 3 minutes", "in 1 hour").
 * Returns `null` if the date is in the past or invalid.
 */
export function formatRelativeFuture(dateStr: string | null | undefined): string | null {
  if (!dateStr) return null
  const diffMs = new Date(dateStr).getTime() - Date.now()
  if (diffMs <= 0) return null

  const seconds = Math.floor(diffMs / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)

  if (seconds < 60) return "in a few seconds"
  if (minutes === 1) return "in 1 minute"
  if (minutes < 60) return `in ${minutes} minutes`
  if (hours === 1) return "in 1 hour"
  return `in ${hours} hours`
}

/**
 * Format a date string as a long-form date (e.g. "January 15, 2026").
 * Returns the raw string on parse failure.
 */
export function formatDateLong(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    })
  } catch {
    return dateStr
  }
}
