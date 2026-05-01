import { useQuery } from "@tanstack/react-query"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CallRecord {
  id: string
  startedAt: string
  endedAt: string | null
  direction: "inbound" | "outbound" | "internal"
  source: string
  destination: string
  disposition: "answered" | "missed" | "voicemail" | "busy" | "failed" | "no_answer"
  durationSeconds: number
  billableSeconds: number
  cost: number | null
  channel: string | null
  uniqueId: string | null
  linkedId: string | null
  recordingUrl: string | null
  extensionId: string | null
  extensionNumber: string | null
  notes: string | null
  createdAt: string | null
  updatedAt: string | null
}

export interface AnalyticsSummary {
  totalCalls: number
  answered: number
  missed: number
  voicemail: number
  avgDuration: number
  totalDuration: number
  avgBillableSeconds: number
}

export interface VolumeDataPoint {
  period: string
  count: number
  answered: number
  missed: number
}

export interface ExtensionStats {
  extension: string
  totalCalls: number
  answered: number
  missed: number
  avgDuration: number
}

interface PaginatedResponse<T> {
  items: T[]
  total: number
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T> {
  const config = client.getConfig()
  const baseUrl = config.baseUrl ?? ""
  const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
  const response = await fetch(`${baseUrl}${url}`, {
    credentials: "include",
    ...options,
    headers: { ...headers, ...(options?.headers as Record<string, string>) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return undefined as unknown as T
  return response.json()
}

function buildQueryString(params: Record<string, string | number | undefined>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== "",
  )
  if (entries.length === 0) return ""
  return `?${entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join("&")}`
}

// ---------------------------------------------------------------------------
// Call Records (CDR list)
// ---------------------------------------------------------------------------

export interface UseCallRecordsFilters {
  page?: number
  pageSize?: number
  startDate?: string
  endDate?: string
  direction?: string
  disposition?: string
  source?: string
  destination?: string
  minDuration?: number
  maxDuration?: number
}

export function useCallRecords(filters: UseCallRecordsFilters = {}) {
  const {
    page = 1,
    pageSize = 25,
    startDate,
    endDate,
    direction,
    disposition,
    source,
    destination,
    minDuration,
    maxDuration,
  } = filters

  return useQuery({
    queryKey: [
      "analytics",
      "cdrs",
      page,
      pageSize,
      startDate,
      endDate,
      direction,
      disposition,
      source,
      destination,
      minDuration,
      maxDuration,
    ],
    queryFn: () =>
      apiFetch<PaginatedResponse<CallRecord>>(
        `/api/analytics/cdrs${buildQueryString({
          currentPage: page,
          pageSize,
          start_date: startDate,
          end_date: endDate,
          direction,
          disposition,
          source,
          destination,
          min_duration: minDuration,
          max_duration: maxDuration,
        })}`,
      ),
  })
}

// ---------------------------------------------------------------------------
// Call Record Detail
// ---------------------------------------------------------------------------

export function useCallRecord(id: string) {
  return useQuery({
    queryKey: ["analytics", "cdr", id],
    queryFn: () => apiFetch<CallRecord>(`/api/analytics/cdrs/${id}`),
    enabled: !!id,
  })
}

// ---------------------------------------------------------------------------
// Summary Stats
// ---------------------------------------------------------------------------

export function useAnalyticsSummary(startDate?: string, endDate?: string) {
  return useQuery({
    queryKey: ["analytics", "summary", startDate, endDate],
    queryFn: () =>
      apiFetch<AnalyticsSummary>(
        `/api/analytics/summary${buildQueryString({
          start_date: startDate,
          end_date: endDate,
        })}`,
      ),
    enabled: !!startDate && !!endDate,
  })
}

// ---------------------------------------------------------------------------
// Call Volume (time-series)
// ---------------------------------------------------------------------------

export function useAnalyticsVolume(
  startDate?: string,
  endDate?: string,
  interval: "hour" | "day" | "week" | "month" = "day",
) {
  return useQuery({
    queryKey: ["analytics", "volume", startDate, endDate, interval],
    queryFn: () =>
      apiFetch<PaginatedResponse<VolumeDataPoint>>(
        `/api/analytics/volume${buildQueryString({
          start_date: startDate,
          end_date: endDate,
          interval,
        })}`,
      ),
    enabled: !!startDate && !!endDate,
  })
}

// ---------------------------------------------------------------------------
// Per-Extension Breakdown
// ---------------------------------------------------------------------------

export function useAnalyticsByExtension(startDate?: string, endDate?: string) {
  return useQuery({
    queryKey: ["analytics", "by-extension", startDate, endDate],
    queryFn: () =>
      apiFetch<PaginatedResponse<ExtensionStats>>(
        `/api/analytics/by-extension${buildQueryString({
          start_date: startDate,
          end_date: endDate,
        })}`,
      ),
    enabled: !!startDate && !!endDate,
  })
}
