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
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== "")
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
  const { page = 1, pageSize = 25, startDate, endDate, direction, disposition, source, destination, minDuration, maxDuration } = filters

  return useQuery({
    queryKey: ["analytics", "cdrs", page, pageSize, startDate, endDate, direction, disposition, source, destination, minDuration, maxDuration],
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

export function useAnalyticsVolume(startDate?: string, endDate?: string, interval: "hour" | "day" | "week" | "month" = "day") {
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

// ---------------------------------------------------------------------------
// Cost Analysis (aggregated from CDR data)
// ---------------------------------------------------------------------------

export interface CostSummary {
  totalCost: number
  avgCostPerCall: number
  inboundCost: number
  outboundCost: number
  internalCost: number
  callsWithCost: number
  totalCalls: number
}

export interface CostByExtension {
  extension: string
  totalCost: number
  callCount: number
}

export interface DailyCost {
  date: string
  cost: number
  label: string
}

export function useAnalyticsCostBreakdown(startDate?: string, endDate?: string) {
  return useQuery({
    queryKey: ["analytics", "cost-breakdown", startDate, endDate],
    queryFn: async () => {
      // Fetch a large page of CDRs to aggregate cost data
      const data = await apiFetch<PaginatedResponse<CallRecord>>(
        `/api/analytics/cdrs${buildQueryString({
          currentPage: 1,
          pageSize: 1000,
          start_date: startDate,
          end_date: endDate,
        })}`,
      )

      const items = data.items ?? []

      // Cost summary
      let totalCost = 0
      let inboundCost = 0
      let outboundCost = 0
      let internalCost = 0
      let callsWithCost = 0

      // Cost by extension
      const extensionCosts = new Map<string, { totalCost: number; callCount: number }>()

      // Daily cost
      const dailyCosts = new Map<string, number>()

      for (const record of items) {
        const cost = record.cost ?? 0
        if (cost > 0) {
          callsWithCost++
          totalCost += cost

          if (record.direction === "inbound") inboundCost += cost
          else if (record.direction === "outbound") outboundCost += cost
          else internalCost += cost

          // By extension
          const ext = record.extensionNumber ?? "Unknown"
          const existing = extensionCosts.get(ext) ?? { totalCost: 0, callCount: 0 }
          existing.totalCost += cost
          existing.callCount++
          extensionCosts.set(ext, existing)
        }

        // Daily cost (include zero-cost days for continuity)
        if (record.startedAt) {
          const dateKey = record.startedAt.split("T")[0]
          dailyCosts.set(dateKey, (dailyCosts.get(dateKey) ?? 0) + cost)
        }
      }

      const summary: CostSummary = {
        totalCost,
        avgCostPerCall: items.length > 0 ? totalCost / items.length : 0,
        inboundCost,
        outboundCost,
        internalCost,
        callsWithCost,
        totalCalls: items.length,
      }

      const byExtension: CostByExtension[] = Array.from(extensionCosts.entries())
        .map(([extension, stats]) => ({ extension, ...stats }))
        .sort((a, b) => b.totalCost - a.totalCost)
        .slice(0, 10)

      const dailyTrend: DailyCost[] = Array.from(dailyCosts.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([date, cost]) => {
          const d = new Date(date)
          return {
            date,
            cost,
            label: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
          }
        })

      return { summary, byExtension, dailyTrend }
    },
    enabled: !!startDate && !!endDate,
  })
}
