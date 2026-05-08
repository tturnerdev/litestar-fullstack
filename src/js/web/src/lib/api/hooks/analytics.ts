import { useQuery } from "@tanstack/react-query"
import {
  type CallAnalyticsSummary,
  type CallRecordDetail,
  type CallRecordList,
  type CallVolumePoint,
  type ExtensionStats,
  getCallRecord,
  getCallSummary,
  getCallsByExtension,
  getCallVolume,
  listCallRecords,
} from "@/lib/generated/api"

export type CallRecord = Required<CallRecordList>

export type { CallAnalyticsSummary, CallRecordDetail, CallRecordList, CallVolumePoint, ExtensionStats }

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
    queryFn: async () => {
      const response = await listCallRecords({
        query: {
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
        },
      })
      return response.data as { items: CallRecord[]; total: number }
    },
  })
}

// ---------------------------------------------------------------------------
// Call Record Detail
// ---------------------------------------------------------------------------

export function useCallRecord(id: string) {
  return useQuery({
    queryKey: ["analytics", "cdr", id],
    queryFn: async () => {
      const response = await getCallRecord({
        path: { cdr_id: id },
      })
      return response.data as Required<CallRecordDetail>
    },
    enabled: !!id,
  })
}

// ---------------------------------------------------------------------------
// Summary Stats
// ---------------------------------------------------------------------------

export function useAnalyticsSummary(teamId: string | undefined, startDate?: string, endDate?: string) {
  return useQuery({
    queryKey: ["analytics", "summary", teamId, startDate, endDate],
    queryFn: async () => {
      const response = await getCallSummary({
        query: { team_id: teamId ?? "", start_date: startDate ?? "", end_date: endDate ?? "" },
      })
      return response.data as Required<CallAnalyticsSummary>
    },
    enabled: !!teamId && !!startDate && !!endDate,
  })
}

// ---------------------------------------------------------------------------
// Call Volume (time-series)
// ---------------------------------------------------------------------------

export function useAnalyticsVolume(teamId: string | undefined, startDate?: string, endDate?: string, interval: string = "day") {
  return useQuery({
    queryKey: ["analytics", "volume", teamId, startDate, endDate, interval],
    queryFn: async () => {
      const response = await getCallVolume({
        query: { team_id: teamId ?? "", start_date: startDate ?? "", end_date: endDate ?? "", interval },
      })
      return response.data as Required<CallVolumePoint>[]
    },
    enabled: !!teamId && !!startDate && !!endDate,
  })
}

// ---------------------------------------------------------------------------
// Per-Extension Breakdown
// ---------------------------------------------------------------------------

export function useAnalyticsByExtension(teamId: string | undefined, startDate?: string, endDate?: string) {
  return useQuery({
    queryKey: ["analytics", "by-extension", teamId, startDate, endDate],
    queryFn: async () => {
      const response = await getCallsByExtension({
        query: { team_id: teamId ?? "", start_date: startDate ?? "", end_date: endDate ?? "" },
      })
      return response.data as Required<ExtensionStats>[]
    },
    enabled: !!teamId && !!startDate && !!endDate,
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
      const response = await listCallRecords({
        query: {
          currentPage: 1,
          pageSize: 1000,
          start_date: startDate,
          end_date: endDate,
        },
      })
      const data = response.data as { items: CallRecordList[] }
      const items = data.items ?? []

      let totalCost = 0
      let inboundCost = 0
      let outboundCost = 0
      let internalCost = 0
      let callsWithCost = 0

      const extensionCosts = new Map<string, { totalCost: number; callCount: number }>()
      const dailyCosts = new Map<string, number>()

      for (const record of items) {
        const cost = record.cost ?? 0
        if (cost > 0) {
          callsWithCost++
          totalCost += cost

          if (record.direction === "inbound") inboundCost += cost
          else if (record.direction === "outbound") outboundCost += cost
          else internalCost += cost

          const ext = record.source ?? "Unknown"
          const existing = extensionCosts.get(ext) ?? { totalCost: 0, callCount: 0 }
          existing.totalCost += cost
          existing.callCount++
          extensionCosts.set(ext, existing)
        }

        if (record.callDate) {
          const dateKey = record.callDate.split("T")[0]
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
