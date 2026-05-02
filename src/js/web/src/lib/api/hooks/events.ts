import { useQueryClient } from "@tanstack/react-query"
import { useCallback, useEffect, useRef } from "react"
import { toast } from "sonner"
import { client } from "@/lib/generated/api/client.gen"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TaskEventData {
  taskId: string
  taskType: string
  status: string
  progress?: number
  result?: Record<string, unknown>
  errorMessage?: string
  entityType?: string
  entityId?: string
}

interface DeviceStatusEventData {
  deviceId: string
  status: string
  previousStatus: string
  deviceName: string
}

interface EntityUpdatedEventData {
  entityType: string
  entityId: string
  action: string
}

interface NotificationEventData {
  notificationId: string
  title?: string
  category?: string
  actionUrl?: string | null
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TASK_TYPE_LABELS: Record<string, string> = {
  "device.reboot": "Device Reboot",
  "device.provision": "Device Provisioning",
  "device.reprovision": "Device Reprovisioning",
  "extension.create": "Extension Creation",
  "extension.update": "Extension Update",
  "extension.delete": "Extension Deletion",
  "fax.send": "Fax Send",
  "fax.receive_process": "Fax Processing",
}

/** Maximum delay between reconnection attempts (30 seconds). */
const MAX_RECONNECT_DELAY_MS = 30_000

/** Base delay for exponential backoff (1 second). */
const BASE_RECONNECT_DELAY_MS = 1_000

// ---------------------------------------------------------------------------
// Fetch-based SSE reader
// ---------------------------------------------------------------------------

/**
 * Reads an SSE stream from a `fetch` Response and dispatches parsed events
 * via the provided callback.  Using `fetch` instead of `EventSource` lets us
 * send a Bearer token in the `Authorization` header.
 */
async function readSSEStream(response: Response, onEvent: (eventType: string, data: string) => void, signal: AbortSignal): Promise<void> {
  const reader = response.body?.getReader()
  if (!reader) return

  const decoder = new TextDecoder()
  let buffer = ""
  let currentEvent = ""
  let currentData = ""

  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })

      const lines = buffer.split("\n")
      // Keep the last (potentially incomplete) line in the buffer
      buffer = lines.pop() ?? ""

      for (const line of lines) {
        if (line.startsWith("event:")) {
          currentEvent = line.slice(6).trim()
        } else if (line.startsWith("data:")) {
          currentData = line.slice(5).trim()
        } else if (line === "") {
          // Empty line = end of an event block
          if (currentEvent && currentData) {
            onEvent(currentEvent, currentData)
          }
          currentEvent = ""
          currentData = ""
        }
        // Ignore comment lines (starting with ':') and unknown prefixes
      }
    }
  } finally {
    reader.releaseLock()
  }
}

// ---------------------------------------------------------------------------
// SSE connection status — importable by other hooks (e.g. tasks.ts) to adjust
// polling frequency when the real-time event stream is unavailable.
// ---------------------------------------------------------------------------

/**
 * Module-level indicator of SSE connectivity.
 *
 * - `connected` — `true` once the stream is actively reading events; `false`
 *   when the connection drops or is being re-established.
 * - `disconnectedSince` — timestamp (ms) of the most recent disconnect, or
 *   `null` while connected.  Consumers can compare against `Date.now()` to
 *   decide whether to ramp up polling (e.g. only after 60 s of downtime).
 */
export const sseStatus = {
  connected: false,
  disconnectedSince: null as number | null,
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Establishes a persistent SSE connection to `/api/events/stream` and
 * performs React Query cache invalidation + toast notifications based on
 * incoming server-sent events.
 *
 * Should be called once at the top of the authenticated app layout so the
 * connection lives for the duration of the user session.
 */
export function useEventStream() {
  const queryClient = useQueryClient()
  const abortRef = useRef<AbortController | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>(undefined)
  const reconnectAttemptRef = useRef(0)
  const mountedRef = useRef(true)

  // ----- event handler -----

  const handleEvent = useCallback(
    (eventType: string, raw: string) => {
      let data: Record<string, unknown>
      try {
        data = JSON.parse(raw)
      } catch {
        return
      }

      switch (eventType) {
        // ---- Task lifecycle --------------------------------------------------
        case "task.updated": {
          queryClient.invalidateQueries({ queryKey: ["tasks"] })
          break
        }

        case "task.completed": {
          const d = data as unknown as TaskEventData
          queryClient.invalidateQueries({ queryKey: ["tasks"] })
          // Also invalidate the entity collection that was affected
          if (d.entityType) {
            queryClient.invalidateQueries({ queryKey: [`${d.entityType}s`] })
          }
          const label = TASK_TYPE_LABELS[d.taskType] || d.taskType
          toast.success(`${label} completed`, {
            description: "The background task finished successfully.",
          })
          break
        }

        case "task.failed": {
          const d = data as unknown as TaskEventData
          queryClient.invalidateQueries({ queryKey: ["tasks"] })
          const label = TASK_TYPE_LABELS[d.taskType] || d.taskType
          toast.error(`${label} failed`, {
            description: d.errorMessage || "The background task encountered an error.",
          })
          break
        }

        // ---- Device status ---------------------------------------------------
        case "device.status_changed": {
          const d = data as unknown as DeviceStatusEventData
          queryClient.invalidateQueries({ queryKey: ["devices"] })
          if (d.deviceId) {
            queryClient.invalidateQueries({ queryKey: ["device", d.deviceId] })
          }
          if (d.status === "online" && d.previousStatus !== "online") {
            toast.success(`${d.deviceName} is back online`)
          }
          break
        }

        // ---- Generic entity update -------------------------------------------
        case "entity.updated": {
          const d = data as unknown as EntityUpdatedEventData
          const listKeys: Record<string, string[]> = {
            device: ["devices"],
            extension: ["voice", "extensions"],
            phone_number: ["voice", "phone-numbers"],
            location: ["locations"],
            connection: ["connections"],
            fax_number: ["fax", "numbers"],
            ticket: ["tickets"],
          }
          const listKey = listKeys[d.entityType]
          if (listKey) {
            queryClient.invalidateQueries({ queryKey: listKey })
          }
          if (d.entityId) {
            queryClient.invalidateQueries({ queryKey: [d.entityType, d.entityId] })
          }
          break
        }

        // ---- Notifications ---------------------------------------------------
        case "notification.created": {
          const d = data as unknown as NotificationEventData
          queryClient.invalidateQueries({ queryKey: ["notifications"] })
          queryClient.invalidateQueries({ queryKey: ["notifications", "unread-count"] })
          if (d.title) {
            toast.info(d.title, {
              description: d.category ? `Category: ${d.category}` : undefined,
            })
          }
          break
        }

        default:
          // Unknown events are silently ignored
          break
      }
    },
    [queryClient],
  )

  // ----- connect / reconnect -----

  const connect = useCallback(() => {
    if (!mountedRef.current) return

    // Abort any existing connection before opening a new one
    abortRef.current?.abort()

    const controller = new AbortController()
    abortRef.current = controller

    const config = client.getConfig()
    const baseUrl = (config.baseUrl ?? "") as string
    const token = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null

    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }

    fetch(`${baseUrl}/api/events/stream`, {
      headers,
      credentials: "include",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`SSE connection failed (${response.status})`)
        }
        // Connection established -- reset the backoff counter
        reconnectAttemptRef.current = 0
        sseStatus.connected = true
        sseStatus.disconnectedSince = null
        await readSSEStream(response, handleEvent, controller.signal)
        // Stream ended normally (server closed) -- reconnect
        sseStatus.connected = false
        sseStatus.disconnectedSince ??= Date.now()
        if (mountedRef.current) {
          scheduleReconnect()
        }
      })
      .catch((err) => {
        // AbortError means we intentionally cancelled -- do not reconnect
        if (err instanceof DOMException && err.name === "AbortError") return
        sseStatus.connected = false
        sseStatus.disconnectedSince ??= Date.now()
        if (mountedRef.current) {
          scheduleReconnect()
        }
      })
  }, [handleEvent])

  const scheduleReconnect = useCallback(() => {
    const delay = Math.min(BASE_RECONNECT_DELAY_MS * 2 ** reconnectAttemptRef.current, MAX_RECONNECT_DELAY_MS)
    reconnectAttemptRef.current++
    reconnectTimeoutRef.current = setTimeout(connect, delay)
  }, [connect])

  // ----- lifecycle -----

  useEffect(() => {
    mountedRef.current = true
    connect()

    return () => {
      mountedRef.current = false
      abortRef.current?.abort()
      sseStatus.connected = false
      sseStatus.disconnectedSince ??= Date.now()
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
    }
  }, [connect])
}
