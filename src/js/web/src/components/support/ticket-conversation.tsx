import { ArrowDown, ArrowUp, Filter, Loader2, MessageSquare } from "lucide-react"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { TicketMessage } from "@/components/support/ticket-message"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { useTicketMessages } from "@/lib/api/hooks/support"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

interface TicketConversationProps {
  ticketId: string
  scrollToBottom?: boolean
  /** Index of the first unread message (0-based). Pass undefined if all are read. */
  firstUnreadIndex?: number
}

// ── Helpers ───────────────────────────────────────────────────────────────

function formatDateLabel(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const messageDay = new Date(date.getFullYear(), date.getMonth(), date.getDate())
  const diffDays = Math.round((today.getTime() - messageDay.getTime()) / (1000 * 60 * 60 * 24))

  if (diffDays === 0) return "Today"
  if (diffDays === 1) return "Yesterday"
  return date.toLocaleDateString(undefined, {
    month: "long",
    day: "numeric",
    year: date.getFullYear() !== now.getFullYear() ? "numeric" : undefined,
  })
}

function getDateKey(dateStr: string | null | undefined): string {
  if (!dateStr) return ""
  const d = new Date(dateStr)
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}

// ── Component ─────────────────────────────────────────────────────────────

export function TicketConversation({
  ticketId,
  scrollToBottom = false,
  firstUnreadIndex,
}: TicketConversationProps) {
  const { data: messages, isLoading, isError } = useTicketMessages(ticketId)
  const isSuperuser = useAuthStore((s) => s.user?.isSuperuser === true)
  const containerRef = useRef<HTMLDivElement>(null)
  const endRef = useRef<HTMLDivElement>(null)
  const topRef = useRef<HTMLDivElement>(null)
  const prevCountRef = useRef(0)

  const [hideSystem, setHideSystem] = useState(false)
  const [isNearBottom, setIsNearBottom] = useState(true)
  const [isNearTop, setIsNearTop] = useState(true)

  // Track scroll position relative to the container
  const handleScroll = useCallback(() => {
    const el = containerRef.current
    if (!el) return
    const threshold = 120
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight
    const distanceFromTop = el.scrollTop
    setIsNearBottom(distanceFromBottom <= threshold)
    setIsNearTop(distanceFromTop <= threshold)
  }, [])

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    el.addEventListener("scroll", handleScroll, { passive: true })
    return () => el.removeEventListener("scroll", handleScroll)
  }, [handleScroll])

  // Scroll to bottom when new messages arrive (not on initial load unless requested)
  useEffect(() => {
    if (!messages) return
    const isNewMessage = messages.length > prevCountRef.current && prevCountRef.current > 0
    prevCountRef.current = messages.length
    if (isNewMessage || scrollToBottom) {
      endRef.current?.scrollIntoView({ behavior: "smooth" })
    }
  }, [messages, scrollToBottom])

  // Filter messages: hide internal notes for non-superusers, optionally hide system messages
  const visibleMessages = useMemo(() => {
    if (!messages) return []
    return messages.filter((m) => {
      if (m.isInternalNote && !isSuperuser) return false
      if (m.isSystemMessage && hideSystem) return false
      return true
    })
  }, [messages, hideSystem, isSuperuser])

  const scrollToEnd = useCallback(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [])

  const scrollToTop = useCallback(() => {
    topRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-sm text-muted-foreground">Loading messages...</p>
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <Card className="border-dashed border-destructive/30 bg-destructive/5">
        <CardContent className="py-12 text-center">
          <p className="text-muted-foreground">We couldn't load messages. Try refreshing.</p>
        </CardContent>
      </Card>
    )
  }

  if (!messages || messages.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted/50">
            <MessageSquare className="h-6 w-6 text-muted-foreground" />
          </div>
          <div>
            <p className="font-medium text-muted-foreground">No messages yet</p>
            <p className="mt-1 text-sm text-muted-foreground/70">
              Be the first to reply to this ticket.
            </p>
          </div>
        </CardContent>
      </Card>
    )
  }

  // Count non-system messages for the header
  const totalCount = messages.length
  const replyCount = messages.filter((m) => !m.isSystemMessage).length
  const systemCount = totalCount - replyCount
  const isLongConversation = visibleMessages.length > 5

  return (
    <div className="relative">
      {/* Header with count + filter toggle */}
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <MessageSquare className="h-4 w-4" />
          <span>
            {hideSystem ? replyCount : totalCount}{" "}
            {(hideSystem ? replyCount : totalCount) === 1 ? "message" : "messages"}
          </span>
          {hideSystem && systemCount > 0 && (
            <Badge variant="secondary" className="h-5 px-1.5 text-[10px]">
              {systemCount} system hidden
            </Badge>
          )}
        </div>

        {systemCount > 0 && (
          <Button
            variant={hideSystem ? "secondary" : "ghost"}
            size="sm"
            className="h-7 gap-1.5 text-xs"
            onClick={() => setHideSystem((prev) => !prev)}
          >
            <Filter className="h-3 w-3" />
            {hideSystem ? "Show all" : "Hide system"}
          </Button>
        )}
      </div>

      {/* Scrollable message area */}
      <div
        ref={containerRef}
        className="relative max-h-[70vh] space-y-4 overflow-y-auto scroll-smooth"
      >
        <div ref={topRef} />
        {visibleMessages.map((message, index) => {
          const currentDateKey = getDateKey(message.createdAt)
          const prevDateKey = index > 0 ? getDateKey(visibleMessages[index - 1].createdAt) : null
          const showDateSeparator = index === 0 || currentDateKey !== prevDateKey

          // Show unread indicator if this is the first unread message.
          // We map the original `firstUnreadIndex` into the visible list.
          const originalIndex = messages.indexOf(message)
          const showUnreadLine =
            firstUnreadIndex !== undefined &&
            originalIndex === firstUnreadIndex &&
            originalIndex > 0

          return (
            <div key={message.id}>
              {/* Date separator */}
              {showDateSeparator && message.createdAt && (
                <div className="flex items-center gap-3 py-2">
                  <div className="h-px flex-1 bg-border" />
                  <span className="shrink-0 text-xs font-medium text-muted-foreground">
                    {formatDateLabel(message.createdAt)}
                  </span>
                  <div className="h-px flex-1 bg-border" />
                </div>
              )}

              {/* Unread indicator */}
              {showUnreadLine && (
                <div className="flex items-center gap-3 py-1">
                  <div className="h-px flex-1 bg-primary/50" />
                  <span className="shrink-0 text-xs font-semibold text-primary">
                    New messages below
                  </span>
                  <div className="h-px flex-1 bg-primary/50" />
                </div>
              )}

              {/* Message with entrance animation */}
              <div
                className={cn(
                  "animate-in fade-in slide-in-from-bottom-2 duration-300 fill-mode-backwards",
                  // Stagger delay for the last few messages only (prevents slow initial render)
                  index >= visibleMessages.length - 3 &&
                    prevCountRef.current > 0 &&
                    "delay-75",
                )}
              >
                <TicketMessage
                  message={message}
                  ticketId={ticketId}
                  isFirstMessage={originalIndex === 0 && !message.isSystemMessage}
                />
              </div>
            </div>
          )
        })}
        <div ref={endRef} />
      </div>

      {/* Jump to latest floating button */}
      {isLongConversation && !isNearBottom && (
        <div className="pointer-events-none absolute bottom-4 left-0 right-0 flex justify-center">
          <Button
            size="sm"
            variant="secondary"
            className="pointer-events-auto h-8 gap-1.5 rounded-full shadow-md text-xs"
            onClick={scrollToEnd}
          >
            <ArrowDown className="h-3.5 w-3.5" />
            Jump to latest
          </Button>
        </div>
      )}

      {/* Scroll to top button (fixed at bottom-right, visible when scrolled far from top) */}
      {isLongConversation && !isNearTop && (
        <div className="pointer-events-none absolute right-2 top-12 flex justify-end">
          <Button
            size="sm"
            variant="outline"
            className="pointer-events-auto h-7 w-7 rounded-full p-0 shadow-sm"
            onClick={scrollToTop}
          >
            <ArrowUp className="h-3.5 w-3.5" />
          </Button>
        </div>
      )}
    </div>
  )
}
