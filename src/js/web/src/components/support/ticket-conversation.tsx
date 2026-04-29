import { MessageSquare } from "lucide-react"
import { useEffect, useRef } from "react"
import { TicketMessage } from "@/components/support/ticket-message"
import { Card, CardContent } from "@/components/ui/card"
import { useTicketMessages } from "@/lib/api/hooks/support"

interface TicketConversationProps {
  ticketId: string
  scrollToBottom?: boolean
}

export function TicketConversation({ ticketId, scrollToBottom = false }: TicketConversationProps) {
  const { data: messages, isLoading, isError } = useTicketMessages(ticketId)
  const endRef = useRef<HTMLDivElement>(null)
  const prevCountRef = useRef(0)

  // Scroll to bottom when new messages arrive (not on initial load unless requested)
  useEffect(() => {
    if (!messages) return
    const isNewMessage = messages.length > prevCountRef.current && prevCountRef.current > 0
    prevCountRef.current = messages.length
    if (isNewMessage || scrollToBottom) {
      endRef.current?.scrollIntoView({ behavior: "smooth" })
    }
  }, [messages, scrollToBottom])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
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
  const replyCount = messages.filter((m) => !m.isSystemMessage).length

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <MessageSquare className="h-4 w-4" />
        <span>
          {replyCount} {replyCount === 1 ? "message" : "messages"}
        </span>
      </div>
      {messages.map((message, index) => (
        <TicketMessage
          key={message.id}
          message={message}
          ticketId={ticketId}
          isFirstMessage={index === 0 && !message.isSystemMessage}
        />
      ))}
      <div ref={endRef} />
    </div>
  )
}
