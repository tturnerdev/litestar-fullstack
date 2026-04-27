import { Card, CardContent } from "@/components/ui/card"
import { useTicketMessages } from "@/lib/api/hooks/support"
import { TicketMessage } from "@/components/support/ticket-message"

export function TicketConversation({ ticketId }: { ticketId: string }) {
  const { data: messages, isLoading, isError } = useTicketMessages(ticketId)

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
        <CardContent className="py-12 text-center">
          <p className="text-muted-foreground">No messages yet.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {messages.map((message) => (
        <TicketMessage key={message.id} message={message} />
      ))}
    </div>
  )
}
