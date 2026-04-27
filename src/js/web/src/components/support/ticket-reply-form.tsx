import { Loader2, Send } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Textarea } from "@/components/ui/textarea"
import { useCreateTicketMessage } from "@/lib/api/hooks/support"

export function TicketReplyForm({ ticketId }: { ticketId: string }) {
  const [body, setBody] = useState("")
  const createMessage = useCreateTicketMessage(ticketId)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!body.trim()) return
    createMessage.mutate(
      { bodyMarkdown: body },
      {
        onSuccess: () => setBody(""),
      },
    )
  }

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium">Reply</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Textarea
            placeholder="Write your reply..."
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="min-h-[120px] resize-none"
          />
          <div className="flex justify-end">
            <Button type="submit" disabled={createMessage.isPending || !body.trim()}>
              {createMessage.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Send className="mr-2 h-4 w-4" />
              )}
              {createMessage.isPending ? "Sending..." : "Send Reply"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
