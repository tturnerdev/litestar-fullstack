import { FileUp, Send } from "lucide-react"
import { useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useFaxNumbers, useSendFax } from "@/lib/api/hooks/fax"

export function SendFaxForm() {
  const { data: faxNumbers, isLoading } = useFaxNumbers(1, 100)
  const sendFax = useSendFax()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [faxNumberId, setFaxNumberId] = useState("")
  const [remoteNumber, setRemoteNumber] = useState("")
  const [file, setFile] = useState<File | null>(null)

  if (isLoading) {
    return <SkeletonCard />
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0] ?? null
    setFile(selected)
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!faxNumberId || !remoteNumber || !file) return
    sendFax.mutate(
      { faxNumberId, remoteNumber, file },
      {
        onSuccess: () => {
          setFaxNumberId("")
          setRemoteNumber("")
          setFile(null)
          if (fileInputRef.current) fileInputRef.current.value = ""
        },
      },
    )
  }

  const activeNumbers = faxNumbers?.items.filter((n) => n.isActive) ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Send a Fax</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="source-number">Source Fax Number</Label>
            <Select value={faxNumberId} onValueChange={setFaxNumberId}>
              <SelectTrigger id="source-number">
                <SelectValue placeholder="Select a fax number" />
              </SelectTrigger>
              <SelectContent>
                {activeNumbers.map((num) => (
                  <SelectItem key={num.id} value={num.id}>
                    {num.number} {num.label ? `(${num.label})` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {activeNumbers.length === 0 && (
              <p className="text-xs text-muted-foreground">No active fax numbers available.</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="destination">Destination Number</Label>
            <Input
              id="destination"
              type="tel"
              placeholder="+1234567890"
              value={remoteNumber}
              onChange={(e) => setRemoteNumber(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="file">Document (PDF)</Label>
            <div className="flex items-center gap-3">
              <Button type="button" variant="outline" onClick={() => fileInputRef.current?.click()}>
                <FileUp className="mr-2 h-4 w-4" /> Choose File
              </Button>
              <span className="text-sm text-muted-foreground">{file ? file.name : "No file selected"}</span>
            </div>
            <input ref={fileInputRef} id="file" type="file" accept=".pdf" className="hidden" onChange={handleFileChange} />
          </div>

          <Button type="submit" disabled={sendFax.isPending || !faxNumberId || !remoteNumber || !file}>
            <Send className="mr-2 h-4 w-4" />
            {sendFax.isPending ? "Sending..." : "Send Fax"}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
