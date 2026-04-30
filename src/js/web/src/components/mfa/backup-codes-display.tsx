import { AlertTriangle, Copy, Download } from "lucide-react"
import { useCallback, useMemo } from "react"
import { toast } from "sonner"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface BackupCodesDisplayProps {
  codes: string[]
  title?: string
  description?: string
}

export function BackupCodesDisplay({ codes, title = "Backup codes", description }: BackupCodesDisplayProps) {
  const formatted = useMemo(() => codes.filter(Boolean), [codes])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(formatted.join("\n"))
      toast.success("Backup codes copied")
    } catch {
      toast.error("Unable to copy backup codes")
    }
  }

  const handleCopyOne = useCallback(async (code: string) => {
    try {
      await navigator.clipboard.writeText(code)
      toast.success("Code copied")
    } catch {
      toast.error("Unable to copy code")
    }
  }, [])

  const handleDownload = useCallback(() => {
    const content = [
      "MFA Backup Codes",
      "================",
      `Generated: ${new Date().toLocaleDateString()}`,
      "",
      "Each code can only be used once.",
      "Store these codes in a secure location.",
      "",
      ...formatted,
    ].join("\n")

    const blob = new Blob([content], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = "mfa-backup-codes.txt"
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
    toast.success("Backup codes downloaded")
  }, [formatted])

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>{title}</CardTitle>
          {description && <p className="text-muted-foreground text-sm">{description}</p>}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleDownload}>
            <Download className="mr-1.5 h-3.5 w-3.5" />
            Download
          </Button>
          <Button variant="outline" size="sm" onClick={handleCopy}>
            <Copy className="mr-1.5 h-3.5 w-3.5" />
            Copy
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <Alert variant="warning" className="mb-4">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>These codes won&apos;t be shown again. Store them securely.</AlertDescription>
        </Alert>
        <div className="grid gap-2 sm:grid-cols-2">
          {formatted.map((code) => (
            <button
              key={code}
              type="button"
              onClick={() => handleCopyOne(code)}
              className="group relative flex items-center justify-between rounded-md border border-border/60 bg-muted/40 px-3 py-2 font-mono text-sm text-foreground transition-colors hover:border-border hover:bg-muted/70"
            >
              <span>{code}</span>
              <Copy className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
