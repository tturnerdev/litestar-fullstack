import { useCallback, useRef, useState } from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ResourcesTab } from "./resources-tab"
import { ReportIssueTab, captureScreenshot, type ReportFormData } from "./report-issue-tab"

interface HelpDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const DEFAULT_FORM_DATA: ReportFormData = {
  title: "",
  category: "",
  description: "",
  screenshot: null,
  files: [],
}

export function HelpDialog({ open, onOpenChange }: HelpDialogProps) {
  const [activeTab, setActiveTab] = useState("resources")
  const [formData, setFormData] = useState<ReportFormData>(DEFAULT_FORM_DATA)
  const [isCapturing, setIsCapturing] = useState(false)
  const formDataRef = useRef<ReportFormData>(formData)

  // Keep ref in sync so the capture callback always sees current form data
  formDataRef.current = formData

  const handleCaptureScreenshot = useCallback(async () => {
    setIsCapturing(true)

    // Close the dialog to reveal the portal content underneath
    onOpenChange(false)

    // Wait for the dialog close animation to complete
    await new Promise((resolve) => setTimeout(resolve, 350))

    try {
      const dataUrl = await captureScreenshot()

      // Restore form data with the captured screenshot attached
      setFormData({ ...formDataRef.current, screenshot: dataUrl })
    } catch (err) {
      console.error("[Help] Screenshot capture failed:", err)
    } finally {
      setIsCapturing(false)
      // Re-open the dialog with the report tab active
      setActiveTab("report")
      onOpenChange(true)
    }
  }, [onOpenChange])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Help & Support</DialogTitle>
          <DialogDescription>Browse resources or report an issue</DialogDescription>
        </DialogHeader>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="w-full">
            <TabsTrigger value="resources" className="flex-1">Resources</TabsTrigger>
            <TabsTrigger value="report" className="flex-1">Report Issue</TabsTrigger>
          </TabsList>
          <TabsContent value="resources">
            <ResourcesTab />
          </TabsContent>
          <TabsContent value="report">
            <ReportIssueTab
              formData={formData}
              onFormDataChange={setFormData}
              onCaptureScreenshot={handleCaptureScreenshot}
              isCapturing={isCapturing}
            />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
