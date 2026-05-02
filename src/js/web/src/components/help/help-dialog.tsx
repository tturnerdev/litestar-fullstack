import { Link } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import { BookOpen, Bug, Command, Keyboard } from "lucide-react"
import * as React from "react"
import { useCallback, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { DURATION, fadeInUp, staggerContainer } from "@/components/ui/motion"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { captureScreenshot, type ReportFormData, ReportIssueTab } from "./report-issue-tab"
import { ResourcesTab } from "./resources-tab"

const APP_VERSION = "v0.37.0"

interface HelpDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  defaultTab?: string
}

const DEFAULT_FORM_DATA: ReportFormData = {
  title: "",
  category: "",
  description: "",
  screenshot: null,
  files: [],
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts data
// ---------------------------------------------------------------------------

const KEYBOARD_SHORTCUTS = [
  { keys: ["Cmd/Ctrl", "K"], description: "Global search" },
  { keys: ["Cmd/Ctrl", "B"], description: "Toggle sidebar" },
  { keys: ["?"], description: "Show keyboard shortcuts" },
  { keys: ["Esc"], description: "Close dialogs" },
] as const

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-[20px] items-center justify-center rounded border border-border bg-muted/60 px-1.5 font-mono text-[11px] font-medium text-muted-foreground shadow-sm">
      {children}
    </kbd>
  )
}

// ---------------------------------------------------------------------------
// Stagger-animated wrapper for sections
// ---------------------------------------------------------------------------

const sectionVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0 },
}

function AnimatedSection({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  return (
    <motion.div variants={sectionVariants} initial="hidden" animate="visible" transition={{ duration: DURATION.medium, delay, ease: [0.25, 0.1, 0.25, 1] }}>
      {children}
    </motion.div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HelpDialog({ open, onOpenChange, defaultTab }: HelpDialogProps) {
  const [activeTab, setActiveTab] = useState("resources")
  const [formData, setFormData] = useState<ReportFormData>(DEFAULT_FORM_DATA)
  const [isCapturing, setIsCapturing] = useState(false)
  const [showShortcuts, setShowShortcuts] = useState(false)

  // Apply defaultTab when the dialog opens
  React.useEffect(() => {
    if (open && defaultTab) {
      if (defaultTab === "shortcuts") {
        setShowShortcuts(true)
        setActiveTab("resources")
      } else {
        setShowShortcuts(false)
        setActiveTab(defaultTab)
      }
    }
  }, [open, defaultTab])
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
        <AnimatedSection delay={0}>
          <DialogHeader>
            <DialogTitle>Help & Support</DialogTitle>
            <DialogDescription>Browse resources or report an issue</DialogDescription>
          </DialogHeader>
        </AnimatedSection>

        {/* Quick action links */}
        <AnimatedSection delay={0.05}>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="flex-1 gap-1.5 text-xs" asChild>
              <Link to="/support/new" onClick={() => onOpenChange(false)}>
                <Bug className="size-3.5" />
                Report a Bug
              </Link>
            </Button>
            <Button variant="outline" size="sm" className="flex-1 gap-1.5 text-xs" asChild>
              <a href="/api/docs" target="_blank" rel="noopener noreferrer">
                <BookOpen className="size-3.5" />
                View Documentation
              </a>
            </Button>
            <Button variant={showShortcuts ? "secondary" : "outline"} size="sm" className="flex-1 gap-1.5 text-xs" onClick={() => setShowShortcuts((v) => !v)}>
              <Keyboard className="size-3.5" />
              Shortcuts
            </Button>
          </div>
        </AnimatedSection>

        {/* Keyboard shortcuts (collapsible) */}
        <AnimatePresence>
          {showShortcuts && (
            <motion.div key="shortcuts" variants={fadeInUp} initial="hidden" animate="visible" exit="hidden" transition={{ duration: DURATION.normal }}>
              <div className="rounded-lg border border-border/60 bg-muted/30 p-4">
                <h4 className="mb-3 flex items-center gap-1.5 text-xs font-semibold text-foreground">
                  <Command className="size-3.5" />
                  Keyboard Shortcuts
                </h4>
                <motion.div className="space-y-2" variants={staggerContainer} initial="hidden" animate="visible">
                  {KEYBOARD_SHORTCUTS.map((shortcut) => (
                    <motion.div key={shortcut.description} variants={sectionVariants} className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{shortcut.description}</span>
                      <div className="flex items-center gap-1">
                        {shortcut.keys.map((key, i) => (
                          <span key={key} className="flex items-center gap-1">
                            {i > 0 && <span className="text-[10px] text-muted-foreground/60">+</span>}
                            <Kbd>{key}</Kbd>
                          </span>
                        ))}
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <AnimatedSection delay={0.1}>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="w-full">
              <TabsTrigger value="resources" className="flex-1">
                Resources
              </TabsTrigger>
              <TabsTrigger value="report" className="flex-1">
                Report Issue
              </TabsTrigger>
            </TabsList>
            <TabsContent value="resources">
              <ResourcesTab />
            </TabsContent>
            <TabsContent value="report">
              <ReportIssueTab formData={formData} onFormDataChange={setFormData} onCaptureScreenshot={handleCaptureScreenshot} isCapturing={isCapturing} />
            </TabsContent>
          </Tabs>
        </AnimatedSection>

        {/* Version footer */}
        <AnimatedSection delay={0.15}>
          <Separator />
          <p className="pt-2 text-center text-[11px] text-muted-foreground/60">Atrelix Admin Portal {APP_VERSION}</p>
        </AnimatedSection>
      </DialogContent>
    </Dialog>
  )
}
