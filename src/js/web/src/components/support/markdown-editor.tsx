import {
  Bold,
  Code,
  Eye,
  Heading2,
  ImageIcon,
  Italic,
  Link2,
  List,
  ListOrdered,
  Maximize2,
  Minimize2,
  Minus,
  Pencil,
  Quote,
  Strikethrough,
  Table,
} from "lucide-react"
import { useCallback, useRef, useState } from "react"
import { MarkdownRenderer } from "@/components/support/markdown-renderer"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { cn } from "@/lib/utils"

interface MarkdownEditorProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  minHeight?: string
  onPaste?: (e: React.ClipboardEvent<HTMLTextAreaElement>) => void
  onDrop?: (e: React.DragEvent<HTMLTextAreaElement>) => void
  disabled?: boolean
}

interface ToolbarAction {
  icon: React.ComponentType<{ className?: string }>
  label: string
  shortcut?: string
  action: (textarea: HTMLTextAreaElement) => { text: string; selectionStart: number; selectionEnd: number }
}

function wrapSelection(
  textarea: HTMLTextAreaElement,
  before: string,
  after: string,
): { text: string; selectionStart: number; selectionEnd: number } {
  const { selectionStart, selectionEnd, value } = textarea
  const selected = value.substring(selectionStart, selectionEnd)
  const replacement = `${before}${selected || "text"}${after}`
  const newText = value.substring(0, selectionStart) + replacement + value.substring(selectionEnd)
  const cursorStart = selectionStart + before.length
  const cursorEnd = selected ? cursorStart + selected.length : cursorStart + 4
  return { text: newText, selectionStart: cursorStart, selectionEnd: cursorEnd }
}

function insertAtCursor(
  textarea: HTMLTextAreaElement,
  insertion: string,
): { text: string; selectionStart: number; selectionEnd: number } {
  const { selectionStart, selectionEnd, value } = textarea
  const newText = value.substring(0, selectionStart) + insertion + value.substring(selectionEnd)
  const cursor = selectionStart + insertion.length
  return { text: newText, selectionStart: cursor, selectionEnd: cursor }
}

function prefixLine(
  textarea: HTMLTextAreaElement,
  prefix: string,
): { text: string; selectionStart: number; selectionEnd: number } {
  const { selectionStart, value } = textarea
  const lineStart = value.lastIndexOf("\n", selectionStart - 1) + 1
  const newText = value.substring(0, lineStart) + prefix + value.substring(lineStart)
  const cursor = selectionStart + prefix.length
  return { text: newText, selectionStart: cursor, selectionEnd: cursor }
}

const toolbarActions: ToolbarAction[] = [
  {
    icon: Bold,
    label: "Bold",
    shortcut: "Ctrl+B",
    action: (ta) => wrapSelection(ta, "**", "**"),
  },
  {
    icon: Italic,
    label: "Italic",
    shortcut: "Ctrl+I",
    action: (ta) => wrapSelection(ta, "_", "_"),
  },
  {
    icon: Strikethrough,
    label: "Strikethrough",
    action: (ta) => wrapSelection(ta, "~~", "~~"),
  },
  {
    icon: Heading2,
    label: "Heading",
    action: (ta) => prefixLine(ta, "## "),
  },
  {
    icon: Code,
    label: "Code",
    action: (ta) => {
      const selected = ta.value.substring(ta.selectionStart, ta.selectionEnd)
      if (selected.includes("\n")) {
        return wrapSelection(ta, "```\n", "\n```")
      }
      return wrapSelection(ta, "`", "`")
    },
  },
  {
    icon: Link2,
    label: "Link",
    shortcut: "Ctrl+K",
    action: (ta) => {
      const selected = ta.value.substring(ta.selectionStart, ta.selectionEnd)
      const linkText = selected || "link text"
      const replacement = `[${linkText}](url)`
      const newText = ta.value.substring(0, ta.selectionStart) + replacement + ta.value.substring(ta.selectionEnd)
      return { text: newText, selectionStart: ta.selectionStart + linkText.length + 3, selectionEnd: ta.selectionStart + linkText.length + 6 }
    },
  },
  {
    icon: ImageIcon,
    label: "Image",
    action: (ta) => insertAtCursor(ta, "![alt text](image-url)"),
  },
  {
    icon: List,
    label: "Bullet list",
    action: (ta) => prefixLine(ta, "- "),
  },
  {
    icon: ListOrdered,
    label: "Numbered list",
    action: (ta) => prefixLine(ta, "1. "),
  },
  {
    icon: Quote,
    label: "Quote",
    action: (ta) => prefixLine(ta, "> "),
  },
  {
    icon: Table,
    label: "Table",
    action: (ta) => insertAtCursor(ta, "\n| Header | Header |\n|--------|--------|\n| Cell   | Cell   |\n"),
  },
  {
    icon: Minus,
    label: "Horizontal rule",
    action: (ta) => insertAtCursor(ta, "\n---\n"),
  },
]

export function MarkdownEditor({
  value,
  onChange,
  placeholder = "Write your message... (Markdown supported)",
  minHeight = "150px",
  onPaste,
  onDrop,
  disabled = false,
}: MarkdownEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const [activeTab, setActiveTab] = useState<string>("write")
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [isDragOver, setIsDragOver] = useState(false)
  const [activeFormats, setActiveFormats] = useState<Set<string>>(new Set())

  const wordCount = value.trim() ? value.trim().split(/\s+/).length : 0

  const detectActiveFormats = useCallback((textarea: HTMLTextAreaElement) => {
    const { selectionStart, value: text } = textarea
    const formats = new Set<string>()

    // Check if cursor is inside **bold**
    const beforeCursor = text.substring(0, selectionStart)
    const afterCursor = text.substring(selectionStart)
    if (/\*\*[^*]*$/.test(beforeCursor) && /^[^*]*\*\*/.test(afterCursor)) {
      formats.add("Bold")
    }
    // Check if cursor is inside _italic_
    if (/(?<!\w)_[^_]*$/.test(beforeCursor) && /^[^_]*_(?!\w)/.test(afterCursor)) {
      formats.add("Italic")
    }
    // Check if cursor is inside ~~strikethrough~~
    if (/~~[^~]*$/.test(beforeCursor) && /^[^~]*~~/.test(afterCursor)) {
      formats.add("Strikethrough")
    }

    setActiveFormats(formats)
  }, [])

  const applyAction = useCallback(
    (action: ToolbarAction["action"]) => {
      const textarea = textareaRef.current
      if (!textarea) return
      const result = action(textarea)
      onChange(result.text)
      requestAnimationFrame(() => {
        textarea.focus()
        textarea.setSelectionRange(result.selectionStart, result.selectionEnd)
      })
    },
    [onChange],
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      const textarea = textareaRef.current
      if (!textarea) return
      const isModKey = e.ctrlKey || e.metaKey
      if (!isModKey) return

      let handled = false
      if (e.key === "b") {
        applyAction(toolbarActions[0].action)
        handled = true
      } else if (e.key === "i") {
        applyAction(toolbarActions[1].action)
        handled = true
      } else if (e.key === "k") {
        applyAction(toolbarActions[5].action)
        handled = true
      }

      if (handled) {
        e.preventDefault()
      }
    },
    [applyAction],
  )

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
      <div className="flex items-center justify-between rounded-t-lg border border-b-0 border-border/80 bg-muted/30 px-2 py-1">
        <div className="flex items-center gap-0.5">
          {toolbarActions.map((action, index) => (
            <span key={action.label} className="contents">
              {(index === 5 || index === 7 || index === 10) && (
                <Separator orientation="vertical" className="mx-1 h-5" />
              )}
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className={cn(
                      "h-7 w-7 p-0",
                      activeFormats.has(action.label) && "bg-accent text-accent-foreground",
                    )}
                    onClick={() => {
                      setActiveTab("write")
                      applyAction(action.action)
                    }}
                    disabled={disabled}
                  >
                    <action.icon className="h-3.5 w-3.5" />
                    <span className="sr-only">{action.label}</span>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  {action.label}
                  {action.shortcut && (
                    <span className="ml-2 text-muted-foreground">{action.shortcut}</span>
                  )}
                </TooltipContent>
              </Tooltip>
            </span>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={() => setIsFullscreen((prev) => !prev)}
                disabled={disabled}
              >
                {isFullscreen ? (
                  <Minimize2 className="h-3.5 w-3.5" />
                ) : (
                  <Maximize2 className="h-3.5 w-3.5" />
                )}
                <span className="sr-only">{isFullscreen ? "Exit fullscreen" : "Fullscreen"}</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>{isFullscreen ? "Exit fullscreen" : "Fullscreen"}</TooltipContent>
          </Tooltip>
          <Separator orientation="vertical" className="mx-1 h-5" />
          <TabsList className="h-7 bg-transparent p-0">
            <TabsTrigger value="write" className="h-6 gap-1 px-2 text-xs">
              <Pencil className="h-3 w-3" />
              Write
            </TabsTrigger>
            <TabsTrigger value="preview" className="h-6 gap-1 px-2 text-xs">
              <Eye className="h-3 w-3" />
              Preview
            </TabsTrigger>
          </TabsList>
        </div>
      </div>
      <TabsContent value="write" className="mt-0">
        <div className="relative">
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={handleKeyDown}
            onKeyUp={() => {
              if (textareaRef.current) detectActiveFormats(textareaRef.current)
            }}
            onClick={() => {
              if (textareaRef.current) detectActiveFormats(textareaRef.current)
            }}
            onPaste={onPaste}
            onDrop={(e) => {
              setIsDragOver(false)
              onDrop?.(e)
            }}
            onDragEnter={(e) => {
              e.preventDefault()
              setIsDragOver(true)
            }}
            onDragOver={(e) => {
              e.preventDefault()
              setIsDragOver(true)
            }}
            onDragLeave={(e) => {
              // Only hide if leaving the textarea entirely
              if (!e.currentTarget.contains(e.relatedTarget as Node)) {
                setIsDragOver(false)
              }
            }}
            placeholder={placeholder}
            disabled={disabled}
            className={cn(
              "flex w-full rounded-b-lg border border-border/80 bg-card/80 px-3 py-2 text-sm shadow-sm outline-none transition-colors",
              "resize-none placeholder:text-muted-foreground",
              "focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50",
              "disabled:cursor-not-allowed disabled:opacity-60",
              isDragOver && "border-dashed border-2 border-primary/50",
            )}
            style={{ minHeight: isFullscreen ? "400px" : minHeight }}
          />
          {isDragOver && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-b-lg bg-primary/5">
              <span className="text-sm font-medium text-primary/70">Drop files here</span>
            </div>
          )}
        </div>
        <div className="flex justify-end px-1 pt-1">
          <span className="text-xs text-muted-foreground">{wordCount} {wordCount === 1 ? "word" : "words"}</span>
        </div>
      </TabsContent>
      <TabsContent value="preview" className="mt-0">
        <div
          className="rounded-b-lg border border-border/80 bg-card/80 px-3 py-2"
          style={{ minHeight }}
        >
          {value.trim() ? (
            <MarkdownRenderer content={value} />
          ) : (
            <p className="text-sm text-muted-foreground">Nothing to preview</p>
          )}
        </div>
      </TabsContent>
    </Tabs>
  )
}
