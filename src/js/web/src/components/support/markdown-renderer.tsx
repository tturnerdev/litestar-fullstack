import { Check, Copy, ExternalLink } from "lucide-react"
import { useId, useState } from "react"
import type { Components } from "react-markdown"
import Markdown from "react-markdown"
import rehypeSanitize from "rehype-sanitize"
import remarkGfm from "remark-gfm"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------------------
// Code block with copy button
// ---------------------------------------------------------------------------

function CodeBlock({ className, children }: { className?: string; children?: React.ReactNode }) {
  const [copied, setCopied] = useState(false)
  const text = extractText(children)

  function handleCopy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="group/code relative">
      <pre className={cn("overflow-x-auto rounded-lg border bg-muted/50 p-4 text-sm", className)}>{children}</pre>
      <button
        type="button"
        onClick={handleCopy}
        className="absolute right-2 top-2 flex h-7 w-7 items-center justify-center rounded-md border bg-background opacity-0 shadow-sm transition-opacity group-hover/code:opacity-100 hover:bg-muted focus:opacity-100"
        title="Copy code"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
      </button>
    </div>
  )
}

/** Recursively extract plain text from React children. */
function extractText(node: React.ReactNode): string {
  if (node == null || typeof node === "boolean") return ""
  if (typeof node === "string") return node
  if (typeof node === "number") return String(node)
  if (Array.isArray(node)) return node.map(extractText).join("")
  if (typeof node === "object" && "props" in node) {
    const el = node as React.ReactElement<{ children?: React.ReactNode }>
    return extractText(el.props.children)
  }
  return ""
}

// ---------------------------------------------------------------------------
// Custom components map
// ---------------------------------------------------------------------------

function useMarkdownComponents(): Components {
  const baseId = useId()

  return {
    // -- Code: inline vs block --
    code({ className, children, ...props }) {
      const match = /language-(\w+)/.exec(className ?? "")
      const isBlock = typeof children === "string" && children.includes("\n")

      if (isBlock || match) {
        return (
          <code className={cn(match ? `language-${match[1]}` : undefined, className)} {...props}>
            {children}
          </code>
        )
      }

      return (
        <code className={cn("rounded bg-muted px-1.5 py-0.5 font-mono text-[0.85em]", className)} {...props}>
          {children}
        </code>
      )
    },

    // -- Pre: wrap in CodeBlock for copy button --
    pre({ children, className }) {
      return <CodeBlock className={className}>{children}</CodeBlock>
    },

    // -- Blockquote --
    blockquote({ children, className, ...props }) {
      return (
        <blockquote className={cn("border-l-4 border-primary/30 bg-muted/30 pl-4 py-2 italic text-muted-foreground [&>p]:mb-0", className)} {...props}>
          {children}
        </blockquote>
      )
    },

    // -- Tables --
    table({ children, className, ...props }) {
      return (
        <div className="my-4 w-full overflow-x-auto rounded-lg border">
          <table className={cn("w-full border-collapse text-sm", className)} {...props}>
            {children}
          </table>
        </div>
      )
    },
    thead({ children, ...props }) {
      return (
        <thead className="border-b bg-muted/50" {...props}>
          {children}
        </thead>
      )
    },
    tr({ children, className, ...props }) {
      return (
        <tr className={cn("border-b last:border-0 even:bg-muted/30", className)} {...props}>
          {children}
        </tr>
      )
    },
    th({ children, className, ...props }) {
      return (
        <th className={cn("px-3 py-2 text-left font-medium text-muted-foreground", className)} {...props}>
          {children}
        </th>
      )
    },
    td({ children, className, ...props }) {
      return (
        <td className={cn("px-3 py-2", className)} {...props}>
          {children}
        </td>
      )
    },

    // -- Links: external icon for external URLs --
    a({ href, children, className, ...props }) {
      const isExternal = href != null && (href.startsWith("http://") || href.startsWith("https://"))

      return (
        <a
          href={href}
          className={cn("text-primary underline decoration-primary/30 underline-offset-2 hover:decoration-primary/60 transition-colors", className)}
          {...(isExternal ? { target: "_blank", rel: "noopener noreferrer" } : {})}
          {...props}
        >
          {children}
          {isExternal && <ExternalLink className="ml-1 inline-block h-3 w-3 align-baseline" />}
        </a>
      )
    },

    // -- Task list items (- [x] / - [ ]) --
    li({ children, className, ...props }) {
      const text = extractText(children)
      const isChecked = text.startsWith("[x] ") || text.startsWith("[X] ")
      const isUnchecked = text.startsWith("[ ] ")

      if (isChecked || isUnchecked) {
        return (
          <li className={cn("flex items-start gap-2 list-none", className)} {...props}>
            <input type="checkbox" checked={isChecked} readOnly className="mt-1 h-4 w-4 rounded border-muted-foreground/40 accent-primary pointer-events-none" />
            <span className={isChecked ? "line-through text-muted-foreground" : ""}>{stripCheckbox(children)}</span>
          </li>
        )
      }

      return (
        <li className={className} {...props}>
          {children}
        </li>
      )
    },

    // -- Headings with hover anchor links --
    h1: createHeading("h1", baseId),
    h2: createHeading("h2", baseId),
    h3: createHeading("h3", baseId),
    h4: createHeading("h4", baseId),
    h5: createHeading("h5", baseId),
    h6: createHeading("h6", baseId),
  }
}

// ---------------------------------------------------------------------------
// Heading factory
// ---------------------------------------------------------------------------

function createHeading(Tag: "h1" | "h2" | "h3" | "h4" | "h5" | "h6", baseId: string): Components[typeof Tag] {
  function HeadingComponent({ children, className, ...props }: React.JSX.IntrinsicElements[typeof Tag]) {
    const text = extractText(children)
    const slug = `${baseId}-${text
      .toLowerCase()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .trim()}`

    return (
      <Tag id={slug} className={cn("group/heading scroll-mt-20", className)} {...props}>
        {children}
        <a
          href={`#${slug}`}
          className="ml-2 text-muted-foreground/0 group-hover/heading:text-muted-foreground/60 hover:text-primary transition-colors"
          aria-label={`Link to ${text}`}
        >
          #
        </a>
      </Tag>
    )
  }
  HeadingComponent.displayName = `Heading_${Tag}`
  return HeadingComponent as NonNullable<Components[typeof Tag]>
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip "[ ] " or "[x] " prefix from task-list children. */
function stripCheckbox(children: React.ReactNode): React.ReactNode {
  if (children == null) return children
  if (typeof children === "string") {
    return children.replace(/^\[(x|X| )\]\s*/, "")
  }
  if (Array.isArray(children)) {
    const [first, ...rest] = children
    return [stripCheckbox(first), ...rest]
  }
  if (typeof children === "object" && "props" in children) {
    const el = children as React.ReactElement<{ children?: React.ReactNode }>
    if (typeof el.props.children === "string") {
      const stripped = el.props.children.replace(/^\[(x|X| )\]\s*/, "")
      if (stripped !== el.props.children) {
        // Return just the stripped text; preserving the wrapper would require cloneElement
        return stripped
      }
    }
  }
  return children
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface MarkdownRendererProps {
  content: string
  className?: string
}

export function MarkdownRenderer({ content, className }: MarkdownRendererProps) {
  const components = useMarkdownComponents()

  return (
    <div
      className={cn(
        "prose prose-sm dark:prose-invert max-w-none",
        // Task list: remove default list markers for task items
        "[&_ul:has(input[type=checkbox])]:list-none [&_ul:has(input[type=checkbox])]:pl-0",
        className,
      )}
    >
      <Markdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]} components={components}>
        {content}
      </Markdown>
    </div>
  )
}
