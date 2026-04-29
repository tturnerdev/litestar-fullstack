import { BookOpen, ExternalLink, FileCode, Globe, MessageSquare, Radio } from "lucide-react"

const resources = [
  {
    label: "Knowledge Base",
    description: "Guides, tutorials, and how-to articles for common tasks",
    href: "https://kb.atrelix.com",
    icon: BookOpen,
    external: true,
  },
  {
    label: "Wiki",
    description: "Internal documentation, policies, and reference material",
    href: "https://wiki.atrelix.com",
    icon: Globe,
    external: true,
  },
  {
    label: "Status Page",
    description: "Current system status, incidents, and scheduled maintenance",
    href: "https://status.atrelix.com",
    icon: Radio,
    external: true,
  },
  {
    label: "API Documentation",
    description: "Interactive API reference and endpoint documentation",
    href: "/api/docs",
    icon: FileCode,
    external: false,
  },
  {
    label: "Community Forum",
    description: "Ask questions, share ideas, and connect with other users",
    href: "https://community.atrelix.com",
    icon: MessageSquare,
    external: true,
  },
] as const

export function ResourcesTab() {
  return (
    <div className="space-y-1 pt-2">
      {resources.map((resource) => (
        <a
          key={resource.label}
          href={resource.href}
          target={resource.external ? "_blank" : undefined}
          rel={resource.external ? "noopener noreferrer" : undefined}
          className="group flex items-start gap-3 rounded-lg px-3 py-3 transition-colors hover:bg-accent"
        >
          <resource.icon className="mt-0.5 size-5 shrink-0 text-muted-foreground transition-colors group-hover:text-foreground" />
          <div className="flex-1 space-y-0.5">
            <div className="flex items-center gap-1.5">
              <span className="text-sm font-medium text-foreground">{resource.label}</span>
              <ExternalLink className="size-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <p className="text-xs text-muted-foreground">{resource.description}</p>
          </div>
        </a>
      ))}
    </div>
  )
}
