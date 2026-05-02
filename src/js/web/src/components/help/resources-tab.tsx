import { BookOpen, ExternalLink, FileCode, Globe, MessageSquare, Radio, Search } from "lucide-react"
import { useMemo, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"

interface Resource {
  label: string
  description: string
  href: string
  icon: typeof BookOpen
  external: boolean
  iconColor: string
  badge?: string
}

interface ResourceSection {
  title: string
  items: Resource[]
}

const sections: ResourceSection[] = [
  {
    title: "Documentation",
    items: [
      {
        label: "Knowledge Base",
        description: "Guides, tutorials, and how-to articles for common tasks",
        href: "https://kb.atrelix.com",
        icon: BookOpen,
        external: true,
        iconColor: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
      },
      {
        label: "Wiki",
        description: "Internal documentation, policies, and reference material",
        href: "https://wiki.atrelix.com",
        icon: Globe,
        external: true,
        iconColor: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
      },
      {
        label: "API Documentation",
        description: "Interactive API reference and endpoint documentation",
        href: "/api/docs",
        icon: FileCode,
        external: false,
        iconColor: "bg-violet-500/15 text-violet-600 dark:text-violet-400",
        badge: "Updated",
      },
    ],
  },
  {
    title: "Community & Support",
    items: [
      {
        label: "Community Forum",
        description: "Ask questions, share ideas, and connect with other users",
        href: "https://community.atrelix.com",
        icon: MessageSquare,
        external: true,
        iconColor: "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",
      },
      {
        label: "Status Page",
        description: "Current system status, incidents, and scheduled maintenance",
        href: "https://status.atrelix.com",
        icon: Radio,
        external: true,
        iconColor: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
      },
    ],
  },
]

export function ResourcesTab() {
  const [search, setSearch] = useState("")

  const filteredSections = useMemo(() => {
    if (!search.trim()) return sections
    const q = search.toLowerCase()
    return sections
      .map((section) => ({
        ...section,
        items: section.items.filter((item) => item.label.toLowerCase().includes(q) || item.description.toLowerCase().includes(q)),
      }))
      .filter((section) => section.items.length > 0)
  }, [search])

  return (
    <div className="space-y-3 pt-2">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input placeholder="Filter resources..." value={search} onChange={(e) => setSearch(e.target.value)} className="h-8 pl-8 text-xs" />
      </div>

      {filteredSections.length === 0 && <p className="py-6 text-center text-xs text-muted-foreground">No resources match your search.</p>}

      {filteredSections.map((section, sectionIdx) => (
        <div key={section.title}>
          {sectionIdx > 0 && <Separator className="mb-3" />}
          <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/70">{section.title}</p>
          <div className="space-y-0.5">
            {section.items.map((resource) => (
              <a
                key={resource.label}
                href={resource.href}
                target={resource.external ? "_blank" : undefined}
                rel={resource.external ? "noopener noreferrer" : undefined}
                className="group flex items-start gap-3 rounded-lg border border-transparent px-3 py-3 transition-all hover:border-border/40 hover:bg-accent"
              >
                <div className={`mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md ${resource.iconColor}`}>
                  <resource.icon className="size-4" />
                </div>
                <div className="flex-1 space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <span className="text-sm font-medium text-foreground">{resource.label}</span>
                    {resource.badge && (
                      <Badge variant="secondary" className="h-4 px-1.5 py-0 text-[10px] leading-none">
                        {resource.badge}
                      </Badge>
                    )}
                    {resource.external && <ExternalLink className="size-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />}
                  </div>
                  <p className="text-xs text-muted-foreground">{resource.description}</p>
                </div>
              </a>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
