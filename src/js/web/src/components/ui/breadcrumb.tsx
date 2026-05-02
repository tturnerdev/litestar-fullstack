import { Slot } from "@radix-ui/react-slot"
import { ChevronDown, ChevronRight, MoreHorizontal } from "lucide-react"
import type * as React from "react"

import { cn } from "@/lib/utils"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

function Breadcrumb({ ...props }: React.ComponentProps<"nav">) {
  return <nav aria-label="breadcrumb" data-slot="breadcrumb" {...props} />
}

function BreadcrumbList({ className, ...props }: React.ComponentProps<"ol">) {
  return <ol data-slot="breadcrumb-list" className={cn("flex flex-wrap items-center gap-1.5 break-words text-muted-foreground text-sm sm:gap-2.5", className)} {...props} />
}

function BreadcrumbItem({ className, ...props }: React.ComponentProps<"li">) {
  return <li data-slot="breadcrumb-item" className={cn("inline-flex items-center gap-1.5", className)} {...props} />
}

function BreadcrumbLink({
  asChild,
  className,
  ...props
}: React.ComponentProps<"a"> & {
  asChild?: boolean
}) {
  const Comp = asChild ? Slot : "a"

  return <Comp data-slot="breadcrumb-link" className={cn("transition-colors hover:text-foreground", className)} {...props} />
}

function BreadcrumbPage({ className, ...props }: React.ComponentProps<"span">) {
  return <span data-slot="breadcrumb-page" aria-disabled="true" aria-current="page" className={cn("font-normal text-foreground", className)} {...props} />
}

function BreadcrumbSeparator({ children, className, ...props }: React.ComponentProps<"li">) {
  return (
    <li data-slot="breadcrumb-separator" role="presentation" aria-hidden="true" className={cn("[&>svg]:size-3.5", className)} {...props}>
      {children ?? <ChevronRight />}
    </li>
  )
}

function BreadcrumbEllipsis({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span data-slot="breadcrumb-ellipsis" role="presentation" aria-hidden="true" className={cn("flex size-9 items-center justify-center", className)} {...props}>
      <MoreHorizontal className="size-4" />
      <span className="sr-only">More</span>
    </span>
  )
}

interface BreadcrumbSibling {
  label: string
  to: string
}

/** A breadcrumb segment that opens a dropdown of sibling navigation links. */
function BreadcrumbDropdownLink({
  label,
  siblings,
  renderLink,
  className,
}: {
  /** Display label for the breadcrumb segment. */
  label: string
  /** Sibling pages shown in the dropdown. */
  siblings: BreadcrumbSibling[]
  /** Render function for navigation links (avoids coupling to a router). */
  renderLink: (sibling: BreadcrumbSibling) => React.ReactNode
  className?: string
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className={cn(
          "flex items-center gap-1 transition-colors hover:text-foreground",
          className,
        )}
      >
        {label}
        <ChevronDown className="h-3 w-3" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {siblings.map((sibling) => (
          <DropdownMenuItem key={sibling.to} asChild>
            {renderLink(sibling)}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
  BreadcrumbEllipsis,
  BreadcrumbDropdownLink,
}
export type { BreadcrumbSibling }
