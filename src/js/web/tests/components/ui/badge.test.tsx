import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { Badge, badgeVariants } from "@/components/ui/badge"

describe("Badge", () => {
  it("renders children", () => {
    render(<Badge>Test Badge</Badge>)
    expect(screen.getByText("Test Badge")).toBeInTheDocument()
  })

  it("has data-slot attribute set to badge", () => {
    render(<Badge>Slotted</Badge>)
    expect(screen.getByText("Slotted")).toHaveAttribute("data-slot", "badge")
  })

  it("applies default variant classes", () => {
    render(<Badge>Default</Badge>)
    const el = screen.getByText("Default")
    expect(el.className).toContain("bg-primary")
  })

  it("applies secondary variant classes", () => {
    render(<Badge variant="secondary">Secondary</Badge>)
    const el = screen.getByText("Secondary")
    expect(el.className).toContain("bg-secondary")
  })

  it("applies outline variant classes", () => {
    render(<Badge variant="outline">Outline</Badge>)
    const el = screen.getByText("Outline")
    expect(el.className).toContain("text-foreground")
    expect(el.className).not.toContain("bg-primary")
  })

  it("applies destructive variant classes", () => {
    render(<Badge variant="destructive">Destructive</Badge>)
    const el = screen.getByText("Destructive")
    expect(el.className).toContain("bg-destructive")
  })

  it("merges custom className", () => {
    render(<Badge className="custom-class">Custom</Badge>)
    const el = screen.getByText("Custom")
    expect(el.className).toContain("custom-class")
  })

  it("passes through HTML div props", () => {
    render(<Badge data-testid="my-badge">Props</Badge>)
    expect(screen.getByTestId("my-badge")).toBeInTheDocument()
  })

  it("always includes base styles", () => {
    render(<Badge>Base</Badge>)
    const el = screen.getByText("Base")
    expect(el.className).toContain("inline-flex")
    expect(el.className).toContain("rounded-full")
    expect(el.className).toContain("text-xs")
  })
})

describe("badgeVariants", () => {
  it("returns a string of class names for default variant", () => {
    const classes = badgeVariants({ variant: "default" })
    expect(classes).toContain("bg-primary")
  })

  it("returns a string of class names for secondary variant", () => {
    const classes = badgeVariants({ variant: "secondary" })
    expect(classes).toContain("bg-secondary")
  })

  it("returns a string of class names for destructive variant", () => {
    const classes = badgeVariants({ variant: "destructive" })
    expect(classes).toContain("bg-destructive")
  })

  it("returns a string of class names for outline variant", () => {
    const classes = badgeVariants({ variant: "outline" })
    expect(classes).toContain("text-foreground")
  })

  it("uses default variant when none specified", () => {
    const classes = badgeVariants({})
    expect(classes).toContain("bg-primary")
  })
})
