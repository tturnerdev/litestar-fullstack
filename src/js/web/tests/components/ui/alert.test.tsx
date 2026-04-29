import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert"

describe("Alert", () => {
  it("renders with role=alert", () => {
    render(<Alert>Alert content</Alert>)
    expect(screen.getByRole("alert")).toBeInTheDocument()
  })

  it("renders children", () => {
    render(<Alert>Something happened</Alert>)
    expect(screen.getByText("Something happened")).toBeInTheDocument()
  })

  it("applies default variant classes", () => {
    render(<Alert>Default</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("bg-background")
    expect(alert.className).toContain("text-foreground")
  })

  it("applies destructive variant classes", () => {
    render(<Alert variant="destructive">Error</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("text-destructive")
  })

  it("applies warning variant classes", () => {
    render(<Alert variant="warning">Warning</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("text-warning-foreground")
  })

  it("applies success variant classes", () => {
    render(<Alert variant="success">Success</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("text-success")
  })

  it("applies info variant classes", () => {
    render(<Alert variant="info">Info</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("text-info")
  })

  it("merges custom className", () => {
    render(<Alert className="my-custom">Content</Alert>)
    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("my-custom")
  })
})

describe("AlertTitle", () => {
  it("renders as heading element", () => {
    render(<AlertTitle>Title Text</AlertTitle>)
    const title = screen.getByText("Title Text")
    expect(title.tagName).toBe("H5")
  })

  it("applies font-medium class", () => {
    render(<AlertTitle>Title</AlertTitle>)
    const title = screen.getByText("Title")
    expect(title.className).toContain("font-medium")
  })

  it("merges custom className", () => {
    render(<AlertTitle className="extra">Title</AlertTitle>)
    expect(screen.getByText("Title").className).toContain("extra")
  })
})

describe("AlertDescription", () => {
  it("renders description text", () => {
    render(<AlertDescription>Description text here</AlertDescription>)
    expect(screen.getByText("Description text here")).toBeInTheDocument()
  })

  it("applies text-sm class", () => {
    render(<AlertDescription>Desc</AlertDescription>)
    const desc = screen.getByText("Desc")
    expect(desc.className).toContain("text-sm")
  })

  it("merges custom className", () => {
    render(<AlertDescription className="custom-desc">Desc</AlertDescription>)
    expect(screen.getByText("Desc").className).toContain("custom-desc")
  })
})

describe("Alert composition", () => {
  it("renders title and description together", () => {
    render(
      <Alert>
        <AlertTitle>Error Occurred</AlertTitle>
        <AlertDescription>Something went wrong. Please try again.</AlertDescription>
      </Alert>,
    )

    expect(screen.getByRole("alert")).toBeInTheDocument()
    expect(screen.getByText("Error Occurred")).toBeInTheDocument()
    expect(screen.getByText("Something went wrong. Please try again.")).toBeInTheDocument()
  })

  it("renders destructive alert with title and description", () => {
    render(
      <Alert variant="destructive">
        <AlertTitle>Danger</AlertTitle>
        <AlertDescription>This action cannot be undone.</AlertDescription>
      </Alert>,
    )

    const alert = screen.getByRole("alert")
    expect(alert.className).toContain("text-destructive")
    expect(screen.getByText("Danger")).toBeInTheDocument()
    expect(screen.getByText("This action cannot be undone.")).toBeInTheDocument()
  })
})
