import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { PasswordStrength } from "@/components/ui/password-strength"

describe("PasswordStrength", () => {
  it("renders nothing when password is empty", () => {
    const { container } = render(<PasswordStrength password="" />)
    expect(container.firstChild).toBeNull()
  })

  it("renders the strength label for a non-empty password", () => {
    render(<PasswordStrength password="abc" />)
    expect(screen.getByText("Password strength")).toBeInTheDocument()
  })

  it("shows 'weak' for a short simple password", () => {
    render(<PasswordStrength password="abc" />)
    expect(screen.getByText("weak")).toBeInTheDocument()
  })

  it("shows 'strong' for a fully qualifying password", () => {
    render(<PasswordStrength password="MyStr0ng!Pass1234567890" />)
    expect(screen.getByText("strong")).toBeInTheDocument()
  })

  it("shows requirement items when showRequirements is true (default)", () => {
    render(<PasswordStrength password="abc" />)
    expect(screen.getByText("Requirements")).toBeInTheDocument()
    expect(screen.getByText("At least 12 characters")).toBeInTheDocument()
    expect(screen.getByText("One uppercase letter")).toBeInTheDocument()
    expect(screen.getByText("One lowercase letter")).toBeInTheDocument()
    expect(screen.getByText("One number")).toBeInTheDocument()
    expect(screen.getByText("One special character (!@#$%^&*)")).toBeInTheDocument()
    expect(screen.getByText("Not a common password")).toBeInTheDocument()
  })

  it("hides requirement items when showRequirements is false", () => {
    render(<PasswordStrength password="abc" showRequirements={false} />)
    expect(screen.queryByText("Requirements")).not.toBeInTheDocument()
  })

  it("applies custom className", () => {
    const { container } = render(
      <PasswordStrength password="test" className="my-custom-class" />
    )
    expect(container.firstChild).toHaveClass("my-custom-class")
  })

  it("shows feedback messages for unmet requirements", () => {
    render(<PasswordStrength password="abc" />)
    expect(screen.getByText("Use at least 12 characters")).toBeInTheDocument()
  })

  it("does not show feedback for met requirements", () => {
    render(<PasswordStrength password="MyStr0ng!Pass1234567890" />)
    expect(screen.queryByText("Use at least 12 characters")).not.toBeInTheDocument()
    expect(screen.queryByText("Include uppercase letters")).not.toBeInTheDocument()
  })

  it("shows medium strength for a partially qualifying password", () => {
    render(<PasswordStrength password="Abcdefghijkl1" />)
    expect(screen.getByText("medium")).toBeInTheDocument()
  })
})
