import { describe, expect, it } from "vitest"
import {
  getPasswordStrength,
  validateEmail,
  validateName,
  validatePassword,
  validatePhone,
  validateUsername,
} from "@/hooks/use-validation"

// =============================================================================
// validateEmail
// =============================================================================

describe("validateEmail", () => {
  it("returns null for valid email", () => {
    expect(validateEmail("user@example.com")).toBeNull()
  })

  it("returns null for empty string (non-required)", () => {
    expect(validateEmail("")).toBeNull()
  })

  it("rejects email exceeding 254 characters", () => {
    // Build an email that exceeds 254 total chars but keeps local part <= 64
    // 64 local + 1 @ + 190 domain = 255 chars
    const longEmail = `${"a".repeat(64)}@${"b".repeat(186)}.com`
    expect(validateEmail(longEmail)).toBe("Email address too long")
  })

  it("rejects email shorter than 3 characters", () => {
    expect(validateEmail("a@")).toBe("Email address too short")
  })

  it("rejects invalid email format", () => {
    expect(validateEmail("noatsign")).toBe("Invalid email format")
  })

  it("rejects double dots in email", () => {
    expect(validateEmail("user..name@example.com")).toBe("Invalid email format")
  })

  it("rejects blocked disposable domains", () => {
    expect(validateEmail("user@mailinator.com")).toBe("This email domain is not allowed")
    expect(validateEmail("user@yopmail.com")).toBe("This email domain is not allowed")
    expect(validateEmail("user@10minutemail.com")).toBe("This email domain is not allowed")
  })

  it("rejects blocked email patterns", () => {
    expect(validateEmail("test123@example.com")).toBe("This email format is not allowed")
    expect(validateEmail("noreply@example.com")).toBe("This email format is not allowed")
  })

  it("rejects local part exceeding 64 characters", () => {
    const longLocal = `${"a".repeat(65)}@example.com`
    expect(validateEmail(longLocal)).toBe("Email local part too long")
  })

  it("trims and lowercases before validation", () => {
    expect(validateEmail("  User@Example.COM  ")).toBeNull()
  })
})

// =============================================================================
// validatePassword
// =============================================================================

describe("validatePassword", () => {
  it("returns null for a valid strong password", () => {
    expect(validatePassword("MyStr0ng!Pass")).toBeNull()
  })

  it("returns null for empty string (non-required)", () => {
    expect(validatePassword("")).toBeNull()
  })

  it("rejects password shorter than 12 characters", () => {
    expect(validatePassword("Sh0rt!")).toContain("at least 12 characters")
  })

  it("rejects password exceeding 128 characters", () => {
    const longPass = `Aa1!${"x".repeat(130)}`
    expect(validatePassword(longPass)).toContain("not exceed 128")
  })

  it("rejects password without uppercase", () => {
    expect(validatePassword("nouppercase1!abc")).toContain("uppercase")
  })

  it("rejects password without lowercase", () => {
    expect(validatePassword("NOLOWERCASE1!ABC")).toContain("lowercase")
  })

  it("rejects password without digit", () => {
    expect(validatePassword("NoDigitsHere!ab")).toContain("digit")
  })

  it("rejects password without special character", () => {
    expect(validatePassword("NoSpecial1abcd")).toContain("special character")
  })

  it("rejects common password patterns", () => {
    expect(validatePassword("Password123!x")).toContain("common")
    expect(validatePassword("Admin12345!xx")).toContain("common")
  })

  it("rejects repeated characters (5+)", () => {
    expect(validatePassword("aaaaaB1!cdefg")).toContain("common")
  })

  it("rejects sequential patterns at start", () => {
    expect(validatePassword("123Abcdefg!x")).toContain("common")
  })

  it("rejects keyboard patterns at start", () => {
    expect(validatePassword("qwertyABC1!x")).toContain("common")
  })
})

// =============================================================================
// getPasswordStrength
// =============================================================================

describe("getPasswordStrength", () => {
  it("returns weak for short passwords", () => {
    const result = getPasswordStrength("abc")
    expect(result.strength).toBe("weak")
    expect(result.score).toBeLessThan(5)
  })

  it("returns strong for fully qualifying passwords", () => {
    const result = getPasswordStrength("MyStr0ng!Pass1234567890")
    expect(result.strength).toBe("strong")
    expect(result.score).toBeGreaterThanOrEqual(7)
  })

  it("returns correct requirements breakdown", () => {
    const result = getPasswordStrength("abcdefghijkl")
    expect(result.requirements.length).toBe(true)
    expect(result.requirements.lowercase).toBe(true)
    expect(result.requirements.uppercase).toBe(false)
    expect(result.requirements.digits).toBe(false)
    expect(result.requirements.special).toBe(false)
  })

  it("provides feedback for unmet requirements", () => {
    const result = getPasswordStrength("abc")
    expect(result.feedback.length).toBeGreaterThan(0)
    expect(result.feedback).toContain("Use at least 12 characters")
  })

  it("gives bonus points for longer passwords", () => {
    const base = getPasswordStrength("MyStr0ng!Pas")
    const longer = getPasswordStrength("MyStr0ng!Pass1234")
    expect(longer.score).toBeGreaterThan(base.score)
  })

  it("marks common patterns in requirements", () => {
    const result = getPasswordStrength("password1234")
    expect(result.requirements.notCommon).toBe(false)
  })

  it("detects medium strength passwords", () => {
    const result = getPasswordStrength("Abcdefghijkl1")
    expect(result.strength).toBe("medium")
  })
})

// =============================================================================
// validateUsername
// =============================================================================

describe("validateUsername", () => {
  it("returns null for valid username", () => {
    expect(validateUsername("john-doe")).toBeNull()
    expect(validateUsername("user_123")).toBeNull()
  })

  it("returns null for empty string", () => {
    expect(validateUsername("")).toBeNull()
  })

  it("rejects username shorter than 3 characters", () => {
    expect(validateUsername("ab")).toContain("at least 3")
  })

  it("rejects username exceeding 30 characters", () => {
    expect(validateUsername("a".repeat(31))).toContain("not exceed 30")
  })

  it("rejects invalid characters", () => {
    expect(validateUsername("user name")).toContain("letters, numbers")
    expect(validateUsername("user@name")).toContain("letters, numbers")
    expect(validateUsername("user.name")).toContain("letters, numbers")
  })

  it("rejects usernames not starting with letter or number", () => {
    expect(validateUsername("_username")).toContain("start with")
    expect(validateUsername("-username")).toContain("start with")
  })

  it("rejects reserved usernames", () => {
    expect(validateUsername("admin")).toContain("reserved")
    expect(validateUsername("root")).toContain("reserved")
    expect(validateUsername("support")).toContain("reserved")
    expect(validateUsername("system")).toContain("reserved")
  })

  it("rejects excessive repeated characters", () => {
    expect(validateUsername("aaaa1")).toContain("repeated")
  })

  it("lowercases before validation", () => {
    expect(validateUsername("VALIDUSER")).toBeNull()
  })
})

// =============================================================================
// validatePhone
// =============================================================================

describe("validatePhone", () => {
  it("returns null for valid phone numbers", () => {
    expect(validatePhone("+1 (555) 123-4567")).toBeNull()
    expect(validatePhone("5551234567")).toBeNull()
  })

  it("returns null for empty string", () => {
    expect(validatePhone("")).toBeNull()
  })

  it("rejects invalid characters", () => {
    expect(validatePhone("555-ABC-1234")).toContain("Invalid phone")
  })

  it("rejects too few digits", () => {
    expect(validatePhone("123456")).toContain("between 7 and 15")
  })

  it("rejects too many digits", () => {
    expect(validatePhone("1234567890123456")).toContain("between 7 and 15")
  })

  it("accepts international format with plus", () => {
    expect(validatePhone("+44 20 7946 0958")).toBeNull()
  })
})

// =============================================================================
// validateName
// =============================================================================

describe("validateName", () => {
  it("returns null for valid names", () => {
    expect(validateName("John Doe")).toBeNull()
    expect(validateName("O'Brien")).toBeNull()
    expect(validateName("Jean-Paul")).toBeNull()
  })

  it("returns null for empty string", () => {
    expect(validateName("")).toBeNull()
  })

  it("rejects names exceeding 100 characters", () => {
    expect(validateName("A".repeat(101))).toContain("not exceed 100")
  })

  it("rejects names with invalid characters", () => {
    expect(validateName("Name123")).toContain("invalid characters")
    expect(validateName("Name@Work")).toContain("invalid characters")
  })

  it("rejects suspicious repeated patterns", () => {
    expect(validateName("aaaaaa")).toContain("suspicious")
  })

  it("accepts unicode names", () => {
    expect(validateName("Müller")).toBeNull()
    expect(validateName("Tanaka")).toBeNull()
  })
})
