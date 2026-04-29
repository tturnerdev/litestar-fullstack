import { describe, expect, it } from "vitest"
import {
  checkPasswordStrength,
  emailSchema,
  formatRecoveryCode,
  isValidRecoveryCode,
  isValidTotpCode,
  loginFormSchema,
  passwordLoginSchema,
  passwordSchema,
  recoveryCodeSchema,
  registerFormSchema,
  resetPasswordFormSchema,
  changePasswordFormSchema,
  teamFormSchema,
  totpCodeSchema,
  usernameSchema,
} from "@/lib/validation"

// =============================================================================
// Field-level schemas
// =============================================================================

describe("emailSchema", () => {
  it("accepts valid emails", () => {
    expect(emailSchema.safeParse("user@example.com").success).toBe(true)
  })

  it("rejects empty string", () => {
    const result = emailSchema.safeParse("")
    expect(result.success).toBe(false)
  })

  it("rejects invalid format", () => {
    expect(emailSchema.safeParse("notanemail").success).toBe(false)
  })

  it("rejects strings exceeding 255 characters", () => {
    const longEmail = `${"a".repeat(250)}@b.com`
    expect(emailSchema.safeParse(longEmail).success).toBe(false)
  })
})

describe("passwordSchema", () => {
  it("accepts a strong password", () => {
    expect(passwordSchema.safeParse("StrongP4ss").success).toBe(true)
  })

  it("rejects passwords shorter than 8 characters", () => {
    expect(passwordSchema.safeParse("Sh0rt").success).toBe(false)
  })

  it("rejects passwords without uppercase", () => {
    expect(passwordSchema.safeParse("nouppercase1").success).toBe(false)
  })

  it("rejects passwords without lowercase", () => {
    expect(passwordSchema.safeParse("NOLOWERCASE1").success).toBe(false)
  })

  it("rejects passwords without digits", () => {
    expect(passwordSchema.safeParse("NoDigitsHere").success).toBe(false)
  })

  it("rejects passwords exceeding 128 characters", () => {
    const longPassword = `A1a${"x".repeat(130)}`
    expect(passwordSchema.safeParse(longPassword).success).toBe(false)
  })
})

describe("passwordLoginSchema", () => {
  it("accepts any non-empty string", () => {
    expect(passwordLoginSchema.safeParse("anything").success).toBe(true)
  })

  it("rejects empty string", () => {
    expect(passwordLoginSchema.safeParse("").success).toBe(false)
  })

  it("rejects strings exceeding 128 characters", () => {
    expect(passwordLoginSchema.safeParse("x".repeat(129)).success).toBe(false)
  })
})

describe("usernameSchema", () => {
  it("accepts valid usernames", () => {
    expect(usernameSchema.safeParse("john_doe").success).toBe(true)
    expect(usernameSchema.safeParse("user-123").success).toBe(true)
  })

  it("rejects usernames shorter than 3 characters", () => {
    expect(usernameSchema.safeParse("ab").success).toBe(false)
  })

  it("rejects usernames exceeding 30 characters", () => {
    expect(usernameSchema.safeParse("a".repeat(31)).success).toBe(false)
  })

  it("rejects usernames with invalid characters", () => {
    expect(usernameSchema.safeParse("user name").success).toBe(false)
    expect(usernameSchema.safeParse("user@name").success).toBe(false)
  })

  it("allows undefined (optional field)", () => {
    expect(usernameSchema.safeParse(undefined).success).toBe(true)
  })
})

describe("totpCodeSchema", () => {
  it("accepts exactly 6 digits", () => {
    expect(totpCodeSchema.safeParse("123456").success).toBe(true)
  })

  it("rejects fewer than 6 digits", () => {
    expect(totpCodeSchema.safeParse("12345").success).toBe(false)
  })

  it("rejects more than 6 digits", () => {
    expect(totpCodeSchema.safeParse("1234567").success).toBe(false)
  })

  it("rejects non-digit characters", () => {
    expect(totpCodeSchema.safeParse("12345a").success).toBe(false)
  })
})

describe("recoveryCodeSchema", () => {
  it("accepts 8-character alphanumeric codes", () => {
    expect(recoveryCodeSchema.safeParse("ABCD1234").success).toBe(true)
  })

  it("accepts 16-character codes", () => {
    expect(recoveryCodeSchema.safeParse("ABCDEFGH12345678").success).toBe(true)
  })

  it("rejects codes shorter than 8 characters", () => {
    expect(recoveryCodeSchema.safeParse("ABC1234").success).toBe(false)
  })

  it("rejects codes longer than 16 characters", () => {
    expect(recoveryCodeSchema.safeParse("A".repeat(17)).success).toBe(false)
  })

  it("rejects codes with special characters", () => {
    expect(recoveryCodeSchema.safeParse("ABCD-123").success).toBe(false)
  })
})

// =============================================================================
// Form schemas
// =============================================================================

describe("loginFormSchema", () => {
  it("accepts valid login data", () => {
    const result = loginFormSchema.safeParse({ username: "user@test.com", password: "password123" })
    expect(result.success).toBe(true)
  })

  it("rejects empty username", () => {
    const result = loginFormSchema.safeParse({ username: "", password: "password123" })
    expect(result.success).toBe(false)
  })

  it("rejects empty password", () => {
    const result = loginFormSchema.safeParse({ username: "user", password: "" })
    expect(result.success).toBe(false)
  })
})

describe("registerFormSchema", () => {
  const validData = {
    email: "user@example.com",
    password: "StrongP4ssword",
    passwordConfirm: "StrongP4ssword",
  }

  it("accepts valid registration data", () => {
    expect(registerFormSchema.safeParse(validData).success).toBe(true)
  })

  it("rejects mismatched passwords", () => {
    const result = registerFormSchema.safeParse({
      ...validData,
      passwordConfirm: "DifferentPass1",
    })
    expect(result.success).toBe(false)
  })

  it("rejects invalid email", () => {
    const result = registerFormSchema.safeParse({
      ...validData,
      email: "notanemail",
    })
    expect(result.success).toBe(false)
  })
})

describe("resetPasswordFormSchema", () => {
  const validData = {
    password: "NewStrongP4ss",
    passwordConfirm: "NewStrongP4ss",
    token: "reset-token-abc",
  }

  it("accepts valid reset data", () => {
    expect(resetPasswordFormSchema.safeParse(validData).success).toBe(true)
  })

  it("rejects mismatched passwords", () => {
    const result = resetPasswordFormSchema.safeParse({
      ...validData,
      passwordConfirm: "Mismatch1234",
    })
    expect(result.success).toBe(false)
  })

  it("rejects missing token", () => {
    const result = resetPasswordFormSchema.safeParse({
      ...validData,
      token: "",
    })
    expect(result.success).toBe(false)
  })
})

describe("changePasswordFormSchema", () => {
  const validData = {
    currentPassword: "oldpassword",
    newPassword: "NewStrongP4ss",
    newPasswordConfirm: "NewStrongP4ss",
  }

  it("accepts valid change password data", () => {
    expect(changePasswordFormSchema.safeParse(validData).success).toBe(true)
  })

  it("rejects when new password matches current", () => {
    const result = changePasswordFormSchema.safeParse({
      currentPassword: "NewStrongP4ss",
      newPassword: "NewStrongP4ss",
      newPasswordConfirm: "NewStrongP4ss",
    })
    expect(result.success).toBe(false)
  })

  it("rejects mismatched new password confirmation", () => {
    const result = changePasswordFormSchema.safeParse({
      ...validData,
      newPasswordConfirm: "DifferentP4ss",
    })
    expect(result.success).toBe(false)
  })
})

describe("teamFormSchema", () => {
  it("accepts valid team data", () => {
    const result = teamFormSchema.safeParse({ name: "My Team" })
    expect(result.success).toBe(true)
  })

  it("rejects team name shorter than 2 characters", () => {
    const result = teamFormSchema.safeParse({ name: "X" })
    expect(result.success).toBe(false)
  })

  it("rejects team name exceeding 50 characters", () => {
    const result = teamFormSchema.safeParse({ name: "T".repeat(51) })
    expect(result.success).toBe(false)
  })

  it("accepts optional description", () => {
    const result = teamFormSchema.safeParse({ name: "My Team", description: "A description" })
    expect(result.success).toBe(true)
  })

  it("rejects description exceeding 500 characters", () => {
    const result = teamFormSchema.safeParse({ name: "My Team", description: "D".repeat(501) })
    expect(result.success).toBe(false)
  })
})

// =============================================================================
// Helper functions
// =============================================================================

describe("checkPasswordStrength", () => {
  it("returns all-false for empty password", () => {
    const result = checkPasswordStrength("")
    expect(result.isValid).toBe(false)
    expect(result.minLength).toBe(false)
    expect(result.hasUppercase).toBe(false)
    expect(result.hasLowercase).toBe(false)
    expect(result.hasNumber).toBe(false)
  })

  it("returns valid for a fully qualifying password", () => {
    const result = checkPasswordStrength("StrongP4ss")
    expect(result.isValid).toBe(true)
    expect(result.minLength).toBe(true)
    expect(result.hasUppercase).toBe(true)
    expect(result.hasLowercase).toBe(true)
    expect(result.hasNumber).toBe(true)
  })

  it("detects missing uppercase", () => {
    const result = checkPasswordStrength("nouppercase1")
    expect(result.hasUppercase).toBe(false)
    expect(result.isValid).toBe(false)
  })

  it("detects missing lowercase", () => {
    const result = checkPasswordStrength("NOLOWERCASE1")
    expect(result.hasLowercase).toBe(false)
    expect(result.isValid).toBe(false)
  })

  it("detects missing number", () => {
    const result = checkPasswordStrength("NoNumbersHere")
    expect(result.hasNumber).toBe(false)
    expect(result.isValid).toBe(false)
  })

  it("detects insufficient length", () => {
    const result = checkPasswordStrength("Ab1")
    expect(result.minLength).toBe(false)
    expect(result.isValid).toBe(false)
  })
})

describe("isValidTotpCode", () => {
  it("returns true for 6-digit code", () => {
    expect(isValidTotpCode("123456")).toBe(true)
  })

  it("returns false for non-digits", () => {
    expect(isValidTotpCode("12345a")).toBe(false)
  })

  it("returns false for wrong length", () => {
    expect(isValidTotpCode("12345")).toBe(false)
    expect(isValidTotpCode("1234567")).toBe(false)
  })

  it("returns false for empty string", () => {
    expect(isValidTotpCode("")).toBe(false)
  })
})

describe("isValidRecoveryCode", () => {
  it("returns true for 8-char alphanumeric code", () => {
    expect(isValidRecoveryCode("ABCD1234")).toBe(true)
  })

  it("returns true for 16-char alphanumeric code", () => {
    expect(isValidRecoveryCode("ABCDEFGH12345678")).toBe(true)
  })

  it("returns false for codes shorter than 8 chars", () => {
    expect(isValidRecoveryCode("ABC1234")).toBe(false)
  })

  it("returns false for codes longer than 16 chars", () => {
    expect(isValidRecoveryCode("A".repeat(17))).toBe(false)
  })

  it("returns false for codes with special characters", () => {
    expect(isValidRecoveryCode("ABCD-123")).toBe(false)
  })
})

describe("formatRecoveryCode", () => {
  it("formats 8-char code with dash at position 4", () => {
    expect(formatRecoveryCode("abcd1234")).toBe("ABCD-1234")
  })

  it("uppercases the output", () => {
    expect(formatRecoveryCode("abcdefgh")).toBe("ABCD-EFGH")
  })

  it("returns short codes without dash", () => {
    expect(formatRecoveryCode("abcd")).toBe("ABCD")
  })

  it("strips non-alphanumeric characters before formatting", () => {
    expect(formatRecoveryCode("ab-cd-12-34")).toBe("ABCD-1234")
  })

  it("handles empty string", () => {
    expect(formatRecoveryCode("")).toBe("")
  })
})
