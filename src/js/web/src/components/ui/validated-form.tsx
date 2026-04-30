/**
 * Validated form component with real-time validation
 */

import React, { useCallback, useEffect } from "react"
import { Button } from "@/components/ui/button"
import ValidatedInput from "@/components/ui/validated-input"
import useValidation, { type ValidationRule, type ValidationRules, validateEmail, validateName, validatePassword, validatePhone, validateUsername } from "@/hooks/use-validation"
import { cn } from "@/lib/utils"

export interface FormField {
  name: string
  label: string
  type?: "text" | "email" | "password" | "tel" | "url"
  placeholder?: string
  validationRule?: ValidationRule
  showPasswordStrength?: boolean
  helperText?: string
  autoComplete?: string
}

export interface ValidatedFormProps {
  fields: FormField[]
  initialValues?: Record<string, any>
  onSubmit: (values: Record<string, any>, isValid: boolean) => void
  submitLabel?: string
  submitDisabled?: boolean
  className?: string
  children?: React.ReactNode
  validateOnSubmit?: boolean
}

// Pre-defined validation rules for common field types
const getDefaultValidationRule = (field: FormField): ValidationRule => {
  const baseRule: ValidationRule = {
    required: true,
  }

  switch (field.type) {
    case "email":
      return {
        ...baseRule,
        custom: validateEmail,
      }

    case "password":
      return {
        ...baseRule,
        custom: validatePassword,
      }

    default:
      // Infer from field name
      if (field.name.toLowerCase().includes("email")) {
        return {
          ...baseRule,
          custom: validateEmail,
        }
      }
      if (field.name.toLowerCase().includes("password")) {
        return {
          ...baseRule,
          custom: validatePassword,
        }
      }
      if (field.name.toLowerCase().includes("username")) {
        return {
          ...baseRule,
          custom: validateUsername,
        }
      }
      if (field.name.toLowerCase().includes("phone")) {
        return {
          ...baseRule,
          custom: validatePhone,
        }
      }
      if (field.name.toLowerCase().includes("name")) {
        return {
          ...baseRule,
          custom: validateName,
        }
      }

      return baseRule
  }
}

export function ValidatedForm({
  fields,
  initialValues = {},
  onSubmit,
  submitLabel = "Submit",
  submitDisabled = false,
  className,
  children,
  validateOnSubmit = true,
}: ValidatedFormProps) {
  // Initialize form data
  const [formData, setFormData] = React.useState<Record<string, any>>(() => {
    const data: Record<string, any> = {}
    fields.forEach((field) => {
      data[field.name] = initialValues[field.name] || ""
    })
    return data
  })

  // Build validation rules
  const validationRules: ValidationRules = React.useMemo(() => {
    const rules: ValidationRules = {}
    fields.forEach((field) => {
      rules[field.name] = field.validationRule || getDefaultValidationRule(field)
    })
    return rules
  }, [fields])

  // Use validation hook
  const { errors, isValid, validate } = useValidation(formData, validationRules)

  // Update form data
  const updateField = useCallback((name: string, value: any) => {
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }))
  }, [])

  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (validateOnSubmit) {
      const formIsValid = validate()
      onSubmit(formData, formIsValid)
    } else {
      onSubmit(formData, isValid)
    }
  }

  // Sync external initial values
  useEffect(() => {
    if (Object.keys(initialValues).length > 0) {
      setFormData((prev) => ({
        ...prev,
        ...initialValues,
      }))
    }
  }, [initialValues])

  return (
    <form onSubmit={handleSubmit} className={cn("space-y-6", className)} noValidate>
      {/* Form fields */}
      <div className="space-y-4">
        {fields.map((field) => (
          <ValidatedInput
            key={field.name}
            label={field.label}
            type={field.type}
            placeholder={field.placeholder}
            value={formData[field.name]}
            error={errors[field.name]}
            validationRule={field.validationRule || getDefaultValidationRule(field)}
            showPasswordStrength={field.showPasswordStrength}
            helperText={field.helperText}
            autoComplete={field.autoComplete}
            onChange={(value) => updateField(field.name, value)}
          />
        ))}
      </div>

      {/* Custom children (additional form elements) */}
      {children}

      {/* Submit button */}
      <Button type="submit" disabled={submitDisabled || (validateOnSubmit ? false : !isValid)} className="w-full">
        {submitLabel}
      </Button>
    </form>
  )
}

export default ValidatedForm
