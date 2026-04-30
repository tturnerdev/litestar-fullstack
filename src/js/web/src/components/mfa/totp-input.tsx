import { useCallback, useEffect, useRef } from "react"

import { cn } from "@/lib/utils"

interface TotpInputProps {
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  autoFocus?: boolean
}

const NUM_DIGITS = 6

export function TotpInput({ value, onChange, disabled, autoFocus }: TotpInputProps) {
  const digits = value.padEnd(NUM_DIGITS, "").slice(0, NUM_DIGITS).split("")
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  useEffect(() => {
    if (autoFocus) {
      inputRefs.current[0]?.focus()
    }
  }, [autoFocus])

  const setDigit = useCallback(
    (index: number, digit: string) => {
      const next = [...digits]
      next[index] = digit
      onChange(next.join("").replace(/\D/g, "").slice(0, NUM_DIGITS))
    },
    [digits, onChange],
  )

  const focusIndex = useCallback((index: number) => {
    const clamped = Math.max(0, Math.min(index, NUM_DIGITS - 1))
    inputRefs.current[clamped]?.focus()
    inputRefs.current[clamped]?.select()
  }, [])

  const handleKeyDown = useCallback(
    (index: number, event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === "Backspace") {
        event.preventDefault()
        if (digits[index]) {
          setDigit(index, "")
        } else if (index > 0) {
          setDigit(index - 1, "")
          focusIndex(index - 1)
        }
      } else if (event.key === "ArrowLeft") {
        event.preventDefault()
        focusIndex(index - 1)
      } else if (event.key === "ArrowRight") {
        event.preventDefault()
        focusIndex(index + 1)
      }
    },
    [digits, setDigit, focusIndex],
  )

  const handleInput = useCallback(
    (index: number, event: React.FormEvent<HTMLInputElement>) => {
      const inputValue = (event.target as HTMLInputElement).value.replace(/\D/g, "")
      if (!inputValue) return

      if (inputValue.length === 1) {
        setDigit(index, inputValue)
        if (index < NUM_DIGITS - 1) {
          focusIndex(index + 1)
        }
      }
    },
    [setDigit, focusIndex],
  )

  const handlePaste = useCallback(
    (event: React.ClipboardEvent<HTMLInputElement>) => {
      event.preventDefault()
      const pasted = event.clipboardData.getData("text/plain").replace(/\D/g, "").slice(0, NUM_DIGITS)
      if (pasted) {
        onChange(pasted)
        focusIndex(Math.min(pasted.length, NUM_DIGITS - 1))
      }
    },
    [onChange, focusIndex],
  )

  return (
    <div className="flex items-center justify-center gap-2">
      {digits.map((digit, index) => (
        <div key={index} className="contents">
          <input
            ref={(el) => {
              inputRefs.current[index] = el
            }}
            type="text"
            inputMode="numeric"
            autoComplete={index === 0 ? "one-time-code" : "off"}
            maxLength={1}
            value={digit === " " ? "" : digit}
            disabled={disabled}
            onInput={(event) => handleInput(index, event)}
            onKeyDown={(event) => handleKeyDown(index, event)}
            onPaste={handlePaste}
            onFocus={(event) => event.target.select()}
            className={cn(
              "h-12 w-10 rounded-md border border-input bg-background text-center font-mono text-lg text-foreground shadow-sm",
              "outline-none transition-colors",
              "focus:border-primary focus:ring-1 focus:ring-primary",
              "disabled:cursor-not-allowed disabled:opacity-50",
            )}
            aria-label={`Digit ${index + 1}`}
          />
          {index === 2 && <span className="mx-1 text-muted-foreground select-none">&ndash;</span>}
        </div>
      ))}
    </div>
  )
}
