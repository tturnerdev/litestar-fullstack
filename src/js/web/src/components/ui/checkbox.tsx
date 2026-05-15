import { Check, Minus } from "lucide-react"
import { useState, type React } from "react"
import { cn } from "@/lib/utils"

interface CheckboxProps extends Omit<React.ComponentProps<"input">, "type"> {
  indeterminate?: boolean
}

function Checkbox({ className, indeterminate, checked, defaultChecked, ref, onChange, ...props }: CheckboxProps & { ref?: React.Ref<HTMLInputElement> }) {
  const isControlled = checked !== undefined
  const [internalChecked, setInternalChecked] = useState(defaultChecked ?? false)

  const innerRef = (node: HTMLInputElement | null) => {
    if (node) {
      node.indeterminate = indeterminate ?? false
    }
    if (typeof ref === "function") ref(node)
    else if (ref) (ref as React.MutableRefObject<HTMLInputElement | null>).current = node
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!isControlled) {
      setInternalChecked(e.target.checked)
    }
    onChange?.(e)
  }

  const isChecked = isControlled ? checked === true : internalChecked
  const isIndeterminate = indeterminate === true

  return (
    <span className="relative inline-flex h-4 w-4 shrink-0">
      <input
        type="checkbox"
        ref={innerRef}
        checked={isControlled ? checked : undefined}
        defaultChecked={isControlled ? undefined : defaultChecked}
        onChange={handleChange}
        className="peer absolute inset-0 h-4 w-4 cursor-pointer opacity-0 disabled:cursor-not-allowed"
        {...props}
      />
      <span
        className={cn(
          "pointer-events-none flex h-4 w-4 items-center justify-center rounded-sm border shadow-xs transition-colors",
          "peer-focus-visible:outline-none peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background",
          "peer-disabled:cursor-not-allowed peer-disabled:opacity-50",
          isChecked || isIndeterminate
            ? "border-primary bg-primary text-primary-foreground"
            : "border-input bg-background",
          className,
        )}
      >
        {isChecked && <Check className="h-3.5 w-3.5" strokeWidth={3} />}
        {!isChecked && isIndeterminate && <Minus className="h-3.5 w-3.5" strokeWidth={3} />}
      </span>
    </span>
  )
}

export { Checkbox }
