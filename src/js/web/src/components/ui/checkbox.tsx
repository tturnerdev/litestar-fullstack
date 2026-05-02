import type * as React from "react"
import { cn } from "@/lib/utils"

interface CheckboxProps extends Omit<React.ComponentProps<"input">, "type"> {
  indeterminate?: boolean
}

function Checkbox({ className, indeterminate, ref, ...props }: CheckboxProps & { ref?: React.Ref<HTMLInputElement> }) {
  const innerRef = (node: HTMLInputElement | null) => {
    if (node) {
      node.indeterminate = indeterminate ?? false
    }
    if (typeof ref === "function") ref(node)
    else if (ref) (ref as React.MutableRefObject<HTMLInputElement | null>).current = node
  }

  return (
    <input
      type="checkbox"
      ref={innerRef}
      className={cn(
        "h-4 w-4 shrink-0 rounded border border-input bg-background shadow-xs transition-colors",
        "checked:border-primary checked:bg-primary checked:text-primary-foreground",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "cursor-pointer accent-primary",
        className,
      )}
      {...props}
    />
  )
}

export { Checkbox }
