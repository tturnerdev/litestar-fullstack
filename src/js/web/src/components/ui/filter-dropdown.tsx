import { ListFilterIcon } from "lucide-react"
import { useState } from "react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"

export interface FilterOption {
  value: string
  label: string
}

interface FilterDropdownProps {
  label: string
  options: FilterOption[]
  selected: string[]
  onChange: (selected: string[]) => void
}

export function FilterDropdown({ label, options, selected, onChange }: FilterDropdownProps) {
  const [open, setOpen] = useState(false)

  function handleToggle(value: string) {
    if (selected.includes(value)) {
      onChange(selected.filter((v) => v !== value))
    } else {
      onChange([...selected, value])
    }
  }

  function handleClear() {
    onChange([])
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="gap-1.5">
          <ListFilterIcon className="size-3.5" />
          {label}
          {selected.length > 0 && (
            <Badge variant="secondary" className="ml-1 size-5 justify-center rounded-full px-0 text-[10px]">
              {selected.length}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-52 p-2">
        <div className="space-y-1">
          {options.map((option) => (
            <button
              type="button"
              key={option.value}
              className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground"
              onClick={() => handleToggle(option.value)}
            >
              <Checkbox checked={selected.includes(option.value)} onChange={() => handleToggle(option.value)} />
              {option.label}
            </button>
          ))}
        </div>
        {selected.length > 0 && (
          <>
            <div className="-mx-2 my-2 h-px bg-border" />
            <Button variant="ghost" size="sm" className="w-full justify-center text-xs" onClick={handleClear}>
              Clear filters
            </Button>
          </>
        )}
      </PopoverContent>
    </Popover>
  )
}
