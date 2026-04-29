import { useCallback, useEffect, useRef } from "react"

export type Modifier = "ctrl" | "shift" | "alt" | "meta"

export interface KeyboardShortcut {
  /** The key to match (e.g., "k", "n", "?"). Case-insensitive. */
  key: string
  /** Modifier keys required. "ctrl" matches both Ctrl (Windows/Linux) and Meta/Cmd (Mac). */
  modifiers?: Modifier[]
  /** Action to execute when the shortcut fires. */
  action: () => void
  /** Human-readable description shown in the help dialog. */
  description: string
  /** Category for grouping in the help dialog. */
  category?: "navigation" | "actions" | "help"
}

export interface SequenceShortcut {
  /** First key in the sequence (e.g., "g"). */
  prefix: string
  /** Second key in the sequence (e.g., "h" for home). */
  key: string
  /** Action to execute when the full sequence fires. */
  action: () => void
  /** Human-readable description shown in the help dialog. */
  description: string
  /** Category for grouping in the help dialog. */
  category?: "navigation" | "actions" | "help"
  /** Time window in ms for the second key press. Default: 1000. */
  timeout?: number
}

interface UseKeyboardShortcutsOptions {
  shortcuts?: KeyboardShortcut[]
  sequences?: SequenceShortcut[]
  /** Called when a sequence prefix key (e.g., "g") is pressed. */
  onSequenceStart?: (prefix: string) => void
  /** Called when the sequence times out or completes. */
  onSequenceEnd?: () => void
  /** Whether shortcuts are enabled. Default: true. */
  enabled?: boolean
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!target || !(target instanceof HTMLElement)) return false
  const tagName = target.tagName.toLowerCase()
  if (tagName === "input" || tagName === "textarea" || tagName === "select") return true
  if (target.isContentEditable) return true
  return false
}

function matchesModifiers(e: KeyboardEvent, modifiers: Modifier[] | undefined): boolean {
  const required = new Set(modifiers ?? [])

  // "ctrl" modifier matches either Ctrl or Meta (for Mac Cmd compatibility)
  const ctrlRequired = required.has("ctrl")
  const metaRequired = required.has("meta")
  const ctrlOrMeta = ctrlRequired || metaRequired
  const ctrlSatisfied = ctrlOrMeta ? e.ctrlKey || e.metaKey : !e.ctrlKey && !e.metaKey

  const shiftSatisfied = required.has("shift") ? e.shiftKey : !e.shiftKey
  const altSatisfied = required.has("alt") ? e.altKey : !e.altKey

  return ctrlSatisfied && shiftSatisfied && altSatisfied
}

export function useKeyboardShortcuts({ shortcuts = [], sequences = [], onSequenceStart, onSequenceEnd, enabled = true }: UseKeyboardShortcutsOptions) {
  const sequencePrefixRef = useRef<string | null>(null)
  const sequenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearSequence = useCallback(() => {
    sequencePrefixRef.current = null
    if (sequenceTimerRef.current) {
      clearTimeout(sequenceTimerRef.current)
      sequenceTimerRef.current = null
    }
    onSequenceEnd?.()
  }, [onSequenceEnd])

  useEffect(() => {
    if (!enabled) return

    const handleKeyDown = (e: KeyboardEvent) => {
      // Skip when typing in editable fields
      if (isEditableTarget(e.target)) return

      // Skip if only modifier keys are pressed
      if (["Control", "Shift", "Alt", "Meta"].includes(e.key)) return

      const pressedKey = e.key.toLowerCase()

      // Check if we're in a sequence and this is the second key
      if (sequencePrefixRef.current) {
        const prefix = sequencePrefixRef.current
        clearSequence()

        for (const seq of sequences) {
          if (seq.prefix.toLowerCase() === prefix && seq.key.toLowerCase() === pressedKey) {
            e.preventDefault()
            seq.action()
            return
          }
        }
        // No matching second key -- fall through to regular shortcut matching
      }

      // Check regular shortcuts (those with modifiers or single keys)
      for (const shortcut of shortcuts) {
        const hasModifiers = shortcut.modifiers && shortcut.modifiers.length > 0
        if (shortcut.key.toLowerCase() === pressedKey && matchesModifiers(e, shortcut.modifiers)) {
          // For "?" key, the actual key pressed is "?" which requires shift on most keyboards.
          // matchesModifiers won't require shift unless specified, so "?" only fires
          // when the literal "?" character is produced (which inherently involves shift).
          if (!hasModifiers && (e.ctrlKey || e.metaKey || e.altKey)) continue
          e.preventDefault()
          shortcut.action()
          return
        }
      }

      // Check if this key starts a sequence
      const isSequencePrefix = sequences.some((seq) => seq.prefix.toLowerCase() === pressedKey)
      if (isSequencePrefix && !e.ctrlKey && !e.metaKey && !e.altKey && !e.shiftKey) {
        e.preventDefault()
        sequencePrefixRef.current = pressedKey
        onSequenceStart?.(pressedKey)

        const timeout = sequences.find((s) => s.prefix.toLowerCase() === pressedKey)?.timeout ?? 1000
        sequenceTimerRef.current = setTimeout(clearSequence, timeout)
      }
    }

    document.addEventListener("keydown", handleKeyDown)
    return () => {
      document.removeEventListener("keydown", handleKeyDown)
      if (sequenceTimerRef.current) {
        clearTimeout(sequenceTimerRef.current)
      }
    }
  }, [enabled, shortcuts, sequences, onSequenceStart, clearSequence])
}
