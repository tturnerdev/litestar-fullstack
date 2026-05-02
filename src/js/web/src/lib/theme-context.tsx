import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react"

export type ThemeMode = "light" | "dark" | "system"
type ResolvedTheme = "light" | "dark"

type ThemeContextType = {
  mode: ThemeMode
  theme: ResolvedTheme
  setMode: (mode: ThemeMode) => void
  toggleTheme: () => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "light"
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

function resolveTheme(mode: ThemeMode): ResolvedTheme {
  if (mode === "system") return getSystemTheme()
  return mode
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("theme") as ThemeMode | null
      if (saved === "light" || saved === "dark" || saved === "system") return saved
    }
    return "light"
  })

  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolveTheme(mode))

  const setMode = useCallback((newMode: ThemeMode) => {
    setModeState(newMode)
    localStorage.setItem("theme", newMode)
  }, [])

  // Listen for system preference changes when in system mode
  useEffect(() => {
    if (mode !== "system") {
      setResolved(mode)
      return
    }

    setResolved(getSystemTheme())

    const mq = window.matchMedia("(prefers-color-scheme: dark)")
    const handler = (e: MediaQueryListEvent) => {
      setResolved(e.matches ? "dark" : "light")
    }
    mq.addEventListener("change", handler)
    return () => mq.removeEventListener("change", handler)
  }, [mode])

  // Apply the resolved theme to the document
  useEffect(() => {
    const root = window.document.documentElement
    root.classList.remove("light", "dark")
    root.classList.add(resolved)
  }, [resolved])

  const toggleTheme = useCallback(() => {
    setMode(resolved === "light" ? "dark" : "light")
  }, [resolved, setMode])

  const value = useMemo(() => ({ mode, theme: resolved, setMode, toggleTheme }), [mode, resolved, setMode, toggleTheme])

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider")
  }
  return context
}
