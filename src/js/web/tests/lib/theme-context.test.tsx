import { renderHook, act } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ThemeProvider, useTheme } from "@/lib/theme-context"

describe("ThemeProvider + useTheme", () => {
  let store: Record<string, string>

  beforeEach(() => {
    store = {}

    const mockStorage = {
      getItem: vi.fn((key: string) => store[key] ?? null),
      setItem: vi.fn((key: string, value: string) => {
        store[key] = value
      }),
      removeItem: vi.fn((key: string) => {
        delete store[key]
      }),
      clear: vi.fn(() => {
        store = {}
      }),
      get length() {
        return Object.keys(store).length
      },
      key: vi.fn((index: number) => Object.keys(store)[index] ?? null),
    }

    Object.defineProperty(window, "localStorage", {
      value: mockStorage,
      writable: true,
      configurable: true,
    })

    document.documentElement.classList.remove("light", "dark")
  })

  afterEach(() => {
    document.documentElement.classList.remove("light", "dark")
  })

  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <ThemeProvider>{children}</ThemeProvider>
  )

  it("defaults to light theme when no saved preference", () => {
    const { result } = renderHook(() => useTheme(), { wrapper })
    expect(result.current.theme).toBe("light")
  })

  it("applies the theme class to document root", () => {
    renderHook(() => useTheme(), { wrapper })
    expect(document.documentElement.classList.contains("light")).toBe(true)
  })

  it("persists theme to localStorage on toggle", () => {
    const { result } = renderHook(() => useTheme(), { wrapper })
    act(() => {
      result.current.toggleTheme()
    })
    expect(localStorage.setItem).toHaveBeenCalledWith("theme", "dark")
  })

  it("toggles from light to dark", () => {
    const { result } = renderHook(() => useTheme(), { wrapper })

    act(() => {
      result.current.toggleTheme()
    })

    expect(result.current.theme).toBe("dark")
    expect(document.documentElement.classList.contains("dark")).toBe(true)
    expect(document.documentElement.classList.contains("light")).toBe(false)
    expect(localStorage.setItem).toHaveBeenCalledWith("theme", "dark")
  })

  it("toggles from dark to light", () => {
    store["theme"] = "dark"

    const { result } = renderHook(() => useTheme(), { wrapper })
    expect(result.current.theme).toBe("dark")

    act(() => {
      result.current.toggleTheme()
    })

    expect(result.current.theme).toBe("light")
  })

  it("reads saved theme from localStorage on mount", () => {
    store["theme"] = "dark"

    const { result } = renderHook(() => useTheme(), { wrapper })
    expect(result.current.theme).toBe("dark")
  })

  it("throws when useTheme is used without ThemeProvider", () => {
    expect(() => {
      renderHook(() => useTheme())
    }).toThrow("useTheme must be used within a ThemeProvider")
  })
})
