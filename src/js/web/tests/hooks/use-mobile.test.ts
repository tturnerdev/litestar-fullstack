import { renderHook, act } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { useIsMobile } from "@/hooks/use-mobile"

describe("useIsMobile", () => {
  let listeners: Array<() => void>
  let mockAddEventListener: ReturnType<typeof vi.fn>
  let mockRemoveEventListener: ReturnType<typeof vi.fn>
  let originalMatchMedia: typeof window.matchMedia

  beforeEach(() => {
    listeners = []
    mockAddEventListener = vi.fn((_, cb) => {
      listeners.push(cb)
    })
    mockRemoveEventListener = vi.fn()

    originalMatchMedia = window.matchMedia

    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: mockAddEventListener,
      removeEventListener: mockRemoveEventListener,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }))
  })

  afterEach(() => {
    window.matchMedia = originalMatchMedia
    vi.restoreAllMocks()
  })

  it("returns false for desktop width (>= 768px)", () => {
    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true })

    const { result } = renderHook(() => useIsMobile())
    expect(result.current).toBe(false)
  })

  it("returns true for mobile width (< 768px)", () => {
    Object.defineProperty(window, "innerWidth", { value: 500, writable: true })

    const { result } = renderHook(() => useIsMobile())
    expect(result.current).toBe(true)
  })

  it("registers a matchMedia change listener", () => {
    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true })

    renderHook(() => useIsMobile())
    expect(mockAddEventListener).toHaveBeenCalledWith("change", expect.any(Function))
  })

  it("removes the listener on unmount", () => {
    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true })

    const { unmount } = renderHook(() => useIsMobile())
    unmount()
    expect(mockRemoveEventListener).toHaveBeenCalledWith("change", expect.any(Function))
  })

  it("updates when viewport changes from desktop to mobile", () => {
    Object.defineProperty(window, "innerWidth", { value: 1024, writable: true })

    const { result } = renderHook(() => useIsMobile())
    expect(result.current).toBe(false)

    // Simulate a resize to mobile
    Object.defineProperty(window, "innerWidth", { value: 500, writable: true })
    act(() => {
      for (const listener of listeners) {
        listener()
      }
    })

    expect(result.current).toBe(true)
  })
})
