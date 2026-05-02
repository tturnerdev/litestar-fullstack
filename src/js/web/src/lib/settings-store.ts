import { create } from "zustand"
import { persist } from "zustand/middleware"

interface NotificationCategories {
  tickets: boolean
  teamUpdates: boolean
  deviceAlerts: boolean
  faxNotifications: boolean
}

const SETTINGS_DEFAULTS = {
  compactMode: false,
  emailNotifications: true,
  pushNotifications: false,
  notificationCategories: {
    tickets: true,
    teamUpdates: true,
    deviceAlerts: true,
    faxNotifications: false,
  } satisfies NotificationCategories,
  defaultPageSize: 25 as 10 | 25 | 50 | 100,
  dateFormat: "relative" as "relative" | "absolute",
  sidebarCollapsed: false,
  reducedMotion: false,
  highContrast: false,
  fontSize: "default" as "default" | "large" | "x-large",
}

interface SettingsState {
  // Appearance
  compactMode: boolean

  // Notifications
  emailNotifications: boolean
  pushNotifications: boolean
  notificationCategories: NotificationCategories

  // Display
  defaultPageSize: 10 | 25 | 50 | 100
  dateFormat: "relative" | "absolute"
  sidebarCollapsed: boolean

  // Accessibility
  reducedMotion: boolean
  highContrast: boolean
  fontSize: "default" | "large" | "x-large"

  // Actions
  setCompactMode: (value: boolean) => void
  setEmailNotifications: (value: boolean) => void
  setPushNotifications: (value: boolean) => void
  setNotificationCategory: (category: keyof NotificationCategories, value: boolean) => void
  setDefaultPageSize: (value: 10 | 25 | 50 | 100) => void
  setDateFormat: (value: "relative" | "absolute") => void
  setSidebarCollapsed: (value: boolean) => void
  setReducedMotion: (value: boolean) => void
  setHighContrast: (value: boolean) => void
  setFontSize: (value: "default" | "large" | "x-large") => void
  resetToDefaults: () => void
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      // Appearance defaults
      compactMode: SETTINGS_DEFAULTS.compactMode,

      // Notification defaults
      emailNotifications: SETTINGS_DEFAULTS.emailNotifications,
      pushNotifications: SETTINGS_DEFAULTS.pushNotifications,
      notificationCategories: { ...SETTINGS_DEFAULTS.notificationCategories },

      // Display defaults
      defaultPageSize: SETTINGS_DEFAULTS.defaultPageSize,
      dateFormat: SETTINGS_DEFAULTS.dateFormat,
      sidebarCollapsed: SETTINGS_DEFAULTS.sidebarCollapsed,

      // Accessibility defaults
      reducedMotion: SETTINGS_DEFAULTS.reducedMotion,
      highContrast: SETTINGS_DEFAULTS.highContrast,
      fontSize: SETTINGS_DEFAULTS.fontSize,

      // Actions
      setCompactMode: (value) => set({ compactMode: value }),
      setEmailNotifications: (value) => set({ emailNotifications: value }),
      setPushNotifications: (value) => set({ pushNotifications: value }),
      setNotificationCategory: (category, value) =>
        set((state) => ({
          notificationCategories: {
            ...state.notificationCategories,
            [category]: value,
          },
        })),
      setDefaultPageSize: (value) => set({ defaultPageSize: value }),
      setDateFormat: (value) => set({ dateFormat: value }),
      setSidebarCollapsed: (value) => set({ sidebarCollapsed: value }),
      setReducedMotion: (value) => set({ reducedMotion: value }),
      setHighContrast: (value) => set({ highContrast: value }),
      setFontSize: (value) => set({ fontSize: value }),
      resetToDefaults: () =>
        set({
          compactMode: SETTINGS_DEFAULTS.compactMode,
          emailNotifications: SETTINGS_DEFAULTS.emailNotifications,
          pushNotifications: SETTINGS_DEFAULTS.pushNotifications,
          notificationCategories: { ...SETTINGS_DEFAULTS.notificationCategories },
          defaultPageSize: SETTINGS_DEFAULTS.defaultPageSize,
          dateFormat: SETTINGS_DEFAULTS.dateFormat,
          sidebarCollapsed: SETTINGS_DEFAULTS.sidebarCollapsed,
          reducedMotion: SETTINGS_DEFAULTS.reducedMotion,
          highContrast: SETTINGS_DEFAULTS.highContrast,
          fontSize: SETTINGS_DEFAULTS.fontSize,
        }),
    }),
    {
      name: "settings-storage",
      partialize: (state) => ({
        compactMode: state.compactMode,
        emailNotifications: state.emailNotifications,
        pushNotifications: state.pushNotifications,
        notificationCategories: state.notificationCategories,
        defaultPageSize: state.defaultPageSize,
        dateFormat: state.dateFormat,
        sidebarCollapsed: state.sidebarCollapsed,
        reducedMotion: state.reducedMotion,
        highContrast: state.highContrast,
        fontSize: state.fontSize,
      }),
    },
  ),
)
