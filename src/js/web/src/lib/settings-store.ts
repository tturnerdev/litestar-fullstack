import { create } from "zustand"
import { persist } from "zustand/middleware"

interface NotificationCategories {
  tickets: boolean
  teamUpdates: boolean
  deviceAlerts: boolean
  faxNotifications: boolean
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

  // Actions
  setCompactMode: (value: boolean) => void
  setEmailNotifications: (value: boolean) => void
  setPushNotifications: (value: boolean) => void
  setNotificationCategory: (category: keyof NotificationCategories, value: boolean) => void
  setDefaultPageSize: (value: 10 | 25 | 50 | 100) => void
  setDateFormat: (value: "relative" | "absolute") => void
  setSidebarCollapsed: (value: boolean) => void
}

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      // Appearance defaults
      compactMode: false,

      // Notification defaults
      emailNotifications: true,
      pushNotifications: false,
      notificationCategories: {
        tickets: true,
        teamUpdates: true,
        deviceAlerts: true,
        faxNotifications: false,
      },

      // Display defaults
      defaultPageSize: 25,
      dateFormat: "relative",
      sidebarCollapsed: false,

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
      }),
    },
  ),
)
