import { create } from "zustand"
import { persist } from "zustand/middleware"

export interface NotificationPreferencesState {
  systemAlerts: boolean
  taskUpdates: boolean
  teamActivity: boolean
  supportTickets: boolean
  deviceAlerts: boolean
  security: boolean
}

const DEFAULTS: NotificationPreferencesState = {
  systemAlerts: true,
  taskUpdates: true,
  teamActivity: true,
  supportTickets: true,
  deviceAlerts: true,
  security: true,
}

interface NotificationPreferencesStore extends NotificationPreferencesState {
  setPreference: (key: keyof NotificationPreferencesState, value: boolean) => void
  resetToDefaults: () => void
}

export const useNotificationPreferencesStore = create<NotificationPreferencesStore>()(
  persist(
    (set) => ({
      ...DEFAULTS,

      setPreference: (key, value) =>
        set((state) => {
          // System alerts cannot be disabled
          if (key === "systemAlerts") return state
          return { [key]: value }
        }),

      resetToDefaults: () => set({ ...DEFAULTS }),
    }),
    {
      name: "notification-preferences",
      partialize: (state) => ({
        systemAlerts: state.systemAlerts,
        taskUpdates: state.taskUpdates,
        teamActivity: state.teamActivity,
        supportTickets: state.supportTickets,
        deviceAlerts: state.deviceAlerts,
        security: state.security,
      }),
    },
  ),
)
