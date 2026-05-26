import { create } from "zustand";
import { persist } from "zustand/middleware";

export type UserRole = "viewer" | "operator" | "intervener" | "admin";

interface AuthState {
  token: string | null;
  refreshToken: string | null;
  role: UserRole | null;
  username: string | null;
  isLoading: boolean;
  setAuth: (token: string, refreshToken: string, role: UserRole, username: string) => void;
  clearAuth: () => void;
  can: (action: "start_run" | "cancel_run" | "intervene" | "manage_settings") => boolean;
  init: () => void;
}

const ROLE_PERMISSIONS: Record<UserRole, Set<string>> = {
  viewer: new Set(),
  operator: new Set(["start_run", "cancel_run"]),
  intervener: new Set(["start_run", "cancel_run", "intervene"]),
  admin: new Set(["start_run", "cancel_run", "intervene", "manage_settings"]),
};

export const useAuth = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      refreshToken: null,
      role: null,
      username: null,
      isLoading: true,

      setAuth: (token, refreshToken, role, username) => {
        localStorage.setItem("access_token", token);
        localStorage.setItem("refresh_token", refreshToken);
        set({ token, refreshToken, role, username, isLoading: false });
      },

      clearAuth: () => {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        set({ token: null, refreshToken: null, role: null, username: null });
      },

      init: () => set({ isLoading: false }),

      can: (action) => {
        const { role } = get();
        if (!role) return false;
        return ROLE_PERMISSIONS[role].has(action);
      },
    }),
    {
      name: "sailor-auth",
      partialize: (s) => ({
        token: s.token,
        refreshToken: s.refreshToken,
        role: s.role,
        username: s.username,
      }),
    }
  )
);
