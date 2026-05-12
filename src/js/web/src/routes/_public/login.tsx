import { createFileRoute, redirect } from "@tanstack/react-router"
import { z } from "zod"
import { AuthForm } from "@/components/auth/auth-form"
import { useAuthStore } from "@/lib/auth"
import { getSafeRedirectUrl } from "@/lib/redirect-utils"

export const Route = createFileRoute("/_public/login")({
  validateSearch: (search) =>
    z
      .object({
        redirect: z.string().optional(),
      })
      .parse(search),
  beforeLoad: ({ search }) => {
    const { isAuthenticated } = useAuthStore.getState()
    if (isAuthenticated) {
      throw redirect({ to: getSafeRedirectUrl(search.redirect) })
    }
  },
  component: LoginPage,
})

function LoginPage() {
  return (
    <div className="flex-1">
      <AuthForm />
    </div>
  )
}
