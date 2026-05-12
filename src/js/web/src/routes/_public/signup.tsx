import { createFileRoute, redirect } from "@tanstack/react-router"
import { AuthForm } from "@/components/auth/auth-form"
import { useAuthStore } from "@/lib/auth"
import { DEFAULT_AUTH_REDIRECT } from "@/lib/redirect-utils"

export const Route = createFileRoute("/_public/signup")({
  beforeLoad: () => {
    const { isAuthenticated } = useAuthStore.getState()
    if (isAuthenticated) {
      throw redirect({ to: DEFAULT_AUTH_REDIRECT })
    }
  },
  component: SignupPage,
})

function SignupPage() {
  return (
    <div className="flex-1">
      <AuthForm />
    </div>
  )
}
