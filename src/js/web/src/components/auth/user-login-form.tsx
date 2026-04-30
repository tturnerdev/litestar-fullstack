import { zodResolver } from "@hookform/resolvers/zod"
import { useNavigate } from "@tanstack/react-router"
import { Eye, EyeOff, Lock, Mail } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { GitHubSignInButton } from "@/components/auth/github-signin-button"
import { GoogleSignInButton } from "@/components/auth/google-signin-button"
import { Icons } from "@/components/icons"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useOAuthConfig } from "@/hooks/use-oauth-config"
import { useAuthStore } from "@/lib/auth"
import { DEFAULT_AUTH_REDIRECT } from "@/lib/redirect-utils"
import { type LoginFormData, loginFormSchema } from "@/lib/validation"

interface UserLoginFormProps extends React.HTMLAttributes<HTMLDivElement> {
  redirectUrl?: string | null
}

export function UserLoginForm({ className, redirectUrl, ...props }: UserLoginFormProps) {
  const navigate = useNavigate()
  const { login, isLoading } = useAuthStore()
  const { data: oauthConfig } = useOAuthConfig()
  const [showPassword, setShowPassword] = useState(false)

  const googleOAuthEnabled = oauthConfig?.googleEnabled ?? false
  const githubOAuthEnabled = oauthConfig?.githubEnabled ?? false
  const hasOAuthProviders = googleOAuthEnabled || githubOAuthEnabled

  // Use redirect URL or default to /home
  const finalRedirect = redirectUrl || DEFAULT_AUTH_REDIRECT

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginFormSchema),
    defaultValues: {
      username: "",
      password: "",
    },
    mode: "onBlur",
    reValidateMode: "onBlur",
  })

  const onSubmit = async (data: LoginFormData) => {
    try {
      const result = await login(data.username, data.password)
      if (result.mfaRequired) {
        // Preserve redirect through MFA flow
        navigate({ to: "/mfa-challenge", search: { redirect: finalRedirect } })
        return
      }
      navigate({ to: finalRedirect })
    } catch (_error) {
      // Error is handled by useAuthStore
    }
  }

  return (
    <div className={className} {...props}>
      <div className="grid gap-5">
        {hasOAuthProviders && (
          <>
            <div className="grid gap-2">
              {googleOAuthEnabled && <GoogleSignInButton variant="signin" className="w-full" authRedirect={finalRedirect} />}
              {githubOAuthEnabled && <GitHubSignInButton variant="signin" className="w-full" authRedirect={finalRedirect} />}
            </div>
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-border/60" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-3 text-muted-foreground/70">or</span>
              </div>
            </div>
          </>
        )}

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-4">
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                      <Input className="pl-9" placeholder="name@example.com" autoCapitalize="none" autoComplete="email" autoCorrect="off" {...field} disabled={isLoading} />
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Password</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                      <Input
                        className="pl-9 pr-10"
                        placeholder="Enter your password"
                        type={showPassword ? "text" : "password"}
                        autoCapitalize="none"
                        autoCorrect="off"
                        autoComplete="current-password"
                        {...field}
                        disabled={isLoading}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3 text-muted-foreground/60 hover:text-foreground"
                        onClick={() => setShowPassword(!showPassword)}
                        tabIndex={-1}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="flex items-center">
              <label htmlFor="remember-me" className="flex cursor-pointer items-center gap-2 text-sm text-muted-foreground select-none">
                <Checkbox id="remember-me" />
                Remember me
              </label>
            </div>

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading && <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />}
              Sign In
            </Button>
          </form>
        </Form>
      </div>
    </div>
  )
}
