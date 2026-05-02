import { zodResolver } from "@hookform/resolvers/zod"
import { useNavigate } from "@tanstack/react-router"
import { Eye, EyeOff, Lock, Mail, User } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { GitHubSignInButton } from "@/components/auth/github-signin-button"
import { GoogleSignInButton } from "@/components/auth/google-signin-button"
import { Icons } from "@/components/icons"
import { Button } from "@/components/ui/button"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { PasswordStrength } from "@/components/ui/password-strength"
import { useOAuthConfig } from "@/hooks/use-oauth-config"
import { validatePassword } from "@/hooks/use-validation"
import { useAuthStore } from "@/lib/auth"
import { accountRegister } from "@/lib/generated/api"
import { DEFAULT_AUTH_REDIRECT } from "@/lib/redirect-utils"

const signupSchema = z
  .object({
    email: z.string().email("Invalid email address"),
    password: z
      .string()
      .min(1, "Password is required")
      .superRefine((value, ctx) => {
        const error = validatePassword(value)
        if (error) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: error })
        }
      }),
    name: z.string().min(1, "Name is required"),
    confirmPassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  })

type SignupFormData = z.infer<typeof signupSchema>

interface UserSignupFormProps extends React.HTMLAttributes<HTMLDivElement> {
  redirectUrl?: string | null
}

export function UserSignupForm({ className, redirectUrl, ...props }: UserSignupFormProps) {
  const navigate = useNavigate()
  const { isLoading } = useAuthStore()
  const { data: oauthConfig } = useOAuthConfig()
  const finalRedirect = redirectUrl || DEFAULT_AUTH_REDIRECT
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const googleOAuthEnabled = oauthConfig?.googleEnabled ?? false
  const githubOAuthEnabled = oauthConfig?.githubEnabled ?? false
  const hasOAuthProviders = googleOAuthEnabled || githubOAuthEnabled

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      email: "",
      password: "",
      name: "",
      confirmPassword: "",
    },
    mode: "onBlur",
    reValidateMode: "onBlur",
  })
  const passwordValue = form.watch("password")

  const onSubmit = async (data: SignupFormData) => {
    try {
      const response = await accountRegister({
        body: { email: data.email, password: data.password, name: data.name },
      })

      if (response.data) {
        toast.success("Account created! Please check your email to verify your account.")
        // Preserve redirect URL when navigating to login
        const loginSearch = redirectUrl ? { redirect: redirectUrl } : undefined
        navigate({ to: "/login", search: loginSearch })
        return
      }

      toast.error(response.error?.detail || "Signup failed")
    } catch (_error) {
      toast.error("An error occurred during signup")
    }
  }

  return (
    <div className={className} {...props}>
      <div className="grid gap-5">
        {hasOAuthProviders && (
          <>
            <div className="grid gap-2">
              {googleOAuthEnabled && <GoogleSignInButton variant="signup" className="w-full" authRedirect={finalRedirect} onSuccess={() => navigate({ to: finalRedirect })} />}
              {githubOAuthEnabled && <GitHubSignInButton variant="signup" className="w-full" authRedirect={finalRedirect} onSuccess={() => navigate({ to: finalRedirect })} />}
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
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <User className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                      <Input className="pl-9" placeholder="Enter your name" autoCapitalize="none" autoComplete="name" autoCorrect="off" {...field} disabled={isLoading} />
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                      <Input
                        className="pl-9"
                        placeholder="name@example.com"
                        autoCapitalize="none"
                        autoComplete="email"
                        autoCorrect="off"
                        {...field}
                        type="email"
                        disabled={isLoading}
                      />
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
                        placeholder="Create a password"
                        autoCapitalize="none"
                        autoComplete="new-password"
                        autoCorrect="off"
                        {...field}
                        type={showPassword ? "text" : "password"}
                        disabled={isLoading}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3 text-muted-foreground/60 hover:text-foreground"
                        onClick={() => setShowPassword(!showPassword)}
                        tabIndex={-1}
                        aria-label={showPassword ? "Hide password" : "Show password"}
                      >
                        {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </FormControl>
                  <PasswordStrength password={passwordValue} />
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Confirm Password</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                      <Input
                        className="pl-9 pr-10"
                        placeholder="Confirm your password"
                        autoCapitalize="none"
                        autoComplete="new-password"
                        autoCorrect="off"
                        {...field}
                        type={showConfirmPassword ? "text" : "password"}
                        disabled={isLoading}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        className="absolute right-0 top-0 h-full px-3 text-muted-foreground/60 hover:text-foreground"
                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        tabIndex={-1}
                        aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                      >
                        {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading && <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />}
              Create Account
            </Button>
          </form>
        </Form>
      </div>
    </div>
  )
}
