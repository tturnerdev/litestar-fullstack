import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation } from "@tanstack/react-query"
import { createFileRoute, Link, useNavigate, useSearch } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { AlertCircle, ArrowLeft, CheckCircle2, Eye, EyeOff, KeyRound, Lock } from "lucide-react"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { AuthHeroPanel } from "@/components/auth/auth-hero-panel"
import { Icons } from "@/components/icons"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { PasswordStrength } from "@/components/ui/password-strength"
import { validatePassword } from "@/hooks/use-validation"
import { resetPassword } from "@/lib/generated/api"

export const Route = createFileRoute("/_public/reset-password")({
  validateSearch: (search) =>
    z
      .object({
        token: z.string().optional(),
      })
      .parse(search),
  component: ResetPasswordPage,
})

const resetPasswordSchema = z
  .object({
    password: z
      .string()
      .min(1, "Password is required")
      .superRefine((value, ctx) => {
        const error = validatePassword(value)
        if (error) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: error })
        }
      }),
    confirmPassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  })

type ResetPasswordForm = z.infer<typeof resetPasswordSchema>

function ResetPasswordPage() {
  const navigate = useNavigate()
  const searchParams = useSearch({ from: "/_public/reset-password" })
  const token = searchParams.token
  const [isSuccess, setIsSuccess] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  const form = useForm<ResetPasswordForm>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: "",
      confirmPassword: "",
    },
  })

  const password = form.watch("password")

  const { mutate: doResetPassword, isPending } = useMutation({
    mutationFn: async (data: ResetPasswordForm) => {
      if (!token) {
        throw new Error("Reset token is missing")
      }

      const response = await resetPassword({
        body: {
          token,
          password: data.password,
          password_confirm: data.confirmPassword,
        },
      })

      if (response.error) {
        throw new Error((response.error as any).detail || "Failed to reset password")
      }

      return response.data
    },
    onSuccess: () => {
      setIsSuccess(true)
      toast.success("Password reset successfully!")
      setTimeout(() => {
        navigate({ to: "/login" })
      }, 3000)
    },
    onError: (error: Error) => {
      if (error.message.includes("expired") || error.message.includes("invalid")) {
        toast.error("This reset link has expired or is invalid. Please request a new one.")
      } else {
        toast.error(error.message || "Failed to reset password")
      }
    },
  })

  const onSubmit = (data: ResetPasswordForm) => {
    doResetPassword(data)
  }

  if (!token) {
    return (
      <div className="relative flex min-h-screen w-full">
        <AuthHeroPanel showTestimonial={false} description="Secure password recovery for your account." />
        <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
          <motion.div
            className="w-full max-w-md"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
          >
            <div className="mb-8 flex flex-col items-center space-y-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
                <AlertCircle className="h-6 w-6 text-destructive" />
              </div>
              <h1 className="text-2xl font-semibold tracking-tight">Invalid Reset Link</h1>
              <p className="text-center text-sm text-muted-foreground">This password reset link is invalid or incomplete.</p>
            </div>
            <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
              <CardContent className="space-y-4 px-6 py-6">
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>Please request a new password reset link.</AlertDescription>
                </Alert>
                <Button className="w-full" onClick={() => navigate({ to: "/forgot-password" })}>
                  Request new reset link
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    )
  }

  if (isSuccess) {
    return (
      <div className="relative flex min-h-screen w-full">
        <AuthHeroPanel showTestimonial={false} description="Secure password recovery for your account." />
        <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
          <motion.div
            className="w-full max-w-md"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
          >
            <div className="mb-8 flex flex-col items-center space-y-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-900/50">
                <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
              </div>
              <h1 className="text-2xl font-semibold tracking-tight">Password Reset Successfully</h1>
              <p className="text-center text-sm text-muted-foreground">Your password has been reset. Redirecting to login...</p>
            </div>
            <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
              <CardContent className="px-6 py-6">
                <Button className="w-full" onClick={() => navigate({ to: "/login" })}>
                  Go to login
                </Button>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    )
  }

  return (
    <div className="relative flex min-h-screen w-full">
      <AuthHeroPanel showTestimonial={false} description="Secure password recovery for your account." />
      <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-12 dark:bg-background">
        <motion.div
          className="w-full max-w-md"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
        >
          <div className="mb-8 flex flex-col items-center space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 shadow-sm">
              <KeyRound className="h-6 w-6 text-primary" />
            </div>
            <h1 className="text-2xl font-semibold tracking-tight">Reset your password</h1>
            <p className="text-center text-sm text-muted-foreground">Choose a strong password for your account</p>
          </div>

          <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
            <CardContent className="px-6 py-6">
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                  <FormField
                    control={form.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>New Password</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                            <Input className="pl-9 pr-10" type={showPassword ? "text" : "password"} placeholder="Enter new password" {...field} />
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
                        {password && <PasswordStrength password={password} className="pt-2" />}
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
                            <Input className="pl-9 pr-10" type={showConfirmPassword ? "text" : "password"} placeholder="Confirm new password" {...field} />
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              className="absolute right-0 top-0 h-full px-3 text-muted-foreground/60 hover:text-foreground"
                              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                              tabIndex={-1}
                            >
                              {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                            </Button>
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <Button type="submit" className="w-full" disabled={isPending}>
                    {isPending ? <Icons.spinner className="mr-2 h-4 w-4 animate-spin" /> : null}
                    {isPending ? "Resetting..." : "Reset password"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          <div className="mt-6 text-center">
            <Button asChild variant="ghost" size="sm">
              <Link to="/login">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back to login
              </Link>
            </Button>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
