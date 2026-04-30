import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation } from "@tanstack/react-query"
import { createFileRoute, Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { ArrowLeft, CheckCircle2, KeyRound, Mail as MailIcon } from "lucide-react"
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
import { forgotPassword } from "@/lib/generated/api"

export const Route = createFileRoute("/_public/forgot-password")({
  component: ForgotPasswordPage,
})

const forgotPasswordSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
})

type ForgotPasswordForm = z.infer<typeof forgotPasswordSchema>

function ForgotPasswordPage() {
  const [isSuccess, setIsSuccess] = useState(false)
  const [submittedEmail, setSubmittedEmail] = useState("")

  const form = useForm<ForgotPasswordForm>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: {
      email: "",
    },
  })

  const { mutate: requestReset, isPending } = useMutation({
    mutationFn: async (data: ForgotPasswordForm) => {
      const response = await forgotPassword({
        body: { email: data.email },
      })

      if (response.error) {
        throw new Error((response.error as any).detail || "Failed to send reset email")
      }

      return response.data
    },
    onSuccess: (_, variables) => {
      setSubmittedEmail(variables.email)
      setIsSuccess(true)
      toast.success("Password reset email sent!")
    },
    onError: (error: Error) => {
      // Don't reveal if email exists or not for security
      if (error.message.includes("not found")) {
        setSubmittedEmail(form.getValues("email"))
        setIsSuccess(true)
        toast.success("If an account exists, a reset email has been sent")
      } else {
        toast.error(error.message || "Failed to send reset email")
      }
    },
  })

  const onSubmit = (data: ForgotPasswordForm) => {
    requestReset(data)
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
              <h1 className="text-2xl font-semibold tracking-tight">Check your email</h1>
              <p className="text-center text-sm text-muted-foreground">
                We sent a reset link to <strong>{submittedEmail}</strong>
              </p>
            </div>

            <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
              <CardContent className="space-y-4 px-6 py-6">
                <Alert>
                  <MailIcon className="h-4 w-4" />
                  <AlertDescription>Links expire in one hour. Check spam or request another email if needed.</AlertDescription>
                </Alert>
                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    setIsSuccess(false)
                    form.reset()
                  }}
                >
                  Send another email
                </Button>
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
            <h1 className="text-2xl font-semibold tracking-tight">Forgot your password?</h1>
            <p className="text-center text-sm text-muted-foreground">No worries. Enter your email and we'll send you a reset link.</p>
          </div>

          <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
            <CardContent className="px-6 py-6">
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                  <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <MailIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                            <Input className="pl-9" type="email" placeholder="you@example.com" autoComplete="email" {...field} />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={isPending}>
                    {isPending ? <Icons.spinner className="mr-2 h-4 w-4 animate-spin" /> : null}
                    {isPending ? "Sending..." : "Send reset email"}
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
