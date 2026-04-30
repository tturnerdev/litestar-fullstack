import { Link, useRouter } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import { Icons } from "@/components/icons"
import { buttonVariants } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { validateRedirectUrl } from "@/lib/redirect-utils"
import { cn } from "@/lib/utils"

import { AuthHeroPanel } from "./auth-hero-panel"
import { UserLoginForm } from "./user-login-form"
import { UserSignupForm } from "./user-signup-form"

export function AuthForm() {
  const router = useRouter()
  const pathname = router.state.location.pathname

  const isLogin = pathname === "/login"

  // Get redirect param from URL search params
  const searchParams = new URLSearchParams(router.state.location.searchStr)
  const redirectParam = searchParams.get("redirect")
  const validatedRedirect = validateRedirectUrl(redirectParam)

  // Build toggle URL with redirect preserved
  const togglePath = isLogin ? "/signup" : "/login"
  const toggleSearch = validatedRedirect ? { redirect: validatedRedirect } : undefined

  return (
    <div className="relative flex min-h-screen w-full">
      {/* Left panel with RetroGrid - hidden on mobile */}
      <AuthHeroPanel title="Litestar Fullstack" description="Build high-performance web applications with Python and React. Seamless SPA experience powered by Vite." />

      {/* Right panel with form - centers on mobile when hero is hidden */}
      <div className="flex flex-1 flex-col items-center justify-center bg-brand-gray-light px-4 py-8 dark:bg-background sm:px-6 lg:px-8">
        {/* Toggle link in top right */}
        <Link to={togglePath} search={toggleSearch} className={cn(buttonVariants({ variant: "ghost" }), "absolute top-4 right-4 md:top-8 md:right-8")}>
          {isLogin ? "Need an account?" : "Sign in"}
        </Link>

        <motion.div
          className="mx-auto flex w-full flex-col justify-center sm:w-[400px]"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, ease: [0.25, 0.1, 0.25, 1] }}
        >
          {/* Branding */}
          <div className="mb-8 flex flex-col items-center space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 shadow-sm">
              <Icons.logo className="h-7 w-7 text-primary" />
            </div>
            <AnimatePresence mode="wait">
              <motion.div
                key={isLogin ? "login" : "signup"}
                className="flex flex-col items-center space-y-1"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <h1 className="text-2xl font-semibold tracking-tight">
                  {isLogin ? "Welcome back" : "Create account"}
                </h1>
                <p className="text-sm text-muted-foreground">
                  {isLogin ? "Sign in to your account to continue" : "Enter your details to get started"}
                </p>
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Form card */}
          <Card className="border-border/50 bg-card/80 shadow-lg backdrop-blur-sm dark:bg-card/60">
            <CardContent className="px-6 py-6">
              <AnimatePresence mode="wait">
                <motion.div
                  key={isLogin ? "login-form" : "signup-form"}
                  initial={{ opacity: 0, x: isLogin ? -8 : 8 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: isLogin ? 8 : -8 }}
                  transition={{ duration: 0.25, ease: [0.25, 0.1, 0.25, 1] }}
                >
                  {isLogin ? <UserLoginForm redirectUrl={validatedRedirect} /> : <UserSignupForm redirectUrl={validatedRedirect} />}
                </motion.div>
              </AnimatePresence>
            </CardContent>
          </Card>

          {/* Footer links */}
          <div className="mt-6 space-y-3">
            {isLogin && (
              <div className="text-center">
                <Link to="/forgot-password" className="text-sm text-muted-foreground underline-offset-4 transition-colors hover:text-primary hover:underline">
                  Forgot your password?
                </Link>
              </div>
            )}

            <p className="px-4 text-center text-xs text-muted-foreground/80">
              By continuing, you agree to our{" "}
              <Link to="/terms" className="underline underline-offset-4 hover:text-primary">
                Terms of Service
              </Link>{" "}
              and{" "}
              <Link to="/privacy" className="underline underline-offset-4 hover:text-primary">
                Privacy Policy
              </Link>
              .
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
