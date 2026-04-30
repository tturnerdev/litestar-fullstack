import { Link } from "@tanstack/react-router"
import { motion } from "framer-motion"
import { ArrowRight, MessageSquare, Monitor, Moon, Phone, Printer, Shield, Sun, Timer, Users } from "lucide-react"
import { Icons } from "@/components/icons"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { RetroGrid } from "@/components/ui/retro-grid"
import { useTheme } from "@/lib/theme-context"

const features = [
  {
    icon: Phone,
    title: "Voice Management",
    description: "Manage extensions, phone numbers, and call settings",
    color: "text-blue-500",
    bg: "bg-blue-500/10",
  },
  {
    icon: Printer,
    title: "Fax Services",
    description: "Send and receive faxes with email integration",
    color: "text-emerald-500",
    bg: "bg-emerald-500/10",
  },
  {
    icon: Monitor,
    title: "Device Management",
    description: "Track and provision phones and SIP devices",
    color: "text-violet-500",
    bg: "bg-violet-500/10",
  },
  {
    icon: MessageSquare,
    title: "Support Tickets",
    description: "Create and manage support requests",
    color: "text-amber-500",
    bg: "bg-amber-500/10",
  },
] as const

const stats = [
  { value: "99.9%", label: "Uptime", icon: Timer },
  { value: "24/7", label: "Monitoring", icon: Shield },
  { value: "Enterprise", label: "Security", icon: Shield },
  { value: "Multi-Team", label: "Support", icon: Users },
] as const

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
}

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: [0.25, 0.1, 0.25, 1] as const },
  },
}

export function LandingPage() {
  const { toggleTheme, theme } = useTheme()

  return (
    <div className="relative flex min-h-screen w-full">
      {/* Left panel with RetroGrid - hidden on mobile */}
      <div className="relative hidden min-h-screen w-1/2 max-w-2xl flex-col bg-brand-navy p-10 text-white lg:flex">
        <RetroGrid />
        <Link to="/" className="relative z-20">
          <div className="flex items-center font-medium text-lg">
            <Icons.logo className="mr-2 h-6 w-6" />
            Litestar Fullstack
          </div>
        </Link>
        <div className="relative z-20 mt-auto">
          <p className="text-lg font-medium leading-relaxed">Build high-performance web applications with Python and React. Seamless SPA experience powered by Vite.</p>
          <div className="mt-4 flex items-center gap-4">
            <div className="flex -space-x-1">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10 ring-2 ring-brand-navy backdrop-blur-sm">
                <Icons.python className="h-5 w-5" />
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10 ring-2 ring-brand-navy backdrop-blur-sm">
                <Icons.react className="h-5 w-5 text-[#61DAFB]" />
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10 ring-2 ring-brand-navy backdrop-blur-sm">
                <Icons.vite className="h-5 w-5" />
              </div>
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10 ring-2 ring-brand-navy backdrop-blur-sm">
                <Icons.typescript className="h-5 w-5" />
              </div>
            </div>
            <div className="text-sm text-white/70">
              <span className="font-medium text-white">Built with</span> Python, React & modern tooling
            </div>
          </div>
        </div>
      </div>

      {/* Right panel with content */}
      <div className="flex flex-1 flex-col bg-brand-gray-light dark:bg-background">
        {/* Header with theme toggle and sign in */}
        <div className="flex items-center justify-end gap-2 p-4 md:p-8">
          <Button variant="ghost" size="icon" onClick={toggleTheme} className="size-9 rounded-full" aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}>
            {theme === "light" ? <Moon className="size-4" /> : <Sun className="size-4" />}
          </Button>
          <Button asChild variant="ghost">
            <Link to="/login">Sign in</Link>
          </Button>
        </div>

        {/* Main content - scrollable */}
        <main className="flex flex-1 flex-col items-center overflow-y-auto px-4 pb-16">
          {/* Hero section */}
          <motion.div className="flex flex-col items-center" initial="hidden" animate="visible" variants={staggerContainer}>
            <motion.div variants={fadeUp}>
              <Icons.logoBrand className="h-16 w-16" />
            </motion.div>

            <motion.h1 variants={fadeUp} className="mt-8 font-heading text-4xl font-bold tracking-tight text-foreground sm:text-5xl">
              Litestar Fullstack
            </motion.h1>

            <motion.p variants={fadeUp} className="mt-4 max-w-md text-center text-lg text-muted-foreground">
              A production-ready Python + React reference application
            </motion.p>

            <motion.div variants={fadeUp} className="mt-10 flex gap-4">
              <Button asChild size="lg" className="shadow-lg shadow-primary/20">
                <Link to="/signup">
                  Get Started
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg">
                <a href="https://github.com/litestar-org/litestar-fullstack" target="_blank" rel="noopener noreferrer">
                  View Source
                </a>
              </Button>
            </motion.div>
          </motion.div>

          {/* Feature cards */}
          <motion.div
            className="mt-20 grid w-full max-w-2xl grid-cols-1 gap-4 sm:grid-cols-2"
            initial="hidden"
            animate="visible"
            variants={staggerContainer}
          >
            {features.map((feature) => (
              <motion.div key={feature.title} variants={fadeUp}>
                <Card hover className="h-full">
                  <CardContent className="flex items-start gap-4 py-5">
                    <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${feature.bg}`}>
                      <feature.icon className={`h-5 w-5 ${feature.color}`} />
                    </div>
                    <div className="space-y-1">
                      <h3 className="font-semibold text-sm text-foreground">{feature.title}</h3>
                      <p className="text-xs leading-relaxed text-muted-foreground">{feature.description}</p>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </motion.div>

          {/* Stats section */}
          <motion.div
            className="mt-16 flex w-full max-w-2xl flex-wrap items-center justify-center gap-8 rounded-xl border border-border/40 bg-card/40 px-8 py-6 backdrop-blur-sm sm:gap-12"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.8, ease: [0.25, 0.1, 0.25, 1] as const }}
          >
            {stats.map((stat) => (
              <div key={stat.label} className="flex flex-col items-center gap-1 text-center">
                <span className="font-heading text-xl font-bold text-foreground">{stat.value}</span>
                <span className="text-xs text-muted-foreground">{stat.label}</span>
              </div>
            ))}
          </motion.div>
        </main>

        {/* Footer */}
        <footer className="py-6 text-center text-sm text-muted-foreground">&copy; {new Date().getFullYear()} Litestar Organization &middot; MIT License</footer>
      </div>
    </div>
  )
}
