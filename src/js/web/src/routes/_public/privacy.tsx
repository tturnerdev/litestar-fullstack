import { createFileRoute, Link } from "@tanstack/react-router"
import { motion, AnimatePresence } from "framer-motion"
import { ArrowLeft, ChevronUp } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { AuthHeroPanel } from "@/components/auth/auth-hero-panel"
import { Button } from "@/components/ui/button"

export const Route = createFileRoute("/_public/privacy")({
  component: PrivacyPage,
})

const sections = [
  { id: "data-collected", label: "Data Collected" },
  { id: "retention", label: "Retention" },
  { id: "third-parties", label: "Third Parties" },
  { id: "your-rights", label: "Your Rights" },
  { id: "cookies", label: "Cookies" },
  { id: "updates-to-this-policy", label: "Updates to This Policy" },
]

const fadeIn = {
  hidden: { opacity: 0, y: 16 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.4, ease: "easeOut" as const },
  }),
}

function PrivacyPage() {
  const [showTop, setShowTop] = useState(false)

  const handleScroll = useCallback(() => {
    setShowTop(window.scrollY > 300)
  }, [])

  useEffect(() => {
    window.addEventListener("scroll", handleScroll, { passive: true })
    return () => window.removeEventListener("scroll", handleScroll)
  }, [handleScroll])

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" })

  return (
    <div className="relative flex min-h-screen w-full">
      <AuthHeroPanel showTestimonial={false} description="Your privacy matters. Learn how we handle your data." />
      <div className="flex flex-1 flex-col items-center bg-brand-gray-light px-4 py-12 dark:bg-background">
        <div className="w-full max-w-xl space-y-8">
          {/* Top bar */}
          <motion.div
            className="flex items-center justify-between"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3 }}
          >
            <div />
            <Link to="/landing" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to home
            </Link>
          </motion.div>

          {/* Header */}
          <motion.div className="space-y-2" custom={0} variants={fadeIn} initial="hidden" animate="visible">
            <p className="text-xs uppercase tracking-[0.2em] text-secondary-foreground/80">Legal</p>
            <h1 className="text-3xl font-semibold tracking-tight">Privacy Policy</h1>
            <p className="text-sm text-muted-foreground">Last updated: April 30, 2026</p>
            <p className="text-muted-foreground">How we collect, store, and use data inside the Litestar reference app.</p>
          </motion.div>

          {/* Table of contents */}
          <motion.nav
            className="rounded-lg border border-border/60 bg-muted/40 p-4"
            custom={1}
            variants={fadeIn}
            initial="hidden"
            animate="visible"
          >
            <p className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">On this page</p>
            <ol className="space-y-1">
              {sections.map((s, i) => (
                <li key={s.id}>
                  <a
                    href={`#${s.id}`}
                    className="text-sm text-muted-foreground transition-colors hover:text-foreground"
                  >
                    {i + 1}. {s.label}
                  </a>
                </li>
              ))}
            </ol>
          </motion.nav>

          {/* Intro */}
          <motion.p className="text-muted-foreground" custom={2} variants={fadeIn} initial="hidden" animate="visible">
            We collect only the information required to operate this reference application, including account details and security events needed to keep the platform reliable.
          </motion.p>

          {/* Sections */}
          <div className="space-y-6 text-muted-foreground">
            <motion.div className="space-y-2" custom={3} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="data-collected" className="scroll-mt-20 text-lg font-semibold text-foreground">1. Data Collected</h3>
              <p>Account profile data, authentication events, team membership metadata, and operational diagnostics for queues and background jobs.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={4} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="retention" className="scroll-mt-20 text-lg font-semibold text-foreground">2. Retention</h3>
              <p>Logs and operational data are retained for a limited period and deleted automatically unless required for security investigations.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={5} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="third-parties" className="scroll-mt-20 text-lg font-semibold text-foreground">3. Third Parties</h3>
              <p>We rely on infrastructure providers for hosting, email delivery, and monitoring. Data is shared only as necessary to provide service.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={6} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="your-rights" className="scroll-mt-20 text-lg font-semibold text-foreground">4. Your Rights</h3>
              <p>
                You may request access to, correction of, or deletion of your personal data at any time by contacting support. We will respond to verified requests within 30 days. Where applicable, you also have the right to data portability and to restrict or object to certain processing activities.
              </p>
            </motion.div>

            <motion.div className="space-y-2" custom={7} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="cookies" className="scroll-mt-20 text-lg font-semibold text-foreground">5. Cookies</h3>
              <p>
                This application uses session cookies solely for authentication and maintaining your login state. We do not use tracking cookies, advertising cookies, or any third-party analytics cookies. Session cookies expire when you log out or after a period of inactivity.
              </p>
            </motion.div>

            <motion.div className="space-y-2" custom={8} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="updates-to-this-policy" className="scroll-mt-20 text-lg font-semibold text-foreground">6. Updates to This Policy</h3>
              <p>
                We may update this privacy policy from time to time to reflect changes in our practices or for operational, legal, or regulatory reasons. When we make material changes, we will notify you through the application or via email. We encourage you to review this page periodically.
              </p>
            </motion.div>
          </div>

          {/* Cross-link footer */}
          <motion.div
            className="border-t border-border/60 pt-6 text-center"
            custom={9}
            variants={fadeIn}
            initial="hidden"
            animate="visible"
          >
            <p className="text-sm text-muted-foreground">
              See also our{" "}
              <Link to="/terms" className="font-medium text-foreground underline underline-offset-4 transition-colors hover:text-primary">
                Terms of Service
              </Link>
            </p>
          </motion.div>
        </div>
      </div>

      {/* Scroll to top */}
      <AnimatePresence>
        {showTop && (
          <motion.div
            className="fixed bottom-6 right-6 z-50"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ duration: 0.2 }}
          >
            <Button
              size="icon"
              variant="outline"
              className="h-10 w-10 rounded-full shadow-lg"
              onClick={scrollToTop}
              aria-label="Back to top"
            >
              <ChevronUp className="h-5 w-5" />
            </Button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
