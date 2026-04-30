import { createFileRoute, Link } from "@tanstack/react-router"
import { motion, AnimatePresence } from "framer-motion"
import { ArrowLeft, ChevronUp } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { AuthHeroPanel } from "@/components/auth/auth-hero-panel"
import { Button } from "@/components/ui/button"

export const Route = createFileRoute("/_public/terms")({
  component: TermsPage,
})

const sections = [
  { id: "usage", label: "Usage" },
  { id: "data", label: "Data" },
  { id: "support", label: "Support" },
  { id: "account-responsibilities", label: "Account Responsibilities" },
  { id: "intellectual-property", label: "Intellectual Property" },
  { id: "changes-to-terms", label: "Changes to Terms" },
]

const fadeIn = {
  hidden: { opacity: 0, y: 16 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.08, duration: 0.4, ease: "easeOut" as const },
  }),
}

function TermsPage() {
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
      <AuthHeroPanel showTestimonial={false} description="The terms that govern your use of this application." />
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
            <h1 className="text-3xl font-semibold tracking-tight">Terms of Service</h1>
            <p className="text-sm text-muted-foreground">Last updated: April 30, 2026</p>
            <p className="text-muted-foreground">These terms govern your use of the Litestar reference application.</p>
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
            By accessing the Litestar reference application you agree to use the service responsibly, follow applicable laws, and avoid any activity that could disrupt platform reliability or security.
          </motion.p>

          {/* Sections */}
          <div className="space-y-6 text-muted-foreground">
            <motion.div className="space-y-2" custom={3} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="usage" className="scroll-mt-20 text-lg font-semibold text-foreground">1. Usage</h3>
              <p>Use the service for legitimate product evaluation. Do not probe for vulnerabilities, overwhelm shared infrastructure, or resell access.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={4} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="data" className="scroll-mt-20 text-lg font-semibold text-foreground">2. Data</h3>
              <p>Your account data remains yours. Operational logs are stored to keep the platform secure and are retained only as long as necessary.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={5} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="support" className="scroll-mt-20 text-lg font-semibold text-foreground">3. Support</h3>
              <p>Support requests are handled on a best-effort basis during the public preview. Critical issues are prioritized within business hours.</p>
            </motion.div>

            <motion.div className="space-y-2" custom={6} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="account-responsibilities" className="scroll-mt-20 text-lg font-semibold text-foreground">4. Account Responsibilities</h3>
              <p>
                You are responsible for maintaining the confidentiality of your account credentials, including passwords and multi-factor authentication tokens. You agree to notify us immediately of any unauthorized use of your account. We are not liable for losses arising from unauthorized access resulting from your failure to safeguard your credentials.
              </p>
            </motion.div>

            <motion.div className="space-y-2" custom={7} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="intellectual-property" className="scroll-mt-20 text-lg font-semibold text-foreground">5. Intellectual Property</h3>
              <p>
                All content, trademarks, and software associated with this application are owned by or licensed to us. You retain ownership of any data you submit. By using the service, you grant us a limited license to process your data solely for the purpose of providing the service.
              </p>
            </motion.div>

            <motion.div className="space-y-2" custom={8} variants={fadeIn} initial="hidden" animate="visible">
              <h3 id="changes-to-terms" className="scroll-mt-20 text-lg font-semibold text-foreground">6. Changes to Terms</h3>
              <p>
                We reserve the right to modify these terms at any time. When changes are material, we will provide notice through the application or by email at least 14 days before the new terms take effect. Your continued use of the service after changes become effective constitutes acceptance of the revised terms.
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
              <Link to="/privacy" className="font-medium text-foreground underline underline-offset-4 transition-colors hover:text-primary">
                Privacy Policy
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
