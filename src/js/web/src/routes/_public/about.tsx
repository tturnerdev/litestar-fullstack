import { createFileRoute, Link } from "@tanstack/react-router"
import { motion, useMotionValue, useTransform } from "framer-motion"
import { ArrowLeft, ArrowRight, ExternalLink, Github, LifeBuoy, Mail, Monitor, Phone, Printer, Star } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageContainer } from "@/components/ui/page-layout"

export const Route = createFileRoute("/_public/about")({
  component: AboutPage,
})

// Konami code sequence
const KONAMI_CODE = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"]

const productFeatures = [
  {
    icon: Phone,
    title: "Voice",
    description: "Enterprise voice communications with call routing, voicemail, and real-time analytics.",
    color: "text-blue-500",
    bg: "bg-blue-500/10",
  },
  {
    icon: Printer,
    title: "Fax",
    description: "Digital fax management with send, receive, and archival capabilities built for compliance.",
    color: "text-purple-500",
    bg: "bg-purple-500/10",
  },
  {
    icon: Monitor,
    title: "Devices",
    description: "Centralized device provisioning, monitoring, and lifecycle management across your fleet.",
    color: "text-emerald-500",
    bg: "bg-emerald-500/10",
  },
  {
    icon: LifeBuoy,
    title: "Support",
    description: "Integrated ticketing and knowledge base to keep your team and customers connected.",
    color: "text-amber-500",
    bg: "bg-amber-500/10",
  },
]

const teamMembers = [
  {
    name: "Alex Chen",
    role: "Engineering Lead",
    avatar: "AC",
    color: "bg-blue-500/20 text-blue-600",
  },
  {
    name: "Sarah Kim",
    role: "Product Manager",
    avatar: "SK",
    color: "bg-purple-500/20 text-purple-600",
  },
  {
    name: "James Rivera",
    role: "Design Lead",
    avatar: "JR",
    color: "bg-emerald-500/20 text-emerald-600",
  },
  {
    name: "Priya Patel",
    role: "Backend Engineer",
    avatar: "PP",
    color: "bg-amber-500/20 text-amber-600",
  },
]

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.12 },
  },
}

const staggerItem = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: "easeOut" as const } },
}

function AboutPage() {
  const [easterEggActive, setEasterEggActive] = useState(false)
  const [konamiIndex, setKonamiIndex] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)
  const mouseX = useMotionValue(0)
  const mouseY = useMotionValue(0)

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const rect = containerRef.current?.getBoundingClientRect()
      if (rect) {
        mouseX.set(e.clientX - rect.left)
        mouseY.set(e.clientY - rect.top)
      }
    },
    [mouseX, mouseY],
  )

  const gradientX = useTransform(mouseX, [0, 800], [0, 100])
  const gradientY = useTransform(mouseY, [0, 600], [0, 100])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (easterEggActive) {
        setEasterEggActive(false)
        return
      }
      const key = e.key
      const expectedKey = KONAMI_CODE[konamiIndex]
      if (key === expectedKey) {
        const nextIndex = konamiIndex + 1
        if (nextIndex === KONAMI_CODE.length) {
          setEasterEggActive(true)
          setKonamiIndex(0)
        } else {
          setKonamiIndex(nextIndex)
        }
      } else {
        setKonamiIndex(0)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [konamiIndex, easterEggActive])

  return (
    // biome-ignore lint/a11y/noStaticElementInteractions: Visual-only mouse tracker for cursor-following gradient effect
    <div ref={containerRef} onMouseMove={handleMouseMove} role="presentation" className="relative min-h-screen">
      {/* Easter egg overlay */}
      {easterEggActive && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-brand-navy"
          onClick={() => setEasterEggActive(false)}
        >
          <div className="relative">
            {Array.from({ length: 12 }).map((_, i) => (
              <motion.div
                key={`star-${i}-${Math.random()}`}
                initial={{ opacity: 0, scale: 0 }}
                animate={{
                  opacity: [0, 1, 0],
                  scale: [0, 1, 0],
                  rotate: [0, 360],
                }}
                transition={{
                  duration: 3,
                  repeat: Number.POSITIVE_INFINITY,
                  delay: i * 0.25,
                  ease: "easeInOut",
                }}
                style={{
                  position: "absolute",
                  left: "50%",
                  top: "50%",
                  x: Math.cos((i / 12) * Math.PI * 2) * 150 - 6,
                  y: Math.sin((i / 12) * Math.PI * 2) * 150 - 6,
                }}
                className="h-3 w-3 rounded-full bg-primary shadow-glow-sm"
              />
            ))}
            <motion.div
              animate={{ scale: [1, 1.1, 1], rotate: [0, 360] }}
              transition={{
                scale: { duration: 2, repeat: Number.POSITIVE_INFINITY },
                rotate: {
                  duration: 20,
                  repeat: Number.POSITIVE_INFINITY,
                  ease: "linear",
                },
              }}
              className="relative flex h-32 w-32 items-center justify-center rounded-full bg-primary/20 shadow-glow-lg backdrop-blur"
            >
              <Star className="h-16 w-16 text-primary" />
            </motion.div>
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="absolute -bottom-20 left-1/2 -translate-x-1/2 whitespace-nowrap text-center text-lg font-semibold text-primary"
            >
              You found the secret!
            </motion.p>
          </div>
          <p className="absolute bottom-10 text-center text-sm text-muted-foreground">Press any key to exit</p>
        </motion.div>
      )}

      {/* Cursor-following glow */}
      <motion.div
        style={{
          background: `radial-gradient(circle at ${gradientX.get()}% ${gradientY.get()}%, hsl(var(--primary) / 0.1), transparent 50%)`,
        }}
        className="pointer-events-none absolute inset-0"
      />

      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-border/40">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-primary/10" />
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />

        <PageContainer className="relative">
          <div className="mb-4">
            <Button variant="ghost" size="sm" asChild>
              <Link to="/landing">
                <ArrowLeft className="mr-2 h-4 w-4" /> Back to home
              </Link>
            </Button>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="mx-auto max-w-3xl py-12 text-center md:py-20"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.1, duration: 0.5 }}
              className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-primary/15 shadow-lg shadow-primary/10"
            >
              <Star className="h-8 w-8 text-primary" />
            </motion.div>

            <Badge variant="secondary" className="mb-4">
              Admin Portal
            </Badge>

            <h1 className="mb-4 font-heading text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl">Atrelix Communications</h1>
            <p className="mx-auto max-w-2xl text-lg text-muted-foreground md:text-xl">
              A unified platform for enterprise voice, fax, device management, and support -- built for teams that demand reliability.
            </p>

            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="mt-8 flex flex-wrap justify-center gap-3">
              <Button asChild>
                <Link to="/login">
                  Get Started <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button variant="outline" asChild>
                <a href="https://github.com/litestar-org" target="_blank" rel="noopener noreferrer">
                  <Github className="mr-2 h-4 w-4" /> View on GitHub
                </a>
              </Button>
            </motion.div>
          </motion.div>
        </PageContainer>
      </div>

      {/* Features Section */}
      <PageContainer className="relative">
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-80px" }} variants={staggerContainer} className="mb-20">
          <motion.div variants={staggerItem} className="mb-10 text-center">
            <Badge variant="outline" className="mb-3">
              Platform
            </Badge>
            <h2 className="text-3xl font-bold tracking-tight md:text-4xl">Everything your team needs</h2>
            <p className="mx-auto mt-3 max-w-2xl text-muted-foreground">Four integrated product areas designed to work together seamlessly.</p>
          </motion.div>

          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {productFeatures.map((feature) => (
              <motion.div key={feature.title} variants={staggerItem}>
                <Card hover glow className="h-full">
                  <CardContent className="space-y-4 p-6">
                    <motion.div
                      whileHover={{ scale: 1.1, rotate: 5 }}
                      transition={{
                        type: "spring",
                        stiffness: 400,
                        damping: 17,
                      }}
                      className={`flex h-12 w-12 items-center justify-center rounded-xl ${feature.bg}`}
                    >
                      <feature.icon className={`h-6 w-6 ${feature.color}`} />
                    </motion.div>
                    <h3 className="text-lg font-semibold">{feature.title}</h3>
                    <p className="text-sm leading-relaxed text-muted-foreground">{feature.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Team Section */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-80px" }} variants={staggerContainer} className="mb-20">
          <motion.div variants={staggerItem} className="mb-10 text-center">
            <Badge variant="outline" className="mb-3">
              Team
            </Badge>
            <h2 className="text-3xl font-bold tracking-tight md:text-4xl">Meet the people behind the platform</h2>
            <p className="mx-auto mt-3 max-w-2xl text-muted-foreground">A dedicated team focused on building reliable communication tools.</p>
          </motion.div>

          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {teamMembers.map((member) => (
              <motion.div key={member.name} variants={staggerItem}>
                <Card hover className="text-center">
                  <CardContent className="p-6">
                    <motion.div whileHover={{ scale: 1.1 }} className={`mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full text-xl font-bold ${member.color}`}>
                      {member.avatar}
                    </motion.div>
                    <h3 className="font-semibold">{member.name}</h3>
                    <p className="text-sm text-muted-foreground">{member.role}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Contact Section */}
        <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-80px" }} variants={staggerContainer} className="mb-20">
          <motion.div variants={staggerItem} className="mb-10 text-center">
            <Badge variant="outline" className="mb-3">
              Contact
            </Badge>
            <h2 className="text-3xl font-bold tracking-tight md:text-4xl">Get in touch</h2>
            <p className="mx-auto mt-3 max-w-2xl text-muted-foreground">Questions, feedback, or need support? We are here to help.</p>
          </motion.div>

          <div className="mx-auto grid max-w-2xl gap-6 md:grid-cols-2">
            <motion.div variants={staggerItem}>
              <Card hover glow className="h-full">
                <CardContent className="flex items-start gap-4 p-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-500/10">
                    <Mail className="h-5 w-5 text-blue-500" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Email Us</h3>
                    <p className="mt-1 text-sm text-muted-foreground">Reach out for general inquiries or partnership opportunities.</p>
                    <a href="mailto:support@atrelix.com" className="mt-2 inline-flex items-center text-sm font-medium text-primary hover:underline">
                      support@atrelix.com
                      <ExternalLink className="ml-1 h-3 w-3" />
                    </a>
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={staggerItem}>
              <Card hover glow className="h-full">
                <CardContent className="flex items-start gap-4 p-6">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10">
                    <LifeBuoy className="h-5 w-5 text-emerald-500" />
                  </div>
                  <div>
                    <h3 className="font-semibold">Support Center</h3>
                    <p className="mt-1 text-sm text-muted-foreground">Browse our knowledge base or submit a support ticket.</p>
                    <Link to="/login" className="mt-2 inline-flex items-center text-sm font-medium text-primary hover:underline">
                      Open Support Portal
                      <ArrowRight className="ml-1 h-3 w-3" />
                    </Link>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </motion.div>
      </PageContainer>

      {/* Footer */}
      <footer className="border-t border-border/40 bg-muted/30">
        <PageContainer className="py-8">
          <div className="flex flex-col items-center justify-between gap-6 md:flex-row">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Star className="h-4 w-4 text-primary" />
              <span>Atrelix Communications</span>
            </div>

            <nav className="flex flex-wrap items-center gap-6 text-sm">
              <a href="#" className="text-muted-foreground transition-colors hover:text-foreground">
                Terms of Service
              </a>
              <a href="#" className="text-muted-foreground transition-colors hover:text-foreground">
                Privacy Policy
              </a>
              <Link to="/login" className="text-muted-foreground transition-colors hover:text-foreground">
                Sign In
              </Link>
              <a href="https://github.com/litestar-org" target="_blank" rel="noopener noreferrer" className="text-muted-foreground transition-colors hover:text-foreground">
                <Github className="h-4 w-4" />
              </a>
            </nav>

            <p className="text-xs text-muted-foreground/60">&copy; {new Date().getFullYear()} Atrelix. All rights reserved.</p>
          </div>
        </PageContainer>
      </footer>

      {/* Hidden konami hint */}
      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 2 }} className="pb-4 text-center text-xs text-muted-foreground/30">
        Try the classic code...
      </motion.p>
    </div>
  )
}
