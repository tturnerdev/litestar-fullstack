import { Link } from "@tanstack/react-router"
import { AnimatePresence, motion } from "framer-motion"
import { BarChart3, Globe, Lock, Shield, Zap } from "lucide-react"
import { useCallback, useEffect, useState } from "react"
import { Icons } from "@/components/icons"
import { RetroGrid } from "@/components/ui/retro-grid"

interface AuthHeroPanelProps {
  title?: string
  description?: string
  showTestimonial?: boolean
}

interface FeatureHighlight {
  icon: React.ElementType
  title: string
  description: string
}

const features: FeatureHighlight[] = [
  {
    icon: Zap,
    title: "High Performance",
    description: "Built on Litestar for blazing-fast async Python APIs with minimal overhead.",
  },
  {
    icon: Shield,
    title: "Enterprise Security",
    description: "Multi-factor authentication, OAuth2, and role-based access controls built in.",
  },
  {
    icon: Globe,
    title: "Modern Stack",
    description: "React + TypeScript frontend with TanStack Router, React Query, and shadcn/ui.",
  },
  {
    icon: BarChart3,
    title: "Full Observability",
    description: "Integrated logging, metrics, and audit trails for complete system visibility.",
  },
  {
    icon: Lock,
    title: "Team Management",
    description: "Organize users into teams with fine-grained permissions and access controls.",
  },
]

const ROTATION_INTERVAL = 5000

export function AuthHeroPanel({ title = "Litestar Fullstack" }: AuthHeroPanelProps) {
  const [activeFeature, setActiveFeature] = useState(0)

  const advanceFeature = useCallback(() => {
    setActiveFeature((prev) => (prev + 1) % features.length)
  }, [])

  useEffect(() => {
    const timer = setInterval(advanceFeature, ROTATION_INTERVAL)
    return () => clearInterval(timer)
  }, [advanceFeature])

  return (
    <div className="relative hidden min-h-screen w-1/2 max-w-2xl flex-col bg-brand-navy p-10 text-white lg:flex">
      <RetroGrid />

      <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, ease: [0.25, 0.1, 0.25, 1] }}>
        <Link to="/" className="relative z-20">
          <div className="flex items-center font-medium text-lg">
            <Icons.logo className="mr-2 h-6 w-6" />
            {title}
          </div>
        </Link>
      </motion.div>

      <div className="relative z-20 my-auto flex flex-col items-start justify-center">
        <motion.div className="w-full max-w-md" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.6, delay: 0.2 }}>
          <div className="space-y-3">
            {features.map((feature, index) => {
              const Icon = feature.icon
              const isActive = index === activeFeature

              return (
                <motion.button
                  key={feature.title}
                  type="button"
                  className="flex w-full cursor-pointer items-start gap-3 rounded-lg border border-transparent p-3 text-left transition-colors"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{
                    opacity: 1,
                    x: 0,
                    backgroundColor: isActive ? "rgba(255, 255, 255, 0.08)" : "rgba(255, 255, 255, 0)",
                    borderColor: isActive ? "rgba(237, 182, 65, 0.3)" : "rgba(255, 255, 255, 0)",
                  }}
                  transition={{
                    opacity: { duration: 0.4, delay: 0.3 + index * 0.08 },
                    x: { duration: 0.4, delay: 0.3 + index * 0.08 },
                    backgroundColor: { duration: 0.4 },
                    borderColor: { duration: 0.4 },
                  }}
                  onClick={() => setActiveFeature(index)}
                >
                  <div
                    className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md transition-colors duration-300 ${isActive ? "bg-brand-gold/20 text-brand-gold" : "bg-white/10 text-white/60"}`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="min-w-0">
                    <p className={`font-medium text-sm transition-colors duration-300 ${isActive ? "text-white" : "text-white/70"}`}>{feature.title}</p>
                    <AnimatePresence mode="wait">
                      {isActive && (
                        <motion.p
                          key={`desc-${feature.title}`}
                          className="mt-0.5 text-white/50 text-xs leading-relaxed"
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.3, ease: [0.25, 0.1, 0.25, 1] }}
                        >
                          {feature.description}
                        </motion.p>
                      )}
                    </AnimatePresence>
                  </div>
                </motion.button>
              )
            })}
          </div>

          <motion.div className="mt-6 flex gap-1.5" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4, delay: 0.8 }}>
            {features.map((_, index) => (
              <button
                key={`dot-${features[index].title}`}
                type="button"
                className="relative h-1 cursor-pointer overflow-hidden rounded-full transition-all duration-300"
                style={{ width: index === activeFeature ? 24 : 8 }}
                onClick={() => setActiveFeature(index)}
                aria-label={`Show feature ${index + 1}`}
              >
                <div className="absolute inset-0 rounded-full bg-white/20" />
                {index === activeFeature && (
                  <motion.div className="absolute inset-0 rounded-full bg-brand-gold" layoutId="activeFeatureDot" transition={{ type: "spring", stiffness: 400, damping: 30 }} />
                )}
              </button>
            ))}
          </motion.div>
        </motion.div>
      </div>

      <motion.div className="relative z-20" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.6 }}>
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex -space-x-1">
              {[
                { icon: <Icons.python className="h-5 w-5" />, label: "Python" },
                { icon: <Icons.react className="h-5 w-5 text-[#61DAFB]" />, label: "React" },
                { icon: <Icons.vite className="h-5 w-5" />, label: "Vite" },
                { icon: <Icons.typescript className="h-5 w-5" />, label: "TypeScript" },
              ].map((tech, index) => (
                <motion.div
                  key={tech.label}
                  className="flex h-9 w-9 items-center justify-center rounded-full bg-white/10 ring-2 ring-brand-navy backdrop-blur-sm"
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{
                    duration: 0.3,
                    delay: 0.7 + index * 0.08,
                    ease: [0.25, 0.1, 0.25, 1],
                  }}
                  title={tech.label}
                >
                  {tech.icon}
                </motion.div>
              ))}
            </div>
            <div className="text-sm text-white/70">
              <span className="font-medium text-white">Built with</span> Python, React & modern tooling
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
