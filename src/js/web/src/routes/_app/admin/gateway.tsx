import { useCallback, useEffect, useState } from "react"
import { createFileRoute } from "@tanstack/react-router"
import { AlertCircle, Clock, Database, Info, Loader2, Network, Save } from "lucide-react"
import { AdminBreadcrumbs } from "@/components/admin/admin-breadcrumbs"
import { AdminNav } from "@/components/admin/admin-nav"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { Separator } from "@/components/ui/separator"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useAdminGatewaySettings, useUpdateAdminGatewaySettings } from "@/lib/api/hooks/gateway"

export const Route = createFileRoute("/_app/admin/gateway")({
  component: AdminGatewayPage,
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function FieldHint({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>
}

function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

function validateTimeout(value: string): string | undefined {
  if (!value) return "Timeout is required"
  const num = Number(value)
  if (!Number.isInteger(num) || num < 1 || num > 300) {
    return "Timeout must be between 1 and 300 seconds"
  }
  return undefined
}

function validateCacheTtl(value: string): string | undefined {
  if (!value) return "Cache TTL is required"
  const num = Number(value)
  if (!Number.isInteger(num) || num < 0 || num > 86400) {
    return "Cache TTL must be between 0 and 86400 seconds (24 hours)"
  }
  return undefined
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function AdminGatewayPage() {
  const { data, isLoading, isError } = useAdminGatewaySettings()
  const updateSettings = useUpdateAdminGatewaySettings()

  const [timeout, setTimeout] = useState("")
  const [cacheTtl, setCacheTtl] = useState("")
  const [initialized, setInitialized] = useState(false)
  const [errors, setErrors] = useState<{ timeout?: string; cacheTtl?: string }>({})
  const [touched, setTouched] = useState<{ timeout?: boolean; cacheTtl?: boolean }>({})

  // Pre-populate form when data loads
  useEffect(() => {
    if (data && !initialized) {
      setTimeout(String(data.defaultTimeout))
      setCacheTtl(String(data.defaultCacheTtl))
      setInitialized(true)
    }
  }, [data, initialized])

  // Track dirty state
  const isDirty =
    initialized &&
    data != null &&
    (timeout !== String(data.defaultTimeout) || cacheTtl !== String(data.defaultCacheTtl))

  const handleFieldBlur = useCallback(
    (field: "timeout" | "cacheTtl", value: string) => {
      setTouched((prev) => ({ ...prev, [field]: true }))
      const error = field === "timeout" ? validateTimeout(value) : validateCacheTtl(value)
      setErrors((prev) => ({ ...prev, [field]: error }))
    },
    [],
  )

  const handleTimeoutChange = useCallback(
    (value: string) => {
      setTimeout(value)
      if (touched.timeout) {
        setErrors((prev) => ({ ...prev, timeout: validateTimeout(value) }))
      }
    },
    [touched.timeout],
  )

  const handleCacheTtlChange = useCallback(
    (value: string) => {
      setCacheTtl(value)
      if (touched.cacheTtl) {
        setErrors((prev) => ({ ...prev, cacheTtl: validateCacheTtl(value) }))
      }
    },
    [touched.cacheTtl],
  )

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const timeoutError = validateTimeout(timeout)
    const cacheTtlError = validateCacheTtl(cacheTtl)
    setTouched({ timeout: true, cacheTtl: true })
    setErrors({ timeout: timeoutError, cacheTtl: cacheTtlError })

    if (timeoutError || cacheTtlError) return

    updateSettings.mutate(
      {
        defaultTimeout: Number(timeout),
        defaultCacheTtl: Number(cacheTtl),
      },
      {
        onSuccess: (newData) => {
          // Update baseline so isDirty resets
          setTimeout(String(newData.defaultTimeout))
          setCacheTtl(String(newData.defaultCacheTtl))
        },
      },
    )
  }

  const isValid = !errors.timeout && !errors.cacheTtl && timeout !== "" && cacheTtl !== ""

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Administration"
        title="Gateway"
        description="Configure default settings for the data gateway service."
        breadcrumbs={<AdminBreadcrumbs />}
      />
      <AdminNav />

      <PageSection>
        {isLoading ? (
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="lg:col-span-2">
              <SkeletonCard />
            </div>
            <SkeletonCard />
          </div>
        ) : isError || !data ? (
          <Card>
            <CardContent className="flex items-center gap-3 py-6 text-muted-foreground">
              <AlertCircle className="h-5 w-5 text-destructive" />
              <span>Unable to load gateway settings. The server may be unreachable.</span>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-6 lg:grid-cols-3">
            {/* Settings form */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Network className="h-4 w-4 text-muted-foreground" />
                  Gateway Defaults
                </CardTitle>
                <CardDescription>
                  These values apply to all gateway queries unless overridden at the connection level.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  {/* Default Timeout */}
                  <div className="space-y-2">
                    <Label htmlFor="gateway-timeout" className="flex items-center gap-2">
                      <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                      Default Request Timeout
                    </Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="gateway-timeout"
                        type="number"
                        min={1}
                        max={300}
                        value={timeout}
                        onChange={(e) => handleTimeoutChange(e.target.value)}
                        onBlur={() => handleFieldBlur("timeout", timeout)}
                        aria-invalid={!!errors.timeout}
                        className="max-w-[200px]"
                      />
                      <span className="text-sm text-muted-foreground">seconds</span>
                    </div>
                    {errors.timeout ? (
                      <FieldError message={errors.timeout} />
                    ) : (
                      <FieldHint>
                        Maximum time to wait for each provider to respond. Applies to all gateway
                        queries (number, extension, and device lookups).
                      </FieldHint>
                    )}
                  </div>

                  <Separator />

                  {/* Default Cache TTL */}
                  <div className="space-y-2">
                    <Label htmlFor="gateway-cache-ttl" className="flex items-center gap-2">
                      <Database className="h-3.5 w-3.5 text-muted-foreground" />
                      Default Cache TTL
                    </Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="gateway-cache-ttl"
                        type="number"
                        min={0}
                        max={86400}
                        value={cacheTtl}
                        onChange={(e) => handleCacheTtlChange(e.target.value)}
                        onBlur={() => handleFieldBlur("cacheTtl", cacheTtl)}
                        aria-invalid={!!errors.cacheTtl}
                        className="max-w-[200px]"
                      />
                      <span className="text-sm text-muted-foreground">seconds</span>
                    </div>
                    {errors.cacheTtl ? (
                      <FieldError message={errors.cacheTtl} />
                    ) : (
                      <FieldHint>
                        How long gateway responses are cached in Redis before being re-fetched from
                        the provider. Set to 0 to disable caching.
                      </FieldHint>
                    )}
                  </div>

                  <Separator />

                  {/* Submit */}
                  <div className="flex items-center justify-end gap-2">
                    <Button type="submit" disabled={!isValid || !isDirty || updateSettings.isPending}>
                      {updateSettings.isPending ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : (
                        <Save className="mr-2 h-4 w-4" />
                      )}
                      Save Changes
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>

            {/* Info sidebar */}
            <div className="flex h-fit flex-col gap-4">
              <Card className="border-border/40 bg-linear-to-br from-muted/30 to-muted/10">
                <CardHeader className="space-y-1 pb-3">
                  <div className="flex items-center gap-2">
                    <Info className="h-4 w-4 text-muted-foreground" />
                    <CardTitle className="text-sm">How It Works</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    The gateway service queries external providers (PBX systems, carriers, etc.)
                    to look up phone numbers, extensions, and devices.
                  </p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    <span className="font-medium text-foreground">Request Timeout</span> controls
                    how long the gateway waits for each provider before giving up. Increase this if
                    providers are on slow networks.
                  </p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    <span className="font-medium text-foreground">Cache TTL</span> determines how
                    long results are cached in Redis. Higher values reduce load on external systems
                    but may serve stale data.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/40">
                <CardHeader className="space-y-1 pb-3">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    <CardTitle className="text-sm">Per-Connection Overrides</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    Individual connections can override these defaults via the
                    <span className="font-medium text-foreground"> Cache TTL </span>
                    and
                    <span className="font-medium text-foreground"> Timeout </span>
                    fields in the connection edit form.
                  </p>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    When a connection-level override is set, it takes precedence over the global
                    default for that connection only.
                  </p>
                </CardContent>
              </Card>

              <Card className="border-border/40">
                <CardHeader className="space-y-1 pb-3">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-amber-500" />
                    <CardTitle className="text-sm">Persistence Note</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-xs leading-relaxed text-muted-foreground">
                    Changes here apply immediately and persist until the server is restarted. To
                    make settings permanent, also update the
                    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
                      GATEWAY_DEFAULT_TIMEOUT
                    </code>{" "}
                    and{" "}
                    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px]">
                      GATEWAY_DEFAULT_CACHE_TTL
                    </code>{" "}
                    environment variables.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </PageSection>
    </PageContainer>
  )
}
