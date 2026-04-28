import { createFileRoute } from "@tanstack/react-router"
import { LayoutGrid, List } from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { PhoneNumberCard } from "@/components/voice/phone-number-card"
import { PhoneNumberTable } from "@/components/voice/phone-number-table"
import { usePhoneNumbers } from "@/lib/api/hooks/voice"

export const Route = createFileRoute("/_app/voice/phone-numbers")({
  component: PhoneNumbersPage,
})

function PhoneNumbersPage() {
  const [viewMode, setViewMode] = useState<"table" | "cards">("table")

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Voice"
        title="Phone Numbers"
        description="View and manage your assigned phone numbers."
        actions={
          <div className="flex items-center gap-1 rounded-lg border p-1">
            <Button
              variant={viewMode === "table" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("table")}
              className="h-8 px-3"
            >
              <List className="mr-2 h-4 w-4" />
              Table
            </Button>
            <Button
              variant={viewMode === "cards" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("cards")}
              className="h-8 px-3"
            >
              <LayoutGrid className="mr-2 h-4 w-4" />
              Cards
            </Button>
          </div>
        }
      />
      <PageSection>
        {viewMode === "table" ? <PhoneNumberTable /> : <PhoneNumberCardGrid />}
      </PageSection>
    </PageContainer>
  )
}

function PhoneNumberCardGrid() {
  const [page, setPage] = useState(1)
  const { data, isLoading, isError } = usePhoneNumbers(page, 12)

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {Array.from({ length: 6 }).map((_, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
          <div key={`pn-skeleton-${index}`} className="h-40 animate-pulse rounded-lg bg-muted" />
        ))}
      </div>
    )
  }

  if (isError || !data) {
    return <p className="text-center text-muted-foreground">Unable to load phone numbers.</p>
  }

  if (data.items.length === 0) {
    return <p className="py-12 text-center text-muted-foreground">No phone numbers found.</p>
  }

  const totalPages = Math.max(1, Math.ceil(data.total / 12))

  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {data.items.map((pn) => (
          <PhoneNumberCard key={pn.id} phoneNumber={pn} />
        ))}
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Page {page} of {totalPages}
          </p>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
              Previous
            </Button>
            <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}>
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
