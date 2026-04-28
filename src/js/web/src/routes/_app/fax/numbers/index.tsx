import { createFileRoute } from "@tanstack/react-router"
import { LayoutGrid, List } from "lucide-react"
import { useState } from "react"
import { FaxNumberCard } from "@/components/fax/fax-number-card"
import { FaxNumberTable } from "@/components/fax/fax-number-table"
import { Button } from "@/components/ui/button"
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page-layout"
import { SkeletonCard } from "@/components/ui/skeleton"
import { useFaxNumbers } from "@/lib/api/hooks/fax"

export const Route = createFileRoute("/_app/fax/numbers/")({
  component: FaxNumbersPage,
})

function FaxNumbersPage() {
  const [viewMode, setViewMode] = useState<"table" | "cards">("table")
  const { data, isLoading } = useFaxNumbers(1, 100)

  return (
    <PageContainer className="flex-1 space-y-8">
      <PageHeader
        eyebrow="Communications"
        title="Fax Numbers"
        description="Manage your fax numbers and configure email delivery routes."
        actions={
          <div className="flex gap-1 rounded-lg border border-border/60 p-0.5">
            <Button
              variant={viewMode === "table" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("table")}
              className="h-8 px-2"
            >
              <List className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === "cards" ? "default" : "ghost"}
              size="sm"
              onClick={() => setViewMode("cards")}
              className="h-8 px-2"
            >
              <LayoutGrid className="h-4 w-4" />
            </Button>
          </div>
        }
      />
      <PageSection>
        {viewMode === "table" ? (
          <FaxNumberTable />
        ) : isLoading ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: Static skeleton placeholders
              <SkeletonCard key={`fax-num-skeleton-${index}`} />
            ))}
          </div>
        ) : data && data.items.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {data.items.map((faxNumber) => (
              <FaxNumberCard key={faxNumber.id} faxNumber={faxNumber} />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center gap-2 py-12 text-muted-foreground">
            <p className="text-sm">No fax numbers found.</p>
          </div>
        )}
      </PageSection>
    </PageContainer>
  )
}
