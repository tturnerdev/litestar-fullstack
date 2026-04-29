import { useQuery } from "@tanstack/react-query"
import { client } from "@/lib/generated/api/client.gen"

export interface SearchResultItem {
  type: string
  id: string
  label: string
  description: string
  url: string
}

export interface SearchResponse {
  query: string
  results: SearchResultItem[]
  total: number
}

export function useGlobalSearch(query: string) {
  return useQuery({
    queryKey: ["global-search", query],
    queryFn: async () => {
      const { data } = await client.get({
        url: "/api/search",
        query: { q: query, limit: 5 },
        security: [{ scheme: "bearer", type: "http" }],
        throwOnError: true,
      })
      return data as unknown as SearchResponse
    },
    enabled: query.trim().length >= 2,
    staleTime: 30_000,
    placeholderData: (prev) => prev,
  })
}
