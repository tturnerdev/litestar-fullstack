import { useQuery } from "@tanstack/react-query"
import { globalSearch, type SearchResponse, type SearchResultItem } from "@/lib/generated/api"

export type { SearchResultItem, SearchResponse }

export function useGlobalSearch(query: string) {
  return useQuery({
    queryKey: ["global-search", query],
    queryFn: async () => {
      const { data } = await globalSearch({
        query: { q: query, limit: 5 },
        throwOnError: true,
      })
      return data as SearchResponse
    },
    enabled: query.trim().length >= 2,
    staleTime: 30_000,
    placeholderData: (prev) => prev,
  })
}
