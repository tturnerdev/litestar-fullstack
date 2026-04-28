import { Pause, Play, Volume2 } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"

interface VoicemailPlayerProps {
  audioUrl: string
  durationSeconds: number
  onPlay?: () => void
}

function formatTime(seconds: number): string {
  const mins = Math.floor(seconds / 60)
  const secs = Math.floor(seconds % 60)
  return `${mins}:${secs.toString().padStart(2, "0")}`
}

export function VoicemailPlayer({ audioUrl, durationSeconds, onPlay }: VoicemailPlayerProps) {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(durationSeconds)

  useEffect(() => {
    const audio = new Audio(audioUrl)
    audioRef.current = audio

    audio.addEventListener("loadedmetadata", () => {
      if (audio.duration && Number.isFinite(audio.duration)) {
        setDuration(audio.duration)
      }
    })

    audio.addEventListener("timeupdate", () => {
      setCurrentTime(audio.currentTime)
    })

    audio.addEventListener("ended", () => {
      setIsPlaying(false)
      setCurrentTime(0)
    })

    return () => {
      audio.pause()
      audio.removeAttribute("src")
    }
  }, [audioUrl])

  const togglePlay = useCallback(() => {
    const audio = audioRef.current
    if (!audio) return

    if (isPlaying) {
      audio.pause()
      setIsPlaying(false)
    } else {
      audio.play()
      setIsPlaying(true)
      onPlay?.()
    }
  }, [isPlaying, onPlay])

  const handleSeek = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const audio = audioRef.current
    if (!audio || !duration) return

    const rect = e.currentTarget.getBoundingClientRect()
    const percent = (e.clientX - rect.left) / rect.width
    const newTime = percent * duration
    audio.currentTime = newTime
    setCurrentTime(newTime)
  }, [duration])

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0

  return (
    <div className="flex items-center gap-3">
      <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={togglePlay}>
        {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
      </Button>

      <div className="flex flex-1 items-center gap-2">
        <span className="w-10 text-xs text-muted-foreground tabular-nums">{formatTime(currentTime)}</span>

        <div
          className="relative h-1.5 flex-1 cursor-pointer rounded-full bg-muted"
          onClick={handleSeek}
          onKeyDown={() => {}}
          role="slider"
          aria-valuenow={currentTime}
          aria-valuemin={0}
          aria-valuemax={duration}
          tabIndex={0}
        >
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-primary transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>

        <span className="w-10 text-xs text-muted-foreground tabular-nums">{formatTime(duration)}</span>
      </div>

      <Volume2 className="h-4 w-4 text-muted-foreground" />
    </div>
  )
}
