import { Pause, Play, Volume1, Volume2, VolumeX } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"

interface VoicemailPlayerProps {
  audioUrl: string
  durationSeconds: number
  onPlay?: () => void
}

const PLAYBACK_RATES = [1, 1.5, 2] as const

function formatTime(seconds: number): string {
  const mins = Math.floor(seconds / 60)
  const secs = Math.floor(seconds % 60)
  return `${mins}:${secs.toString().padStart(2, "0")}`
}

export function VoicemailPlayer({ audioUrl, durationSeconds, onPlay }: VoicemailPlayerProps) {
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(durationSeconds)
  const [volume, setVolume] = useState(1)
  const [muted, setMuted] = useState(false)
  const [showVolumeSlider, setShowVolumeSlider] = useState(false)
  const [rateIndex, setRateIndex] = useState(0)
  const [isDragging, setIsDragging] = useState(false)

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

  // Sync volume and mute state to audio element
  useEffect(() => {
    const audio = audioRef.current
    if (!audio) return
    audio.volume = volume
    audio.muted = muted
  }, [volume, muted])

  // Sync playback rate to audio element
  useEffect(() => {
    const audio = audioRef.current
    if (!audio) return
    audio.playbackRate = PLAYBACK_RATES[rateIndex]
  }, [rateIndex])

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

  const seekTo = useCallback(
    (clientX: number, rect: DOMRect) => {
      const audio = audioRef.current
      if (!audio || !duration) return
      const percent = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width))
      const newTime = percent * duration
      audio.currentTime = newTime
      setCurrentTime(newTime)
    },
    [duration],
  )

  const handleSeek = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      seekTo(e.clientX, e.currentTarget.getBoundingClientRect())
    },
    [seekTo],
  )

  const handleProgressMouseDown = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      setIsDragging(true)
      const trackRect = e.currentTarget.getBoundingClientRect()
      seekTo(e.clientX, trackRect)

      const handleMouseMove = (moveEvent: MouseEvent) => {
        seekTo(moveEvent.clientX, trackRect)
      }
      const handleMouseUp = () => {
        setIsDragging(false)
        document.removeEventListener("mousemove", handleMouseMove)
        document.removeEventListener("mouseup", handleMouseUp)
      }
      document.addEventListener("mousemove", handleMouseMove)
      document.addEventListener("mouseup", handleMouseUp)
    },
    [seekTo],
  )

  const toggleMute = useCallback(() => {
    setMuted((prev) => !prev)
  }, [])

  const cycleSpeed = useCallback(() => {
    setRateIndex((prev) => (prev + 1) % PLAYBACK_RATES.length)
  }, [])

  // Keyboard controls
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const audio = audioRef.current
      if (!audio) return

      switch (e.key) {
        case " ": {
          e.preventDefault()
          togglePlay()
          break
        }
        case "ArrowLeft": {
          e.preventDefault()
          const backTime = Math.max(0, audio.currentTime - 5)
          audio.currentTime = backTime
          setCurrentTime(backTime)
          break
        }
        case "ArrowRight": {
          e.preventDefault()
          const fwdTime = Math.min(duration, audio.currentTime + 5)
          audio.currentTime = fwdTime
          setCurrentTime(fwdTime)
          break
        }
        case "ArrowUp": {
          e.preventDefault()
          setVolume((prev) => Math.min(1, prev + 0.1))
          setMuted(false)
          break
        }
        case "ArrowDown": {
          e.preventDefault()
          setVolume((prev) => Math.max(0, prev - 0.1))
          break
        }
      }
    },
    [togglePlay, duration],
  )

  const progress = duration > 0 ? (currentTime / duration) * 100 : 0

  const VolumeIcon = muted || volume === 0 ? VolumeX : volume < 0.5 ? Volume1 : Volume2

  return (
    <div
      ref={containerRef}
      className="flex items-center gap-3 rounded-lg bg-muted/30 px-3 py-2"
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="group"
      aria-label="Audio player"
    >
      <Button variant="ghost" size="sm" className="h-8 w-8 shrink-0 p-0" onClick={togglePlay}>
        {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
      </Button>

      <div className="flex min-w-0 flex-1 items-center gap-2">
        <span className="w-10 shrink-0 text-xs text-muted-foreground tabular-nums">{formatTime(currentTime)}</span>

        <div
          className="group relative h-1.5 flex-1 cursor-pointer rounded-full bg-muted transition-[height] hover:h-2.5"
          onMouseDown={handleProgressMouseDown}
          onClick={handleSeek}
          role="slider"
          aria-label="Seek"
          aria-valuenow={Math.round(currentTime)}
          aria-valuemin={0}
          aria-valuemax={Math.round(duration)}
          tabIndex={-1}
        >
          <div
            className="absolute inset-y-0 left-0 rounded-full bg-primary transition-all"
            style={{ width: `${progress}%` }}
          />
          {/* Draggable dot */}
          <div
            className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary shadow-sm transition-transform group-hover:scale-100"
            style={{
              left: `${progress}%`,
              width: 12,
              height: 12,
              transform: `translate(-50%, -50%) scale(${isDragging ? 1.2 : 1})`,
            }}
          />
        </div>

        <span className="w-10 shrink-0 text-xs text-muted-foreground tabular-nums">{formatTime(duration)}</span>
      </div>

      {/* Playback speed button */}
      <Button
        variant="ghost"
        size="sm"
        className="h-6 shrink-0 px-1.5 text-[10px] font-semibold tabular-nums text-muted-foreground hover:text-foreground"
        onClick={cycleSpeed}
        title="Playback speed"
      >
        {PLAYBACK_RATES[rateIndex]}x
      </Button>

      {/* Volume control */}
      <div
        className="relative flex shrink-0 items-center"
        onMouseEnter={() => setShowVolumeSlider(true)}
        onMouseLeave={() => setShowVolumeSlider(false)}
      >
        <button
          type="button"
          className="flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:text-foreground"
          onClick={toggleMute}
          title={muted ? "Unmute" : "Mute"}
        >
          <VolumeIcon className="h-4 w-4" />
        </button>
        {showVolumeSlider && (
          <div className="absolute bottom-full left-1/2 mb-2 -translate-x-1/2 rounded-md bg-popover p-2 shadow-md">
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={muted ? 0 : volume}
              onChange={(e) => {
                const val = parseFloat(e.target.value)
                setVolume(val)
                if (val > 0) setMuted(false)
              }}
              className="h-1.5 w-14 cursor-pointer accent-primary"
              aria-label="Volume"
            />
          </div>
        )}
      </div>
    </div>
  )
}
