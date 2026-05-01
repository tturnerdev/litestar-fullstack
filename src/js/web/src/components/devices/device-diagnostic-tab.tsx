import { useState, useMemo, useEffect } from "react"
import {
  AlertCircle,
  Copy,
  Check,
  FileCode,
  Loader2,
  MonitorSmartphone,
  Play,
  RefreshCw,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useDeviceTemplateLookup } from "@/lib/api/hooks/device-templates"
import { useDeviceScreenshot } from "@/lib/api/hooks/devices"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface WireframeRegion {
  id: string
  type: "button" | "screen" | "shape"
  shape?: "rect" | "circle" | "handset"
  x?: number
  y?: number
  width?: number
  height?: number
  cx?: number
  cy?: number
  r?: number
  label: string
  category?: string
  color?: string
  style?: string
}

interface WireframeDialpad {
  startX: number
  startY: number
  buttonWidth: number
  buttonHeight: number
  gapX: number
  gapY: number
  keys: string[]
  subLabels: string[]
}

interface WireframeData {
  width: number
  height: number
  regions: WireframeRegion[]
  dialpad?: WireframeDialpad
}

// ---------------------------------------------------------------------------
// V1 Schema Types
// ---------------------------------------------------------------------------

interface V1Bounds {
  x: number
  y: number
  width: number
  height: number
}

interface V1ViewBox {
  x: number
  y: number
  width: number
  height: number
}

interface V1Canvas {
  viewBox: V1ViewBox
}

interface V1Body {
  id: string
  shape: string
  bounds: V1Bounds
  cornerRadius: number
  fill: string
  stroke: string
}

interface V1Indicator {
  id: string
  type: string
  label: string
  shape: string
  bounds: V1Bounds
  cornerRadius: number
  color: string
  states: string[]
}

interface V1HandsetElement {
  id: string
  type: string
  shape?: string
  geometry?: { cx: number; cy: number; rx: number; ry: number }
  text?: string
  decoration?: string
  anchor?: { x: number; y: number }
  exitDirection?: string
}

interface V1Handset {
  id: string
  bounds: V1Bounds
  cornerRadius: number
  elements: V1HandsetElement[]
}

interface V1Branding {
  id: string
  text: string
  anchor: { x: number; y: number; alignment: string }
}

interface V1LineKeyLabel {
  slot: number
  icon: string
  text: string
}

interface V1SoftKeyBar {
  style: string
  labels: string[]
}

interface V1DisplayContent {
  statusBar: { icon: string; text: string }
  primaryRegion: { time: string; seconds: string; date: string }
  lineKeyLabels: V1LineKeyLabel[]
  softKeyBar: V1SoftKeyBar
}

interface V1Display {
  id: string
  type: string
  bounds: V1Bounds
  cornerRadius: number
  content: V1DisplayContent
}

interface V1LineKey {
  id: string
  slot: number
  color: string
  shape: string
  bounds: V1Bounds
  cornerRadius: number
}

interface V1SoftKey {
  id: string
  slot: number
  bounds: V1Bounds
  cornerRadius: number
}

interface V1DialPadKey {
  id: string
  row: number
  col: number
  digit: string
  letters: string
}

interface V1DialPad {
  id: string
  origin: { x: number; y: number }
  grid: { rows: number; cols: number }
  keySize: { width: number; height: number }
  gap: number
  cornerRadius: number
  keys: V1DialPadKey[]
}

interface V1FunctionKey {
  id: string
  row: number
  col: number
  icon: string
  function: string
}

interface V1FunctionKeys {
  id: string
  origin: { x: number; y: number }
  grid: { rows: number; cols: number }
  keySize: { width: number; height: number }
  gap: number
  cornerRadius: number
  keys: V1FunctionKey[]
}

interface V1VolumeControl {
  side: string
  label: string
  function: string
}

interface V1VolumeRocker {
  id: string
  type: string
  orientation: string
  shape: string
  bounds: V1Bounds
  cornerRadius: number
  controls: V1VolumeControl[]
}

interface V1WireframeData {
  $schema: string
  canvas: V1Canvas
  body: V1Body
  indicators: V1Indicator[]
  handset: V1Handset
  branding: V1Branding
  display: V1Display
  lineKeys: V1LineKey[]
  softKeys: V1SoftKey[]
  dialPad: V1DialPad
  functionKeys: V1FunctionKeys
  volumeRocker: V1VolumeRocker
}

// ---------------------------------------------------------------------------
// Color palette by category
// ---------------------------------------------------------------------------

const categoryColors: Record<string, { fill: string; stroke: string; hoverFill: string }> = {
  softkey: { fill: "#dbeafe", stroke: "#3b82f6", hoverFill: "#93c5fd" },
  line: { fill: "#dcfce7", stroke: "#22c55e", hoverFill: "#86efac" },
  navigation: { fill: "#f3f4f6", stroke: "#6b7280", hoverFill: "#d1d5db" },
  function: { fill: "#fef3c7", stroke: "#f59e0b", hoverFill: "#fde68a" },
  default: { fill: "#f1f5f9", stroke: "#94a3b8", hoverFill: "#cbd5e1" },
}

function getCategoryColor(category?: string, color?: string) {
  if (color === "red") return { fill: "#fee2e2", stroke: "#ef4444", hoverFill: "#fca5a5" }
  if (color === "green") return { fill: "#dcfce7", stroke: "#22c55e", hoverFill: "#86efac" }
  return categoryColors[category ?? ""] ?? categoryColors.default
}

// ---------------------------------------------------------------------------
// Wireframe data normalization
// ---------------------------------------------------------------------------

function isV1Schema(raw: Record<string, unknown>): raw is Record<string, unknown> & { canvas: unknown } {
  return raw?.canvas !== undefined && typeof raw?.body === "object"
}

function normalizeWireframeData(raw: Record<string, unknown>): { version: "v0"; data: WireframeData } | { version: "v1"; data: V1WireframeData } | null {
  // Detect v1 schema: has canvas + body (structured schema)
  if (isV1Schema(raw)) {
    return { version: "v1", data: raw as unknown as V1WireframeData }
  }

  // v0 fallback: flat width/height/regions
  if (typeof raw?.width === "number" && typeof raw?.height === "number") {
    return { version: "v0", data: raw as unknown as WireframeData }
  }

  return null
}

// ---------------------------------------------------------------------------
// SVG Wireframe Renderer
// ---------------------------------------------------------------------------

function WireframeRenderer({ data }: { data: WireframeData }) {
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  const padding = 20
  const svgWidth = data.width + padding * 2
  const svgHeight = data.height + padding * 2

  return (
    <svg
      viewBox={`0 0 ${svgWidth} ${svgHeight}`}
      className="w-full max-w-lg mx-auto"
      style={{ fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      <defs>
        <linearGradient id="screen-gradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#c7d2e0" />
          <stop offset="100%" stopColor="#94a3b8" />
        </linearGradient>
        <filter id="shadow" x="-2%" y="-2%" width="104%" height="104%">
          <feDropShadow dx="0" dy="1" stdDeviation="2" floodOpacity="0.1" />
        </filter>
      </defs>

      {/* Phone body */}
      <rect
        x={padding}
        y={padding}
        width={data.width}
        height={data.height}
        rx={12}
        ry={12}
        fill="#f8fafc"
        stroke="#cbd5e1"
        strokeWidth={1.5}
        filter="url(#shadow)"
      />

      {/* Regions */}
      <g transform={`translate(${padding}, ${padding})`}>
        {(data.regions ?? []).map((region) => {
          const isHovered = hoveredId === region.id
          const colors = getCategoryColor(region.category, region.color)

          if (region.type === "screen") {
            return (
              <Tooltip key={region.id}>
                <TooltipTrigger asChild>
                  <g
                    onMouseEnter={() => setHoveredId(region.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    className="cursor-default"
                  >
                    <rect
                      x={region.x}
                      y={region.y}
                      width={region.width}
                      height={region.height}
                      rx={4}
                      fill="url(#screen-gradient)"
                      stroke="#64748b"
                      strokeWidth={1}
                      opacity={isHovered ? 0.9 : 1}
                    />
                    <text
                      x={(region.x ?? 0) + (region.width ?? 0) / 2}
                      y={(region.y ?? 0) + (region.height ?? 0) / 2}
                      textAnchor="middle"
                      dominantBaseline="central"
                      fontSize={9}
                      fill="#334155"
                      fontWeight={500}
                    >
                      {region.label}
                    </text>
                  </g>
                </TooltipTrigger>
                <TooltipContent>{region.label}</TooltipContent>
              </Tooltip>
            )
          }

          if (region.type === "shape" && region.shape === "handset") {
            return (
              <Tooltip key={region.id}>
                <TooltipTrigger asChild>
                  <g
                    onMouseEnter={() => setHoveredId(region.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    className="cursor-default"
                  >
                    {/* Simplified handset shape */}
                    <rect
                      x={region.x}
                      y={region.y}
                      width={region.width}
                      height={region.height}
                      rx={20}
                      ry={20}
                      fill="none"
                      stroke={isHovered ? "#475569" : "#94a3b8"}
                      strokeWidth={2}
                      strokeDasharray={isHovered ? "none" : "4 2"}
                    />
                    <text
                      x={(region.x ?? 0) + (region.width ?? 0) / 2}
                      y={(region.y ?? 0) + (region.height ?? 0) / 2}
                      textAnchor="middle"
                      dominantBaseline="central"
                      fontSize={7}
                      fill="#94a3b8"
                      style={{ writingMode: "vertical-rl" as const }}
                      transform={`rotate(-90, ${(region.x ?? 0) + (region.width ?? 0) / 2}, ${(region.y ?? 0) + (region.height ?? 0) / 2})`}
                    >
                      HANDSET
                    </text>
                  </g>
                </TooltipTrigger>
                <TooltipContent>{region.label}</TooltipContent>
              </Tooltip>
            )
          }

          // Button regions
          if (region.shape === "circle" && region.cx !== undefined && region.cy !== undefined) {
            return (
              <Tooltip key={region.id}>
                <TooltipTrigger asChild>
                  <g
                    onMouseEnter={() => setHoveredId(region.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    className="cursor-pointer"
                  >
                    <circle
                      cx={region.cx}
                      cy={region.cy}
                      r={region.r ?? 8}
                      fill={isHovered ? colors.hoverFill : colors.fill}
                      stroke={colors.stroke}
                      strokeWidth={1}
                      style={{ transition: "fill 0.15s ease" }}
                    />
                  </g>
                </TooltipTrigger>
                <TooltipContent>{region.label}</TooltipContent>
              </Tooltip>
            )
          }

          // Default: rect button
          return (
            <Tooltip key={region.id}>
              <TooltipTrigger asChild>
                <g
                  onMouseEnter={() => setHoveredId(region.id)}
                  onMouseLeave={() => setHoveredId(null)}
                  className="cursor-pointer"
                >
                  <rect
                    x={region.x}
                    y={region.y}
                    width={region.width}
                    height={region.height}
                    rx={2}
                    fill={isHovered ? colors.hoverFill : colors.fill}
                    stroke={colors.stroke}
                    strokeWidth={0.75}
                    style={{ transition: "fill 0.15s ease" }}
                  />
                  {(region.width ?? 0) > 30 && (
                    <text
                      x={(region.x ?? 0) + (region.width ?? 0) / 2}
                      y={(region.y ?? 0) + (region.height ?? 0) / 2}
                      textAnchor="middle"
                      dominantBaseline="central"
                      fontSize={5}
                      fill={colors.stroke}
                      fontWeight={500}
                    >
                      {region.id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                    </text>
                  )}
                </g>
              </TooltipTrigger>
              <TooltipContent>{region.label}</TooltipContent>
            </Tooltip>
          )
        })}

        {/* Dialpad */}
        {data.dialpad && <DialpadRenderer dialpad={data.dialpad} hoveredId={hoveredId} setHoveredId={setHoveredId} />}
      </g>
    </svg>
  )
}

function DialpadRenderer({
  dialpad,
  hoveredId,
  setHoveredId,
}: {
  dialpad: WireframeDialpad
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const cols = 3
  return (
    <g>
      {dialpad.keys.map((key, i) => {
        const row = Math.floor(i / cols)
        const col = i % cols
        const x = dialpad.startX + col * (dialpad.buttonWidth + dialpad.gapX)
        const y = dialpad.startY + row * (dialpad.buttonHeight + dialpad.gapY)
        const id = `dialpad_${key}`
        const isHovered = hoveredId === id
        const subLabel = dialpad.subLabels[i] || ""

        return (
          <Tooltip key={id}>
            <TooltipTrigger asChild>
              <g
                onMouseEnter={() => setHoveredId(id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-pointer"
              >
                <rect
                  x={x}
                  y={y}
                  width={dialpad.buttonWidth}
                  height={dialpad.buttonHeight}
                  rx={3}
                  fill={isHovered ? "#e2e8f0" : "#f1f5f9"}
                  stroke="#94a3b8"
                  strokeWidth={0.75}
                  style={{ transition: "fill 0.15s ease" }}
                />
                <text
                  x={x + dialpad.buttonWidth / 2}
                  y={y + dialpad.buttonHeight / 2 - (subLabel ? 3 : 0)}
                  textAnchor="middle"
                  dominantBaseline="central"
                  fontSize={10}
                  fontWeight={600}
                  fill="#334155"
                >
                  {key}
                </text>
                {subLabel && (
                  <text
                    x={x + dialpad.buttonWidth / 2}
                    y={y + dialpad.buttonHeight / 2 + 7}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fontSize={4}
                    fill="#94a3b8"
                    letterSpacing={0.5}
                  >
                    {subLabel}
                  </text>
                )}
              </g>
            </TooltipTrigger>
            <TooltipContent>Key: {key}{subLabel ? ` (${subLabel})` : ""}</TooltipContent>
          </Tooltip>
        )
      })}
    </g>
  )
}

// ---------------------------------------------------------------------------
// V1 Color System
// ---------------------------------------------------------------------------

const V1_COLORS = {
  chassisStroke: "rgba(222, 220, 209, 0.3)",
  keyFill: "rgb(48, 48, 46)",
  keyStroke: "rgba(222, 220, 209, 0.3)",
  keyStrokeWidth: 0.75,
  lcdFill: "rgb(48, 48, 46)",
  lcdStroke: "rgba(222, 220, 209, 0.3)",
  textPrimary: "rgb(250, 249, 245)",
  textSecondary: "rgb(194, 192, 182)",
  textTertiary: "rgb(156, 154, 146)",
  successFill: "rgb(27, 70, 20)",
  successStroke: "rgb(89, 145, 48)",
  dangerFill: "rgb(96, 42, 40)",
  dangerStroke: "rgb(205, 92, 88)",
  grilleStroke: "rgba(222, 220, 209, 0.15)",
  softKeyBarBg: "rgb(250, 249, 245)",
  softKeyBarText: "rgb(48, 48, 46)",
  hoverKeyFill: "rgb(62, 62, 60)",
} as const

function getV1KeyColor(color: string) {
  if (color === "success") return { fill: V1_COLORS.successFill, stroke: V1_COLORS.successStroke }
  if (color === "danger") return { fill: V1_COLORS.dangerFill, stroke: V1_COLORS.dangerStroke }
  return { fill: V1_COLORS.keyFill, stroke: V1_COLORS.keyStroke }
}

// Phone icon path data (handset shape used in status bar and line key labels)
const PHONE_ICON_PATH = "M 0 1 Q 0 -1 2 -1 L 4 -1 Q 5 -1 5 0 L 5 2 Q 5 3 4 3 L 3 3 Q 4 5 6 6 L 6 5 Q 6 4 7 4 L 9 4 Q 10 4 10 5 L 10 7 Q 10 8 9 8 Q 3 8 0 2 Z"

// ---------------------------------------------------------------------------
// V1 Wireframe Renderer
// ---------------------------------------------------------------------------

function WireframeRendererV1({ data }: { data: V1WireframeData }) {
  const [hoveredId, setHoveredId] = useState<string | null>(null)

  const vb = data.canvas.viewBox

  return (
    <svg
      viewBox={`${vb.x} ${vb.y} ${vb.width} ${vb.height}`}
      className="w-full max-w-lg mx-auto"
      style={{ fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      {/* Chassis body */}
      <rect
        x={data.body.bounds.x}
        y={data.body.bounds.y}
        width={data.body.bounds.width}
        height={data.body.bounds.height}
        rx={data.body.cornerRadius}
        fill="none"
        stroke={V1_COLORS.chassisStroke}
        strokeWidth={1}
      />

      {/* MWI / Indicators */}
      {data.indicators.map((ind) => {
        const colors = getV1KeyColor(ind.color)
        const isHovered = hoveredId === ind.id
        return (
          <Tooltip key={ind.id}>
            <TooltipTrigger asChild>
              <rect
                x={ind.bounds.x}
                y={ind.bounds.y}
                width={ind.bounds.width}
                height={ind.bounds.height}
                rx={ind.cornerRadius}
                fill={colors.fill}
                stroke={colors.stroke}
                strokeWidth={0.5}
                opacity={isHovered ? 0.8 : 1}
                onMouseEnter={() => setHoveredId(ind.id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-default"
                style={{ transition: "opacity 0.15s ease" }}
              />
            </TooltipTrigger>
            <TooltipContent>{ind.label}</TooltipContent>
          </Tooltip>
        )
      })}

      {/* Handset */}
      <V1HandsetRenderer
        handset={data.handset}
        hoveredId={hoveredId}
        setHoveredId={setHoveredId}
      />

      {/* Branding */}
      <text
        x={data.branding.anchor.x}
        y={data.branding.anchor.y}
        textAnchor={data.branding.anchor.alignment as "start" | "middle" | "end"}
        fill={V1_COLORS.textSecondary}
        fontSize={14}
        fontWeight={500}
      >
        {data.branding.text}
      </text>

      {/* LCD Display */}
      <V1DisplayRenderer
        display={data.display}
        hoveredId={hoveredId}
        setHoveredId={setHoveredId}
      />

      {/* Line Keys */}
      {data.lineKeys.map((lk) => {
        const colors = getV1KeyColor(lk.color)
        const isHovered = hoveredId === lk.id
        return (
          <Tooltip key={lk.id}>
            <TooltipTrigger asChild>
              <rect
                x={lk.bounds.x}
                y={lk.bounds.y}
                width={lk.bounds.width}
                height={lk.bounds.height}
                rx={lk.cornerRadius}
                fill={colors.fill}
                stroke={colors.stroke}
                strokeWidth={V1_COLORS.keyStrokeWidth}
                opacity={isHovered ? 0.8 : 1}
                onMouseEnter={() => setHoveredId(lk.id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-pointer"
                style={{ transition: "opacity 0.15s ease" }}
              />
            </TooltipTrigger>
            <TooltipContent>Line {lk.slot} ({lk.color})</TooltipContent>
          </Tooltip>
        )
      })}

      {/* Soft Keys */}
      {data.softKeys.map((sk) => {
        const isHovered = hoveredId === sk.id
        return (
          <Tooltip key={sk.id}>
            <TooltipTrigger asChild>
              <rect
                x={sk.bounds.x}
                y={sk.bounds.y}
                width={sk.bounds.width}
                height={sk.bounds.height}
                rx={sk.cornerRadius}
                fill={isHovered ? V1_COLORS.hoverKeyFill : V1_COLORS.keyFill}
                stroke={V1_COLORS.keyStroke}
                strokeWidth={V1_COLORS.keyStrokeWidth}
                onMouseEnter={() => setHoveredId(sk.id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-pointer"
                style={{ transition: "fill 0.15s ease" }}
              />
            </TooltipTrigger>
            <TooltipContent>Soft Key {sk.slot}</TooltipContent>
          </Tooltip>
        )
      })}

      {/* Dial Pad */}
      <V1DialPadRenderer
        dialPad={data.dialPad}
        hoveredId={hoveredId}
        setHoveredId={setHoveredId}
      />

      {/* Function Keys */}
      <V1FunctionKeysRenderer
        functionKeys={data.functionKeys}
        hoveredId={hoveredId}
        setHoveredId={setHoveredId}
      />

      {/* Volume Rocker */}
      <V1VolumeRockerRenderer
        rocker={data.volumeRocker}
        hoveredId={hoveredId}
        setHoveredId={setHoveredId}
      />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// V1 Handset Sub-renderer
// ---------------------------------------------------------------------------

function V1HandsetRenderer({
  handset,
  hoveredId,
  setHoveredId,
}: {
  handset: V1Handset
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const isHovered = hoveredId === handset.id
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <g
          onMouseEnter={() => setHoveredId(handset.id)}
          onMouseLeave={() => setHoveredId(null)}
          className="cursor-default"
        >
          {/* Handset body */}
          <rect
            x={handset.bounds.x}
            y={handset.bounds.y}
            width={handset.bounds.width}
            height={handset.bounds.height}
            rx={handset.cornerRadius}
            fill={V1_COLORS.keyFill}
            stroke={V1_COLORS.keyStroke}
            strokeWidth={V1_COLORS.keyStrokeWidth}
            opacity={isHovered ? 0.85 : 1}
            style={{ transition: "opacity 0.15s ease" }}
          />

          {handset.elements.map((el) => {
            if (el.type === "speaker" && el.geometry) {
              // Earpiece: two concentric ellipses
              return (
                <g key={el.id}>
                  <ellipse
                    cx={el.geometry.cx}
                    cy={el.geometry.cy}
                    rx={el.geometry.rx}
                    ry={el.geometry.ry}
                    fill="none"
                    stroke={V1_COLORS.grilleStroke}
                    strokeWidth={V1_COLORS.keyStrokeWidth}
                  />
                  <ellipse
                    cx={el.geometry.cx}
                    cy={el.geometry.cy}
                    rx={22}
                    ry={9}
                    fill="none"
                    stroke={V1_COLORS.grilleStroke}
                    strokeWidth={V1_COLORS.keyStrokeWidth}
                  />
                </g>
              )
            }

            if (el.type === "label" && el.anchor) {
              // HD mark with wifi-wave arcs
              return (
                <g key={el.id}>
                  <text
                    x={el.anchor.x}
                    y={el.anchor.y}
                    textAnchor="end"
                    fill={V1_COLORS.textTertiary}
                    fontSize={11}
                    fontWeight={500}
                  >
                    {el.text}
                  </text>
                  {el.decoration === "wifi-waves" && (
                    <>
                      <path
                        d={`M ${el.anchor.x + 3} ${el.anchor.y - 5} Q ${el.anchor.x + 8} ${el.anchor.y - 5} ${el.anchor.x + 8} ${el.anchor.y}`}
                        fill="none"
                        stroke={V1_COLORS.textTertiary}
                        strokeWidth={1}
                        strokeLinecap="round"
                      />
                      <path
                        d={`M ${el.anchor.x + 3} ${el.anchor.y - 11} Q ${el.anchor.x + 14} ${el.anchor.y - 11} ${el.anchor.x + 14} ${el.anchor.y}`}
                        fill="none"
                        stroke={V1_COLORS.textTertiary}
                        strokeWidth={1}
                        strokeLinecap="round"
                      />
                    </>
                  )}
                </g>
              )
            }

            if (el.type === "microphone" && el.geometry) {
              // Mouthpiece: ellipse + two horizontal grille lines
              return (
                <g key={el.id}>
                  <ellipse
                    cx={el.geometry.cx}
                    cy={el.geometry.cy}
                    rx={el.geometry.rx}
                    ry={el.geometry.ry}
                    fill="none"
                    stroke={V1_COLORS.grilleStroke}
                    strokeWidth={V1_COLORS.keyStrokeWidth}
                  />
                  <line
                    x1={el.geometry.cx - 26}
                    y1={el.geometry.cy - 3}
                    x2={el.geometry.cx + 26}
                    y2={el.geometry.cy - 3}
                    stroke={V1_COLORS.grilleStroke}
                    strokeWidth={V1_COLORS.keyStrokeWidth}
                  />
                  <line
                    x1={el.geometry.cx - 26}
                    y1={el.geometry.cy + 3}
                    x2={el.geometry.cx + 26}
                    y2={el.geometry.cy + 3}
                    stroke={V1_COLORS.grilleStroke}
                    strokeWidth={V1_COLORS.keyStrokeWidth}
                  />
                </g>
              )
            }

            if (el.type === "coiled-cable" && el.anchor) {
              // Wavy coiled cable path going down
              const ax = el.anchor.x
              const ay = el.anchor.y
              return (
                <path
                  key={el.id}
                  d={`M ${ax} ${ay} Q ${ax - 8} ${ay + 7} ${ax} ${ay + 14} Q ${ax + 8} ${ay + 21} ${ax} ${ay + 28} Q ${ax - 8} ${ay + 35} ${ax} ${ay + 42} Q ${ax + 8} ${ay + 49} ${ax} ${ay + 56}`}
                  fill="none"
                  stroke={V1_COLORS.textTertiary}
                  strokeWidth={1.5}
                  strokeLinecap="round"
                />
              )
            }

            return null
          })}
        </g>
      </TooltipTrigger>
      <TooltipContent>Handset</TooltipContent>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// V1 Display Sub-renderer
// ---------------------------------------------------------------------------

function V1DisplayRenderer({
  display,
  hoveredId,
  setHoveredId,
}: {
  display: V1Display
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const isHovered = hoveredId === display.id
  const b = display.bounds
  const c = display.content
  const monoFont = "ui-monospace, monospace"

  // Soft key bar dimensions
  const softKeyBarHeight = 28
  const softKeyBarY = b.y + b.height - softKeyBarHeight
  const softKeyBarWidth = b.width
  const sectionWidth = softKeyBarWidth / c.softKeyBar.labels.length

  // Line key label area
  const lineKeyAreaX = b.x + 142
  const lineKeyAreaY = b.y + 24
  const lineKeyAreaWidth = 124
  const lineKeyRowHeight = 32

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <g
          onMouseEnter={() => setHoveredId(display.id)}
          onMouseLeave={() => setHoveredId(null)}
          className="cursor-default"
        >
          {/* LCD background */}
          <rect
            x={b.x}
            y={b.y}
            width={b.width}
            height={b.height}
            rx={display.cornerRadius}
            fill={V1_COLORS.lcdFill}
            stroke={V1_COLORS.lcdStroke}
            strokeWidth={1}
            opacity={isHovered ? 0.9 : 1}
            style={{ transition: "opacity 0.15s ease" }}
          />

          {/* Status bar: phone icon + text */}
          <g transform={`translate(${b.x + 12}, ${b.y + 16})`}>
            <path d={PHONE_ICON_PATH} fill={V1_COLORS.textPrimary} />
          </g>
          <text
            x={b.x + 28}
            y={b.y + 18}
            fill={V1_COLORS.textPrimary}
            fontFamily={monoFont}
            fontSize={11}
            fontWeight={400}
          >
            {c.statusBar.text}
          </text>

          {/* Primary region: time */}
          <text
            x={b.x + 12}
            y={b.y + 60}
            fill={V1_COLORS.textPrimary}
            fontFamily={monoFont}
            fontSize={22}
            fontWeight={500}
          >
            {c.primaryRegion.time}
          </text>
          {/* Seconds */}
          <text
            x={b.x + 68}
            y={b.y + 52}
            fill={V1_COLORS.textPrimary}
            fontFamily={monoFont}
            fontSize={11}
            fontWeight={400}
          >
            {c.primaryRegion.seconds}
          </text>

          {/* Date */}
          <text
            x={b.x + 12}
            y={b.y + 104}
            fill={V1_COLORS.textPrimary}
            fontFamily={monoFont}
            fontSize={11}
            fontWeight={400}
          >
            {c.primaryRegion.date}
          </text>

          {/* Line key labels area */}
          {c.lineKeyLabels.map((lkl, i) => {
            const rowY = lineKeyAreaY + i * (lineKeyRowHeight + 6)
            return (
              <g key={lkl.slot}>
                <rect
                  x={lineKeyAreaX}
                  y={rowY}
                  width={lineKeyAreaWidth}
                  height={lineKeyRowHeight}
                  rx={2}
                  fill="none"
                  stroke={V1_COLORS.textTertiary}
                  strokeWidth={0.5}
                />
                <g transform={`translate(${lineKeyAreaX + 10}, ${rowY + 18})`}>
                  <path d={PHONE_ICON_PATH} fill={V1_COLORS.textPrimary} />
                </g>
                <text
                  x={lineKeyAreaX + 28}
                  y={rowY + 23}
                  fill={V1_COLORS.textPrimary}
                  fontFamily={monoFont}
                  fontSize={11}
                  fontWeight={400}
                >
                  {lkl.text}
                </text>
              </g>
            )
          })}

          {/* Soft key bar (inverted) */}
          <rect
            x={b.x}
            y={softKeyBarY}
            width={softKeyBarWidth}
            height={softKeyBarHeight}
            fill={V1_COLORS.softKeyBarBg}
          />
          {c.softKeyBar.labels.map((label, i) => (
            <g key={label}>
              <text
                x={b.x + sectionWidth * i + sectionWidth / 2}
                y={softKeyBarY + softKeyBarHeight / 2}
                textAnchor="middle"
                dominantBaseline="middle"
                fill={V1_COLORS.softKeyBarText}
                fontFamily={monoFont}
                fontSize={11}
                fontWeight={400}
              >
                {label}
              </text>
              {/* Divider lines between sections */}
              {i > 0 && (
                <line
                  x1={b.x + sectionWidth * i}
                  y1={softKeyBarY + 3}
                  x2={b.x + sectionWidth * i}
                  y2={softKeyBarY + softKeyBarHeight - 3}
                  stroke={V1_COLORS.softKeyBarText}
                  strokeWidth={0.5}
                />
              )}
            </g>
          ))}
        </g>
      </TooltipTrigger>
      <TooltipContent>LCD Display</TooltipContent>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// V1 Dial Pad Sub-renderer
// ---------------------------------------------------------------------------

function V1DialPadRenderer({
  dialPad,
  hoveredId,
  setHoveredId,
}: {
  dialPad: V1DialPad
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const { origin, keySize, gap, cornerRadius } = dialPad

  return (
    <g transform={`translate(${origin.x}, ${origin.y})`}>
      {dialPad.keys.map((key) => {
        const kx = key.col * (keySize.width + gap)
        const ky = key.row * (keySize.height + gap)
        const isHovered = hoveredId === key.id
        const hasLetters = key.letters.length > 0
        const isSend = key.letters === "SEND"

        // Compute digit text position: shift left when letters are present
        // Reference SVG positions digit at left-of-center, letters after it
        const digitX = hasLetters ? kx + keySize.width / 2 - 14 : kx + keySize.width / 2
        const digitY = ky + keySize.height / 2

        const lettersX = digitX + 13
        const lettersY = ky + keySize.height / 2 + 5

        return (
          <Tooltip key={key.id}>
            <TooltipTrigger asChild>
              <g
                onMouseEnter={() => setHoveredId(key.id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-pointer"
              >
                <rect
                  x={kx}
                  y={ky}
                  width={keySize.width}
                  height={keySize.height}
                  rx={cornerRadius}
                  fill={isHovered ? V1_COLORS.hoverKeyFill : V1_COLORS.keyFill}
                  stroke={V1_COLORS.keyStroke}
                  strokeWidth={V1_COLORS.keyStrokeWidth}
                  style={{ transition: "fill 0.15s ease" }}
                />
                <text
                  x={digitX}
                  y={digitY}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fill={V1_COLORS.textPrimary}
                  fontSize={18}
                  fontWeight={500}
                >
                  {key.digit}
                </text>
                {hasLetters && (
                  <text
                    x={lettersX}
                    y={lettersY}
                    textAnchor="start"
                    fill={V1_COLORS.textTertiary}
                    fontSize={isSend ? 9 : 11}
                    fontWeight={400}
                  >
                    {key.letters}
                  </text>
                )}
              </g>
            </TooltipTrigger>
            <TooltipContent>
              Key: {key.digit}{key.letters ? ` (${key.letters})` : ""}
            </TooltipContent>
          </Tooltip>
        )
      })}
    </g>
  )
}

// ---------------------------------------------------------------------------
// V1 Function Keys Sub-renderer
// ---------------------------------------------------------------------------

function V1FunctionKeyIcon({ icon, cx, cy }: { icon: string; cx: number; cy: number }) {
  const color = V1_COLORS.textSecondary
  const sw = 1.3

  switch (icon) {
    case "microphone-slash":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <rect x={-3} y={-9} width={6} height={11} rx={3} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <path d="M -7 -2 Q -7 6 0 6 Q 7 6 7 -2" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <line x1={0} y1={6} x2={0} y2={10} stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <line x1={-4} y1={10} x2={4} y2={10} stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <line x1={-9} y1={-12} x2={9} y2={11} stroke={color} strokeWidth={1.5} strokeLinecap="round" />
        </g>
      )
    case "envelope":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <rect x={-10} y={-7} width={20} height={14} rx={1} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <path d="M -10 -7 L 0 1 L 10 -7" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
        </g>
      )
    case "phone-arrow":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <path d="M -11 -2 Q -10 -5 -7 -5 L -5 -5 Q -3 -5 -3 -3 L -3 -1 Q -3 0 -4 0 L -5 0 Q -3 3 0 4 L 0 3 Q 0 1 2 1 L 4 1 Q 6 1 6 3 L 6 5 Q 6 7 4 7 Q -7 7 -11 -2 Z" fill="none" stroke={color} strokeWidth={1.2} strokeLinejoin="round" />
          <line x1={7} y1={-4} x2={13} y2={-4} stroke={color} strokeWidth={1.2} />
          <polygon points="11,-7 14,-4 11,-1" fill={color} />
        </g>
      )
    case "headset":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <path d="M -9 2 Q -9 -8 0 -8 Q 9 -8 9 2" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <rect x={-10} y={2} width={4} height={8} rx={1} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <rect x={6} y={2} width={4} height={8} rx={1} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <line x1={-8} y1={9} x2={-8} y2={11} stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <line x1={-8} y1={11} x2={-3} y2={11} stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <circle cx={-2} cy={11} r={1.2} fill={color} />
        </g>
      )
    case "circular-arrow":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <path d="M 9 -1 A 9 9 0 1 1 -3 -8" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <polygon points="-5,-10 -1,-8 -3,-4" fill={color} />
        </g>
      )
    case "speaker-waves":
      return (
        <g transform={`translate(${cx}, ${cy})`}>
          <path d="M -9 -3 L -3 -3 L 2 -8 L 2 8 L -3 3 L -9 3 Z" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <path d="M 5 -4 Q 9 0 5 4" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
          <path d="M 8 -8 Q 14 0 8 8" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round" />
        </g>
      )
    default:
      return null
  }
}

function V1FunctionKeysRenderer({
  functionKeys,
  hoveredId,
  setHoveredId,
}: {
  functionKeys: V1FunctionKeys
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const { origin, keySize, gap, cornerRadius } = functionKeys

  return (
    <g>
      {functionKeys.keys.map((key) => {
        const kx = origin.x + key.col * (keySize.width + gap)
        const ky = origin.y + key.row * (keySize.height + gap)
        const isHovered = hoveredId === key.id

        return (
          <Tooltip key={key.id}>
            <TooltipTrigger asChild>
              <g
                onMouseEnter={() => setHoveredId(key.id)}
                onMouseLeave={() => setHoveredId(null)}
                className="cursor-pointer"
              >
                <rect
                  x={kx}
                  y={ky}
                  width={keySize.width}
                  height={keySize.height}
                  rx={cornerRadius}
                  fill={isHovered ? V1_COLORS.hoverKeyFill : V1_COLORS.keyFill}
                  stroke={V1_COLORS.keyStroke}
                  strokeWidth={V1_COLORS.keyStrokeWidth}
                  style={{ transition: "fill 0.15s ease" }}
                />
                <V1FunctionKeyIcon
                  icon={key.icon}
                  cx={kx + keySize.width / 2}
                  cy={ky + keySize.height / 2}
                />
              </g>
            </TooltipTrigger>
            <TooltipContent>{key.function}</TooltipContent>
          </Tooltip>
        )
      })}
    </g>
  )
}

// ---------------------------------------------------------------------------
// V1 Volume Rocker Sub-renderer
// ---------------------------------------------------------------------------

function V1VolumeRockerRenderer({
  rocker,
  hoveredId,
  setHoveredId,
}: {
  rocker: V1VolumeRocker
  hoveredId: string | null
  setHoveredId: (id: string | null) => void
}) {
  const b = rocker.bounds
  const isHovered = hoveredId === rocker.id

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <g
          onMouseEnter={() => setHoveredId(rocker.id)}
          onMouseLeave={() => setHoveredId(null)}
          className="cursor-pointer"
        >
          <rect
            x={b.x}
            y={b.y}
            width={b.width}
            height={b.height}
            rx={rocker.cornerRadius}
            fill={isHovered ? V1_COLORS.hoverKeyFill : V1_COLORS.keyFill}
            stroke={V1_COLORS.keyStroke}
            strokeWidth={V1_COLORS.keyStrokeWidth}
            style={{ transition: "fill 0.15s ease" }}
          />
          {/* Minus label */}
          <text
            x={b.x + 10}
            y={b.y + b.height / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            fill={V1_COLORS.textSecondary}
            fontSize={11}
            fontWeight={400}
          >
            {"−"}
          </text>
          {/* Plus label */}
          <text
            x={b.x + b.width - 10}
            y={b.y + b.height / 2}
            textAnchor="middle"
            dominantBaseline="middle"
            fill={V1_COLORS.textSecondary}
            fontSize={11}
            fontWeight={400}
          >
            +
          </text>
          {/* Subtle diagonal line across surface */}
          <line
            x1={b.x + 25}
            y1={b.y + b.height - 5}
            x2={b.x + b.width - 25}
            y2={b.y + 5}
            stroke={V1_COLORS.grilleStroke}
            strokeWidth={0.75}
            strokeLinecap="round"
          />
        </g>
      </TooltipTrigger>
      <TooltipContent>Volume Rocker</TooltipContent>
    </Tooltip>
  )
}

// ---------------------------------------------------------------------------
// Config Generator
// ---------------------------------------------------------------------------

function generateConfig(
  template: string,
  variables: Record<string, string>,
): string {
  let result = template
  for (const [key, value] of Object.entries(variables)) {
    result = result.replace(new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, "g"), value)
  }
  return result
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

interface DeviceDiagnosticTabProps {
  deviceId: string
  manufacturer: string | null | undefined
  deviceModel: string | null | undefined
  macAddress?: string | null
  sipUsername?: string
  sipServer?: string
  ipAddress?: string | null
  deviceName?: string
}

export function DeviceDiagnosticTab({
  deviceId,
  manufacturer,
  deviceModel,
  macAddress,
  sipUsername,
  sipServer,
  ipAddress,
  deviceName,
}: DeviceDiagnosticTabProps) {
  const { data: template, isLoading, isError } = useDeviceTemplateLookup(manufacturer, deviceModel)
  const [generatedConfig, setGeneratedConfig] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [liveView, setLiveView] = useState(false)
  const screenshotQuery = useDeviceScreenshot(deviceId, liveView && !!ipAddress)
  const [screenshotUrl, setScreenshotUrl] = useState<string | null>(null)

  useEffect(() => {
    if (!screenshotQuery.data) return
    const url = URL.createObjectURL(screenshotQuery.data)
    setScreenshotUrl(url)
    return () => URL.revokeObjectURL(url)
  }, [screenshotQuery.data])

  const deviceVars = useMemo(
    () => ({
      mac_address: macAddress ?? "",
      sip_username: sipUsername ?? "",
      sip_server: sipServer ?? "",
      ip_address: ipAddress ?? "",
      display_name: deviceName ?? "",
      sip_password: "",
    }),
    [macAddress, sipUsername, sipServer, ipAddress, deviceName],
  )

  function handleGenerateConfig() {
    if (!template?.provisioningTemplate) return
    const config = generateConfig(template.provisioningTemplate, deviceVars)
    setGeneratedConfig(config)
  }

  function handleCopy() {
    if (!generatedConfig) return
    navigator.clipboard.writeText(generatedConfig)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // No manufacturer/model set on the device
  if (!manufacturer || !deviceModel) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <MonitorSmartphone className="mx-auto mb-3 h-10 w-10 text-muted-foreground/50" />
          <p className="font-medium">No device model information</p>
          <p className="mt-1 text-sm">
            Set the manufacturer and model on this device to view its wireframe diagram
            and provisioning template.
          </p>
        </CardContent>
      </Card>
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-[300px] w-full max-w-lg mx-auto rounded-lg" />
          </CardContent>
        </Card>
      </div>
    )
  }

  // No template found for this manufacturer/model
  if (isError || !template) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          <AlertCircle className="mx-auto mb-3 h-10 w-10 text-muted-foreground/50" />
          <p className="font-medium">
            No wireframe template available for {manufacturer} {deviceModel}
          </p>
          <p className="mt-1 text-sm">
            An administrator can create a template for this device model in the Admin panel.
          </p>
        </CardContent>
      </Card>
    )
  }

  const wireframe = normalizeWireframeData(template.wireframeData as Record<string, unknown>)

  const v0LegendItems = [
    { label: "Soft Keys", color: "#3b82f6" },
    { label: "Line Keys", color: "#22c55e" },
    { label: "Navigation", color: "#6b7280" },
    { label: "Function", color: "#f59e0b" },
    { label: "Dialpad", color: "#94a3b8" },
  ]

  const v1LegendItems = [
    { label: "Line (Active)", color: V1_COLORS.successStroke },
    { label: "Line (Busy)", color: V1_COLORS.dangerStroke },
    { label: "Keys", color: "rgba(222, 220, 209, 0.5)" },
    { label: "LCD Display", color: V1_COLORS.textPrimary },
    { label: "Indicator", color: V1_COLORS.dangerStroke },
  ]

  return (
    <div className="space-y-6">
      {/* Wireframe Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <MonitorSmartphone className="h-5 w-5 text-muted-foreground" />
              {template.displayName} Wireframe
            </CardTitle>
            {ipAddress && (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <Switch
                    id="live-view"
                    checked={liveView}
                    onCheckedChange={setLiveView}
                  />
                  <Label htmlFor="live-view" className="text-sm font-medium cursor-pointer">
                    Live View
                  </Label>
                </div>
                {liveView && (
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-8 w-8"
                    onClick={() => screenshotQuery.refetch()}
                    disabled={screenshotQuery.isFetching}
                  >
                    <RefreshCw className={`h-4 w-4 ${screenshotQuery.isFetching ? "animate-spin" : ""}`} />
                  </Button>
                )}
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {liveView && ipAddress ? (
            <div className="flex flex-col items-center gap-3">
              {screenshotQuery.isFetching && !screenshotUrl && (
                <div className="flex items-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  <span className="text-sm">Capturing display...</span>
                </div>
              )}
              {screenshotQuery.isError && (
                <div className="py-8 text-center text-sm text-destructive">
                  <AlertCircle className="mx-auto mb-2 h-8 w-8" />
                  <p>{screenshotQuery.error instanceof Error ? screenshotQuery.error.message : "Failed to capture screenshot"}</p>
                </div>
              )}
              {screenshotUrl && (
                <img
                  src={screenshotUrl}
                  alt="Device LCD screenshot"
                  className="max-w-lg w-full rounded border border-border"
                />
              )}
              <p className="text-xs text-muted-foreground">
                Live capture from {ipAddress}
              </p>
            </div>
          ) : wireframe ? (
            wireframe.version === "v1" ? (
              <WireframeRendererV1 data={wireframe.data} />
            ) : (
              <WireframeRenderer data={wireframe.data} />
            )
          ) : (
            <div className="py-8 text-center text-muted-foreground text-sm">
              <FileCode className="mx-auto mb-2 h-8 w-8 text-muted-foreground/50" />
              <p>Wireframe data uses an unsupported schema format.</p>
              <p className="mt-1 text-xs">
                Expected top-level <code className="bg-muted px-1 rounded">width</code>, <code className="bg-muted px-1 rounded">height</code>, and <code className="bg-muted px-1 rounded">regions</code> fields.
              </p>
            </div>
          )}

          {/* Legend (only when showing wireframe) */}
          {!liveView && (
            <div className="mt-6 flex flex-wrap gap-4 justify-center text-xs text-muted-foreground">
              {(wireframe?.version === "v1" ? v1LegendItems : v0LegendItems).map((item) => (
                <div key={item.label} className="flex items-center gap-1.5">
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-sm border"
                    style={{ backgroundColor: item.color, borderColor: item.color }}
                  />
                  {item.label}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Provisioning Card */}
      {template.provisioningTemplate && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileCode className="h-5 w-5 text-muted-foreground" />
              Provisioning Template
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-lg border bg-muted/30 p-4">
              <pre className="text-xs font-mono whitespace-pre-wrap text-muted-foreground overflow-x-auto">
                {template.provisioningTemplate}
              </pre>
            </div>

            <div className="flex items-center gap-3">
              <Button size="sm" onClick={handleGenerateConfig}>
                <Play className="mr-2 h-4 w-4" />
                Generate Config
              </Button>
              <p className="text-xs text-muted-foreground">
                Substitutes device variables (MAC, SIP credentials, etc.) into the template.
              </p>
            </div>

            {generatedConfig !== null && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium">Generated Configuration</p>
                  <Button variant="outline" size="sm" onClick={handleCopy}>
                    {copied ? (
                      <>
                        <Check className="mr-2 h-4 w-4" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="mr-2 h-4 w-4" />
                        Copy
                      </>
                    )}
                  </Button>
                </div>
                <div className="rounded-lg border bg-card p-4">
                  <pre className="text-xs font-mono whitespace-pre-wrap overflow-x-auto">
                    {generatedConfig}
                  </pre>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
