const deviceTypeLabels: Record<string, string> = {
  desk_phone: "Desk Phone",
  softphone: "Softphone",
  ata: "ATA",
  conference: "Conference",
  other: "Other",
}

export function deviceTypeLabel(deviceType: string): string {
  return deviceTypeLabels[deviceType] ?? deviceType
}
