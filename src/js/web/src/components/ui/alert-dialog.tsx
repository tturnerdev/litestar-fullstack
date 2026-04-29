"use client"

import * as React from "react"

import { cn } from "@/lib/utils"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { buttonVariants } from "@/components/ui/button"

/**
 * AlertDialog built on top of the existing Dialog primitive.
 * Provides a confirmation-style dialog with cancel/action buttons.
 */
const AlertDialog = Dialog
const AlertDialogTrigger = DialogTrigger
const AlertDialogPortal = DialogPortal
const AlertDialogOverlay = DialogOverlay

function AlertDialogContent({ className, ...props }: React.ComponentProps<typeof DialogContent>) {
  return <DialogContent className={cn("[&>[data-slot=dialog-close]]:hidden", className)} {...props} />
}

const AlertDialogHeader = DialogHeader
const AlertDialogFooter = DialogFooter
const AlertDialogTitle = DialogTitle
const AlertDialogDescription = DialogDescription

function AlertDialogAction({ className, ...props }: React.ComponentProps<"button">) {
  return <button className={cn(buttonVariants(), className)} {...props} />
}

function AlertDialogCancel({ className, ...props }: React.ComponentProps<"button">) {
  return <button className={cn(buttonVariants({ variant: "outline" }), className)} {...props} />
}

export {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogOverlay,
  AlertDialogPortal,
  AlertDialogTitle,
  AlertDialogTrigger,
}
