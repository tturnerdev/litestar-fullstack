import { zodResolver } from "@hookform/resolvers/zod"
import { useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, Loader2, ShieldCheck, User, UserPlus, X, XCircle } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import * as z from "zod"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { createTeamInvitation, type TeamRoles } from "@/lib/generated/api"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const inviteSchema = z.object({
  email: z.string().email("Please enter a valid email address"),
  role: z.enum(["MEMBER", "ADMIN"] as const),
})

type InviteFormData = z.infer<typeof inviteSchema>

interface InviteMemberDialogProps {
  teamId: string
}

const rolePermissions: Record<string, string[]> = {
  MEMBER: ["View team content", "Create support tickets", "Manage own devices"],
  ADMIN: ["Manage members", "Edit team settings", "View audit logs", "All member permissions"],
}

const roleOptions = [
  {
    value: "MEMBER" as const,
    label: "Member",
    description: "Can view and collaborate on team content",
    icon: User,
  },
  {
    value: "ADMIN" as const,
    label: "Admin",
    description: "Can invite members and manage team settings",
    icon: ShieldCheck,
  },
]

export function InviteMemberDialog({ teamId }: InviteMemberDialogProps) {
  const [open, setOpen] = useState(false)
  const [pendingEmails, setPendingEmails] = useState<string[]>([])
  const [sendProgress, setSendProgress] = useState<{ current: number; total: number } | null>(null)
  const [roleHighlight, setRoleHighlight] = useState(false)
  const roleCardRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()

  const form = useForm<InviteFormData>({
    resolver: zodResolver(inviteSchema),
    defaultValues: {
      email: "",
      role: "MEMBER",
    },
  })

  const currentEmail = form.watch("email")
  const currentRole = form.watch("role")
  const isCurrentEmailValid = emailRegex.test(currentEmail)
  const selectedRole = roleOptions.find((opt) => opt.value === currentRole)

  const addEmail = () => {
    if (isCurrentEmailValid && !pendingEmails.includes(currentEmail)) {
      setPendingEmails((prev) => [...prev, currentEmail])
      form.setValue("email", "")
    }
  }

  const removeEmail = (email: string) => {
    setPendingEmails((prev) => prev.filter((e) => e !== email))
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && isCurrentEmailValid && pendingEmails.length > 0) {
      e.preventDefault()
      addEmail()
    }
  }

  const handleRoleChange = useCallback(
    (onChange: (value: string) => void, value: string) => {
      onChange(value)
      if (pendingEmails.length > 0) {
        setRoleHighlight(true)
      }
    },
    [pendingEmails.length],
  )

  useEffect(() => {
    if (roleHighlight) {
      const timer = setTimeout(() => setRoleHighlight(false), 800)
      return () => clearTimeout(timer)
    }
  }, [roleHighlight])

  const onSubmit = async (data: InviteFormData) => {
    const allEmails = [...pendingEmails]
    if (data.email && emailRegex.test(data.email) && !allEmails.includes(data.email)) {
      allEmails.push(data.email)
    }

    if (allEmails.length === 0) {
      form.setError("email", { message: "Please enter at least one email address" })
      return
    }

    const succeeded: string[] = []
    const failed: string[] = []

    setSendProgress({ current: 0, total: allEmails.length })

    for (let i = 0; i < allEmails.length; i++) {
      setSendProgress({ current: i + 1, total: allEmails.length })
      try {
        await createTeamInvitation({
          path: { team_id: teamId },
          body: {
            email: allEmails[i],
            role: data.role as TeamRoles,
          },
        })
        succeeded.push(allEmails[i])
      } catch {
        failed.push(allEmails[i])
      }
    }

    setSendProgress(null)

    await queryClient.invalidateQueries({ queryKey: ["team", teamId] })
    await queryClient.invalidateQueries({ queryKey: ["teamInvitations", teamId] })

    if (succeeded.length > 0) {
      const emailList = succeeded.length === 1 ? succeeded[0] : `${succeeded.length} people`
      toast.success(`Invitation sent to ${emailList}`)
    }
    if (failed.length > 0) {
      toast.error(`Failed to invite ${failed.join(", ")}`, {
        description: "They may already be invited or team members.",
      })
    }

    if (failed.length === 0) {
      setOpen(false)
      form.reset()
      setPendingEmails([])
    } else {
      setPendingEmails(failed)
      form.setValue("email", "")
    }
  }

  const handleOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next) {
      form.reset()
      setPendingEmails([])
      setSendProgress(null)
    }
  }

  const totalCount = pendingEmails.length + (isCurrentEmailValid && !pendingEmails.includes(currentEmail) ? 1 : 0)

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button size="sm">
          <UserPlus className="mr-2 h-4 w-4" />
          Invite
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/10">
              <UserPlus className="h-5 w-5 text-primary" />
            </div>
            <div>
              <DialogTitle>Invite Team Member</DialogTitle>
              <DialogDescription>Send an invitation to join this team. They'll receive an email to accept or decline.</DialogDescription>
            </div>
          </div>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email address</FormLabel>
                  <div className="flex items-center gap-2">
                    <FormControl>
                      <div className="relative flex-1">
                        <Input
                          {...field}
                          type="email"
                          placeholder="colleague@company.com"
                          onKeyDown={handleKeyDown}
                          className={
                            currentEmail.length > 2 && !isCurrentEmailValid
                              ? "pr-10 border-destructive/50 focus-visible:ring-destructive/30"
                              : currentEmail.length > 0 && isCurrentEmailValid
                                ? "pr-10"
                                : ""
                          }
                        />
                        {currentEmail.length > 0 && isCurrentEmailValid && (
                          <CheckCircle2 className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-emerald-500 transition-opacity duration-200" />
                        )}
                        {currentEmail.length > 2 && !isCurrentEmailValid && (
                          <XCircle className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-destructive/60 transition-opacity duration-200" />
                        )}
                      </div>
                    </FormControl>
                    {pendingEmails.length > 0 && isCurrentEmailValid && (
                      <Button type="button" variant="outline" size="sm" onClick={addEmail}>
                        Add
                      </Button>
                    )}
                  </div>
                  <FormMessage />
                  {pendingEmails.length > 0 && <p className="text-xs text-muted-foreground/60">Up to 10 recipients per batch</p>}
                </FormItem>
              )}
            />

            {pendingEmails.length > 0 && (
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">
                  {pendingEmails.length} recipient{pendingEmails.length !== 1 ? "s" : ""} added
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {pendingEmails.map((email) => (
                    <Badge key={email} variant="secondary" className="gap-1 pl-2 pr-1 py-1 animate-in fade-in zoom-in-95 duration-200">
                      {email}
                      <button type="button" onClick={() => removeEmail(email)} className="ml-0.5 rounded-full p-0.5 transition-colors hover:bg-muted-foreground/20">
                        <X className="h-3 w-3" />
                        <span className="sr-only">Remove {email}</span>
                      </button>
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {pendingEmails.length === 0 && isCurrentEmailValid && (
              <Button type="button" variant="ghost" size="sm" className="text-muted-foreground" onClick={addEmail}>
                <UserPlus className="mr-1.5 h-3.5 w-3.5" />
                Add another recipient
              </Button>
            )}

            <FormField
              control={form.control}
              name="role"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Role</FormLabel>
                  <Select onValueChange={(v) => handleRoleChange(field.onChange, v)} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a role">
                          {selectedRole && (
                            <span className="flex items-center gap-2">
                              <selectedRole.icon className="h-4 w-4 text-muted-foreground" />
                              {selectedRole.label}
                            </span>
                          )}
                        </SelectValue>
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {roleOptions.map((option) => (
                        <SelectItem key={option.value} value={option.value} className="py-3">
                          <div className="flex items-start gap-3">
                            <option.icon className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                            <div className="flex flex-col">
                              <span className="font-medium">{option.label}</span>
                              <span className="text-xs text-muted-foreground">{option.description}</span>
                            </div>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Card ref={roleCardRef} className={`border-dashed transition-all duration-500 ${roleHighlight ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20" : ""}`}>
              <CardContent className="p-3">
                <p className="text-xs font-medium text-muted-foreground mb-1.5">{selectedRole?.label} permissions</p>
                <ul className="space-y-1">
                  {rolePermissions[currentRole]?.map((perm) => (
                    <li key={perm} className="flex items-center gap-1.5 text-xs text-muted-foreground animate-in fade-in slide-in-from-left-1 duration-200">
                      <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-500" />
                      {perm}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            {form.formState.errors.root && (
              <div className="rounded-md bg-destructive/10 border border-destructive/20 p-3">
                <p className="text-destructive text-sm">{form.formState.errors.root.message}</p>
              </div>
            )}
            <div className="flex justify-end gap-3 pt-2">
              <Button type="button" variant="ghost" onClick={() => handleOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={form.formState.isSubmitting}>
                {form.formState.isSubmitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {sendProgress && sendProgress.total > 1 ? `Sending ${sendProgress.current} of ${sendProgress.total}...` : "Sending..."}
                  </>
                ) : totalCount > 1 ? (
                  `Send ${totalCount} Invitations`
                ) : (
                  "Send Invitation"
                )}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
