import { useState } from "react";
import { useForm } from "@tanstack/react-form";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";
import { toastSuccess, toastError } from "@/lib/toast";
import {
    useTeams,
    useTeamMembers,
    useCreateTeam,
    useDeleteTeam,
    useAddTeamMember,
    useUpdateTeamMember,
    useRemoveTeamMember,
    useSearchUsers,
} from "@/hooks/useApi";
import { motion, AnimatePresence } from "motion/react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/dashboard/settings/teams")({
    beforeLoad: () => {
        // Check if user is authenticated
        const token = getAccessToken();
        const user = getStoredUser();
        
        if (!token || !user) {
            throw redirect({
                to: '/login',
                replace: true,
            });
        }
    },
    component: TeamsPage,
});
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import {
  Loader2,
  Plus,
  Crown,
  Trash2,
  UserPlus,
  X,
  Users,
  Shield,
  MoreHorizontal,
  Search,
  Settings2
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Team {
    id: string;
    name: string;
    description?: string;
}

interface Member {
    id: string;
    role: string;
    user_id?: string;
    email?: string;
    display_name?: string;
    joined_at?: string;
}

interface UserSearchResult {
    id: string;
    email: string;
    full_name?: string;
}

interface CreateTeamFormValues {
    name: string;
    description: string;
}

interface AddMemberFormValues {
    user_id: string;
    role: string;
}

function CreateTeamForm({
    onSuccess,
}: {
    onSuccess: () => void;
}) {
    const createTeam = useCreateTeam();

    const form = useForm<CreateTeamFormValues>({
        defaultValues: {
            name: "",
            description: "",
        },
        onSubmit: async ({ value }) => {
            try {
                await createTeam.mutateAsync({
                    name: value.name,
                    description: value.description,
                });
                form.reset();
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to create team");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-4"
        >
            <form.Field
                name="name"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>Team Name</Label>
                        <Input
                            id={field.name}
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            placeholder="Engineering"
                            required
                        />
                        <p className="text-xs text-muted-foreground">
                            The display name for the team
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <form.Field
                name="description"
                children={(field) => (
                    <div className="space-y-2">
                        <Label htmlFor={field.name}>Description (optional)</Label>
                        <Input
                            id={field.name}
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            placeholder="Engineering team description"
                        />
                        <p className="text-xs text-muted-foreground">
                            A brief description of the team&apos;s purpose
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <Button type="submit" disabled={form.state.isSubmitting} className="w-full">
                {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                <Plus className="w-4 h-4 mr-2" />
                Create Team
            </Button>
        </form>
    );
}

function AddMemberForm({
    teamId,
    onSuccess,
    onCancel,
}: {
    teamId: string;
    onSuccess: () => void;
    onCancel: () => void;
}) {
    const addTeamMember = useAddTeamMember();
    const [memberSearch, setMemberSearch] = useState("");
    const [selectedUser, setSelectedUser] = useState<UserSearchResult | null>(null);

    const { data: searchResults, isLoading: searchLoading } = useSearchUsers(memberSearch, memberSearch.length >= 2);

    const form = useForm<AddMemberFormValues>({
        defaultValues: {
            user_id: "",
            role: "member",
        },
        onSubmit: async ({ value }) => {
            if (!selectedUser) return;
            try {
                await addTeamMember.mutateAsync({
                    teamId,
                    data: { user_id: value.user_id, role: value.role },
                });
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to add member");
            }
        },
    });

    const handleSelectUser = (user: UserSearchResult) => {
        setSelectedUser(user);
        setMemberSearch(user.email);
        form.setFieldValue("user_id", user.id);
    };

    const handleClearUser = () => {
        setSelectedUser(null);
        setMemberSearch("");
        form.setFieldValue("user_id", "");
    };

    const getInitials = (email: string, fullName?: string) => {
        if (fullName) {
            const parts = fullName.split(" ");
            if (parts.length >= 2) {
                return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
            }
            return fullName[0].toUpperCase();
        }
        return email?.[0]?.toUpperCase() || `?`;
    };

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-3 p-4 border rounded-lg"
        >
            <div className="space-y-2">
                <Label className="text-xs">Search User</Label>
                <div className="relative">
                    <Input
                        value={memberSearch}
                        onChange={(e) => {
                            setMemberSearch(e.target.value);
                            if (selectedUser) handleClearUser();
                        }}
                        placeholder="Search by email or name..."
                        className="pr-10"
                    />
                    <Search className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                </div>

                {memberSearch.length >= 2 && !selectedUser && (
                    <div className="border rounded-lg max-h-40 overflow-y-auto">
                        {searchLoading ? (
                            <div className="p-2 text-sm text-muted-foreground flex items-center gap-2">
                                <Loader2 className="h-3 w-3 animate-spin" />
                                Searching...
                            </div>
                        ) : searchResults?.items?.length === 0 ? (
                            <div className="p-2 text-sm text-muted-foreground">
                                No users found
                            </div>
                        ) : (
                            searchResults?.items?.map((user: UserSearchResult) => (
                                <button
                                    key={user.id}
                                    type="button"
                                    onClick={() => handleSelectUser(user)}
                                    className="w-full p-2 text-left hover:bg-accent flex items-center gap-2"
                                >
                                    <Avatar className="h-6 w-6">
                                        <AvatarFallback className="text-xs">
                                            {getInitials(user.email, user.full_name)}
                                        </AvatarFallback>
                                    </Avatar>
                                    <div>
                                        <p className="text-sm font-medium">{user.email}</p>
                                        {user.full_name && (
                                            <p className="text-xs text-muted-foreground">
                                                {user.full_name}
                                            </p>
                                        )}
                                    </div>
                                </button>
                            ))
                        )}
                    </div>
                )}

                {selectedUser && (
                    <div className="flex items-center justify-between p-2 bg-muted rounded-lg">
                        <div className="flex items-center gap-2">
                            <Avatar className="h-6 w-6">
                                <AvatarFallback className="text-xs">
                                    {getInitials(selectedUser.email, selectedUser.full_name)}
                                </AvatarFallback>
                            </Avatar>
                            <span className="text-sm">{selectedUser.email}</span>
                        </div>
                        <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={handleClearUser}
                        >
                            <X className="h-4 w-4" />
                        </Button>
                    </div>
                )}
            </div>

            <form.Field
                name="role"
                children={(field) => (
                    <div className="space-y-2">
                        <Label className="text-xs">Role</Label>
                        <Select
                            value={field.state.value}
                            onValueChange={field.handleChange}
                        >
                            <SelectTrigger>
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectItem value="member" description="Can view team content and participate">Member</SelectItem>
                                <SelectItem value="admin" description="Can manage team members and settings">Admin</SelectItem>
                            </SelectContent>
                        </Select>
                        <p className="text-xs text-muted-foreground">
                            Admins can manage team members
                        </p>
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />

            <div className="flex gap-2">
                <Button
                    type="submit"
                    disabled={!selectedUser || addTeamMember.isPending}
                    size="sm"
                    className="flex-1"
                >
                    {addTeamMember.isPending && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
                    Add Member
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
                    <X className="h-4 w-4" />
                </Button>
            </div>
        </form>
    );
}

export default function TeamsPage() {
    // State
    const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
    const [showAddMember, setShowAddMember] = useState(false);

    // Queries
    const { data: teamsData, isLoading: teamsLoading } = useTeams();
    const teams: Team[] = teamsData?.items || [];

    const { data: membersData, isLoading: membersLoading, refetch: refetchMembers } = useTeamMembers(selectedTeamId || "");
    const members: Member[] = membersData?.items || [];

    // Mutations
    const deleteTeam = useDeleteTeam();
    const updateTeamMember = useUpdateTeamMember();
    const removeTeamMember = useRemoveTeamMember();

    // Handle team selection
    const handleSelectTeam = (team: Team) => {
        setSelectedTeamId(team.id);
        setShowAddMember(false);
    };

    const handleDeleteTeam = async () => {
        if (!selectedTeamId) return;
        try {
            await deleteTeam.mutateAsync(selectedTeamId);
            setSelectedTeamId(null);
            toastSuccess("Team deleted");
        } catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || "Failed to delete team");
        }
    };

    const handleRemoveMember = async (memberId: string) => {
        if (!selectedTeamId) return;
        try {
            await removeTeamMember.mutateAsync({
                teamId: selectedTeamId,
                memberId,
            });
            toastSuccess("Member removed");
            refetchMembers();
        } catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || "Failed to remove member");
        }
    };

    const handleUpdateMemberRole = async (memberId: string, newRole: string) => {
        if (!selectedTeamId) return;
        try {
            await updateTeamMember.mutateAsync({
                teamId: selectedTeamId,
                memberId,
                data: { role: newRole },
            });
            toastSuccess("Member role updated");
            refetchMembers();
        } catch (err: unknown) {
            const error = err as { message?: string };
            toastError(error.message || "Failed to update member role");
        }
    };

    const getDisplayName = (member: Member) => {
        if (!member) return "Unknown";
        return member.display_name || member.email || "Unknown";
    };

    const getInitials = (member: Member) => {
        const name = member.display_name || member.email || "?";
        if (name.length >= 2) {
            return `${name[0]}${name[1]}`.toUpperCase();
        }
        return name[0]?.toUpperCase() || "?";
    };

    const selectedTeam = teams.find(t => t.id === selectedTeamId);

    return (
        <div className="space-y-6 relative z-10">
            {/* Animated Background */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none -z-10">
                <motion.div 
                    className="absolute -top-40 -right-40 w-[600px] h-[600px] bg-gradient-to-br from-primary/10 via-primary/5 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.3, 1],
                        x: [0, 50, 0],
                        opacity: [0.3, 0.5, 0.3],
                    }}
                    transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                />
                <motion.div 
                    className="absolute -bottom-40 -left-40 w-[500px] h-[500px] bg-gradient-to-tr from-violet-500/10 via-purple-500/5 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.4, 1],
                        x: [0, -40, 0],
                        opacity: [0.2, 0.4, 0.2],
                    }}
                    transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 2 }}
                />
            </div>

            <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
            >
                <h1 className="text-3xl font-bold tracking-tight">Teams</h1>
                <p className="text-muted-foreground mt-1">
                    Manage teams and team members
                </p>
            </motion.div>

            {/* Top Section: Teams Cards + Create Team */}
            <div className="grid gap-6 lg:grid-cols-3">
                {/* Your Teams */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="lg:col-span-2"
                >
                    <Card className="h-full">
                        <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                                <div>
                                    <CardTitle className="text-lg flex items-center gap-2">
                                        <Users className="h-5 w-5 text-primary" />
                                        Your Teams
                                    </CardTitle>
                                    <CardDescription>
                                        {teams.length} team{teams.length !== 1 ? "s" : ""}
                                    </CardDescription>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent>
                            {teamsLoading ? (
                                <div className="flex justify-center py-12">
                                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                                </div>
                            ) : teams.length === 0 ? (
                                <div className="text-center py-8">
                                    <Users className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                                    <p className="text-muted-foreground">No teams yet</p>
                                </div>
                            ) : (
                                <div className="grid gap-3 sm:grid-cols-2">
                                    {teams.map((team, index) => (
                                        <motion.button
                                            key={team.id}
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            transition={{ delay: index * 0.05 }}
                                            onClick={() => handleSelectTeam(team)}
                                            className={cn(
                                                "p-4 text-left border rounded-xl transition-all hover:shadow-md",
                                                selectedTeamId === team.id
                                                    ? "border-primary bg-primary/5 shadow-md"
                                                    : "border-border hover:border-primary/50"
                                            )}
                                        >
                                            <div className="flex items-center gap-3">
                                                <div className={cn(
                                                    "p-2 rounded-lg",
                                                    selectedTeamId === team.id 
                                                        ? "bg-primary/10" 
                                                        : "bg-muted"
                                                )}>
                                                    <Users className={cn(
                                                        "h-4 w-4",
                                                        selectedTeamId === team.id 
                                                            ? "text-primary" 
                                                            : "text-muted-foreground"
                                                    )} />
                                                </div>
                                                <div className="flex-1 min-w-0">
                                                    <p className="font-semibold truncate">{team.name}</p>
                                                    {team.description && (
                                                        <p className="text-xs text-muted-foreground truncate">{team.description}</p>
                                                    )}
                                                </div>
                                            </div>
                                        </motion.button>
                                    ))}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </motion.div>

                {/* Create Team */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                >
                    <Card className="h-full">
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Plus className="h-5 w-5 text-primary" />
                                Create Team
                            </CardTitle>
                            <CardDescription>
                                Create a new team to organize members
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <CreateTeamForm
                                onSuccess={() => {
                                    toastSuccess("Team created successfully");
                                }}
                            />
                        </CardContent>
                    </Card>
                </motion.div>
            </div>

            {/* Bottom Section: Team Members DataTable */}
            {selectedTeam && (
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                >
                    <Card>
                        <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 rounded-lg bg-primary/10">
                                        <Settings2 className="h-5 w-5 text-primary" />
                                    </div>
                                    <div>
                                        <CardTitle className="text-lg">{selectedTeam.name}</CardTitle>
                                        <CardDescription>
                                            {selectedTeam.description || "No description"} • {members.length} member{members.length !== 1 ? "s" : ""}
                                        </CardDescription>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Button variant="outline" size="sm" onClick={() => setShowAddMember(!showAddMember)}>
                                        <UserPlus className="w-4 h-4 mr-1" />
                                        Add Member
                                    </Button>
                                    <AlertDialog>
                                        <AlertDialogTrigger asChild>
                                            <Button variant="outline" size="sm">
                                                <Trash2 className="w-4 h-4 text-destructive" />
                                            </Button>
                                        </AlertDialogTrigger>
                                        <AlertDialogContent>
                                            <AlertDialogHeader>
                                                <AlertDialogTitle>Delete Team</AlertDialogTitle>
                                                <AlertDialogDescription>
                                                    Are you sure you want to delete &quot;{selectedTeam.name}&quot;? This action cannot be undone.
                                                </AlertDialogDescription>
                                            </AlertDialogHeader>
                                            <AlertDialogFooter>
                                                <AlertDialogCancel>Cancel</AlertDialogCancel>
                                                <AlertDialogAction onClick={handleDeleteTeam} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                                                    Delete
                                                </AlertDialogAction>
                                            </AlertDialogFooter>
                                        </AlertDialogContent>
                                    </AlertDialog>
                                </div>
                            </div>
                        </CardHeader>
                        <CardContent>
                            {/* Add Member Form */}
                            <AnimatePresence>
                                {showAddMember && (
                                    <motion.div
                                        initial={{ opacity: 0, height: 0 }}
                                        animate={{ opacity: 1, height: "auto" }}
                                        exit={{ opacity: 0, height: 0 }}
                                        className="mb-4"
                                    >
                                        <AddMemberForm
                                            teamId={selectedTeamId || ""}
                                            onSuccess={() => {
                                                setShowAddMember(false);
                                                toastSuccess("Member added successfully");
                                                refetchMembers();
                                            }}
                                            onCancel={() => setShowAddMember(false)}
                                        />
                                    </motion.div>
                                )}
                            </AnimatePresence>

                            {/* Members DataTable */}
                            {membersLoading ? (
                                <div className="flex justify-center py-12">
                                    <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                                </div>
                            ) : members.length === 0 ? (
                                <div className="text-center py-12">
                                    <Users className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                                    <p className="text-muted-foreground">No members in this team</p>
                                    <Button variant="outline" className="mt-4" onClick={() => setShowAddMember(true)}>
                                        Add the first member
                                    </Button>
                                </div>
                            ) : (
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead className="w-[50px]"></TableHead>
                                            <TableHead>Member</TableHead>
                                            <TableHead>Role</TableHead>
                                            <TableHead>Joined</TableHead>
                                            <TableHead className="w-[50px]"></TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {members.map((member, index) => (
                                            <motion.tr
                                                key={member.id}
                                                initial={{ opacity: 0, x: -10 }}
                                                animate={{ opacity: 1, x: 0 }}
                                                transition={{ delay: index * 0.03 }}
                                                className="group"
                                            >
                                                <TableCell>
                                                    <Avatar className="h-8 w-8">
                                                        <AvatarFallback className="text-xs bg-primary/10 text-primary">
                                                            {getInitials(member)}
                                                        </AvatarFallback>
                                                    </Avatar>
                                                </TableCell>
                                                <TableCell>
                                                    <div>
                                                        <p className="font-medium">{getDisplayName(member)}</p>
                                                        <p className="text-xs text-muted-foreground">{member.email}</p>
                                                    </div>
                                                </TableCell>
                                                <TableCell>
                                                    <Badge variant={member.role === "owner" ? "default" : member.role === "admin" ? "secondary" : "outline"}>
                                                        {member.role === "owner" && <Crown className="h-3 w-3 mr-1" />}
                                                        {member.role === "admin" && <Shield className="h-3 w-3 mr-1" />}
                                                        {member.role}
                                                    </Badge>
                                                </TableCell>
                                                <TableCell className="text-muted-foreground text-sm">
                                                    {member.joined_at ? new Date(member.joined_at).toLocaleDateString() : "—"}
                                                </TableCell>
                                                <TableCell>
                                                    {member.role !== "owner" && (
                                                        <DropdownMenu>
                                                            <DropdownMenuTrigger asChild>
                                                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity">
                                                                    <MoreHorizontal className="h-4 w-4" />
                                                                </Button>
                                                            </DropdownMenuTrigger>
                                                            <DropdownMenuContent align="end">
                                                                <DropdownMenuItem onClick={() => handleUpdateMemberRole(member.id, "member")}>
                                                                    <Badge variant="secondary" className="mr-2">Member</Badge>
                                                                    Set as Member
                                                                </DropdownMenuItem>
                                                                <DropdownMenuItem onClick={() => handleUpdateMemberRole(member.id, "admin")}>
                                                                    <Badge variant="default" className="mr-2">Admin</Badge>
                                                                    Set as Admin
                                                                </DropdownMenuItem>
                                                                <DropdownMenuSeparator />
                                                                <DropdownMenuItem onClick={() => handleRemoveMember(member.id)} className="text-destructive focus:text-destructive">
                                                                    <Trash2 className="h-4 w-4 mr-2" />
                                                                    Remove Member
                                                                </DropdownMenuItem>
                                                            </DropdownMenuContent>
                                                        </DropdownMenu>
                                                    )}
                                                </TableCell>
                                            </motion.tr>
                                        ))}
                                    </TableBody>
                                </Table>
                            )}
                        </CardContent>
                    </Card>
                </motion.div>
            )}
        </div>
    );
}
