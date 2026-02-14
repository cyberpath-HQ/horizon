import { useState, useEffect } from "react";
import { useForm } from "@tanstack/react-form";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";
import {
    useTeams,
    useTeamMembers,
    useCreateTeam,
    useUpdateTeam,
    useDeleteTeam,
    useAddTeamMember,
    useUpdateTeamMember,
    useRemoveTeamMember,
    useSearchUsers,
} from "@/hooks/useApi";
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
import {
  Alert,
  AlertDescription,
  AlertTitle
} from "@/components/ui/alert";
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
  Loader2,
  Plus,
  Crown,
  Trash2,
  UserPlus,
  X,
  Users,
  Shield,
  AlertCircle,
  CheckCircle,
  MoreHorizontal,
  Search
} from "lucide-react";

interface Team {
    id: string;
    name: string;
    description?: string;
}

interface Member {
    id: string;
    role: string;
    user?: {
        email: string;
        first_name?: string;
        last_name?: string;
    };
}

interface UserSearchResult {
    id: string;
    email: string;
    first_name?: string;
    last_name?: string;
}

interface CreateTeamFormValues {
    name: string;
    description: string;
}

interface UpdateTeamFormValues {
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

function UpdateTeamForm({
    team,
    onSuccess,
    onCancel,
}: {
    team: Team;
    onSuccess: () => void;
    onCancel: () => void;
}) {
    const updateTeam = useUpdateTeam();

    const form = useForm<UpdateTeamFormValues>({
        defaultValues: {
            name: team.name,
            description: team.description || "",
        },
        onSubmit: async ({ value }) => {
            try {
                await updateTeam.mutateAsync({
                    id: team.id,
                    data: { name: value.name, description: value.description },
                });
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to update team");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
            className="space-y-3 p-4 bg-muted rounded-lg"
        >
            <Label className="text-sm font-medium">Edit Team</Label>
            <form.Field
                name="name"
                children={(field) => (
                    <div className="space-y-2">
                        <Input
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            placeholder="Team name"
                            required
                        />
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
                        <Input
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                            onBlur={field.handleBlur}
                            placeholder="Description"
                        />
                        {field.state.meta.errors ? (
                            <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                        ) : null}
                    </div>
                )}
            />
            <div className="flex gap-2">
                <Button type="submit" disabled={form.state.isSubmitting} size="sm">
                    {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
                    Save
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
                    Cancel
                </Button>
            </div>
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

    const getInitials = (email: string, firstName?: string, lastName?: string) => {
        if (firstName || lastName) {
            return `${firstName?.[0] || ""}${lastName?.[0] || ""}`.toUpperCase();
        }
        return email?.[0]?.toUpperCase() || "?";
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
                                            {getInitials(user.email, user.first_name, user.last_name)}
                                        </AvatarFallback>
                                    </Avatar>
                                    <div>
                                        <p className="text-sm font-medium">{user.email}</p>
                                        {(user.first_name || user.last_name) && (
                                            <p className="text-xs text-muted-foreground">
                                                {[user.first_name, user.last_name].filter(Boolean).join(" ")}
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
                                    {getInitials(selectedUser.email, selectedUser.first_name, selectedUser.last_name)}
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
                                <SelectItem value="member">Member</SelectItem>
                                <SelectItem value="admin">Admin</SelectItem>
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
    const [editingTeam, setEditingTeam] = useState<Team | null>(null);
    const [showAddMember, setShowAddMember] = useState(false);

    // Alert state
    const [alert, setAlert] = useState<{ type: "success" | "error"; title: string; message: string } | null>(null);

    // Queries
    const { data: teamsData, isLoading: teamsLoading } = useTeams();
    const teams: Team[] = teamsData?.items || [];

    const { data: membersData, isLoading: membersLoading } = useTeamMembers(selectedTeamId || "");
    const members: Member[] = membersData?.items || [];

    // Mutations
    const deleteTeam = useDeleteTeam();
    const updateTeamMember = useUpdateTeamMember();
    const removeTeamMember = useRemoveTeamMember();

    // Auto-dismiss alert
    useEffect(() => {
        if (alert) {
            const timer = setTimeout(() => setAlert(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [alert]);

    // Handle team selection
    const handleSelectTeam = (team: Team) => {
        setSelectedTeamId(team.id);
        setEditingTeam(null);
        setShowAddMember(false);
    };

    const handleDeleteTeam = async () => {
        if (!selectedTeamId) return;
        try {
            await deleteTeam.mutateAsync(selectedTeamId);
            setSelectedTeamId(null);
            setAlert({ type: "success", title: "Success", message: "Team deleted" });
        } catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({ type: "error", title: "Error", message: error.message || "Failed to delete team" });
        }
    };

    const handleRemoveMember = async (memberId: string) => {
        if (!selectedTeamId) return;
        try {
            await removeTeamMember.mutateAsync({
                teamId: selectedTeamId,
                memberId,
            });
            setAlert({ type: "success", title: "Success", message: "Member removed" });
        } catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({ type: "error", title: "Error", message: error.message || "Failed to remove member" });
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
            setAlert({ type: "success", title: "Success", message: "Member role updated" });
        } catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({ type: "error", title: "Error", message: error.message || "Failed to update member role" });
        }
    };

    const startEditTeam = (team: Team) => {
        setEditingTeam(team);
        setShowAddMember(false);
    };

    const getInitials = (email: string, firstName?: string, lastName?: string) => {
        if (firstName || lastName) {
            return `${firstName?.[0] || ""}${lastName?.[0] || ""}`.toUpperCase();
        }
        return email?.[0]?.toUpperCase() || "?";
    };

    const getDisplayName = (user?: { email: string; first_name?: string; last_name?: string }) => {
        if (!user) return "Unknown";
        const name = [user.first_name, user.last_name].filter(Boolean).join(" ");
        return name || user.email;
    };

    const selectedTeam = teams.find(t => t.id === selectedTeamId);

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold tracking-tight">Teams</h1>
                <p className="text-muted-foreground mt-1">
                    Manage teams and team members
                </p>
            </div>

            {alert && (
                <Alert variant={alert.type === "error" ? "destructive" : "default"} className={alert.type === "success" ? "border-green-500 bg-green-50" : ""}>
                    {alert.type === "success" ? <CheckCircle className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                    <AlertTitle>{alert.title}</AlertTitle>
                    <AlertDescription>{alert.message}</AlertDescription>
                </Alert>
            )}

            <div className="grid gap-6 lg:grid-cols-2">
                {/* Teams List */}
                <Card>
                    <CardHeader className="pb-3">
                        <div className="flex items-center justify-between">
                            <div>
                                <CardTitle className="text-lg">Your Teams</CardTitle>
                                <CardDescription>
                                    {teams.length} team{teams.length !== 1 ? "s" : ""}
                                </CardDescription>
                            </div>
                            <Users className="h-5 w-5 text-muted-foreground" />
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
                            <div className="space-y-2">
                                {teams.map((team) => (
                                    <button
                                        key={team.id}
                                        onClick={() => handleSelectTeam(team)}
                                        className={`w-full p-4 text-left border rounded-lg transition-all hover:shadow-sm ${
                                            selectedTeamId === team.id
                                                ? "border-primary bg-primary/5 shadow-sm"
                                                : "border-border hover:border-primary/50"
                                        }`}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <p className="font-semibold">{team.name}</p>
                                                {team.description && (
                                                    <p className="text-sm text-muted-foreground line-clamp-1">{team.description}</p>
                                                )}
                                            </div>
                                            <Users className="h-5 w-5 text-muted-foreground" />
                                        </div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>

                <div className="space-y-6">
                    {/* Create Team */}
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-lg">Create Team</CardTitle>
                            <CardDescription>
                                Create a new team to organize members
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <CreateTeamForm
                                onSuccess={() => {
                                    setAlert({ type: "success", title: "Success", message: "Team created successfully" });
                                }}
                            />
                        </CardContent>
                    </Card>

                    {/* Team Details */}
                    {selectedTeam && (
                        <Card>
                            <CardHeader className="pb-3">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <CardTitle className="text-lg flex items-center gap-2">
                                            {selectedTeam.name}
                                            <Badge variant="secondary">{members.length} members</Badge>
                                        </CardTitle>
                                        <CardDescription>
                                            {selectedTeam.description || "No description"}
                                        </CardDescription>
                                    </div>
                                    <div className="flex gap-2">
                                        <Button variant="outline" size="sm" onClick={() => startEditTeam(selectedTeam)}>
                                            Edit
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
                            <CardContent className="space-y-4">
                                {/* Edit Team Form */}
                                {editingTeam && (
                                    <UpdateTeamForm
                                        team={editingTeam}
                                        onSuccess={() => {
                                            setEditingTeam(null);
                                            setAlert({ type: "success", title: "Success", message: "Team updated" });
                                        }}
                                        onCancel={() => setEditingTeam(null)}
                                    />
                                )}

                                {/* Members Header */}
                                <div className="flex items-center justify-between">
                                    <Label className="text-sm font-medium">Members</Label>
                                    {!showAddMember && !editingTeam && (
                                        <Button variant="outline" size="sm" onClick={() => setShowAddMember(true)}>
                                            <UserPlus className="w-4 h-4 mr-1" />
                                            Add Member
                                        </Button>
                                    )}
                                </div>

                                {/* Add Member Form with Autocomplete */}
                                {showAddMember && (
                                    <AddMemberForm
                                        teamId={selectedTeamId || ""}
                                        onSuccess={() => {
                                            setShowAddMember(false);
                                            setAlert({ type: "success", title: "Success", message: "Member added successfully" });
                                        }}
                                        onCancel={() => setShowAddMember(false)}
                                    />
                                )}

                                {/* Members List */}
                                {membersLoading ? (
                                    <div className="flex justify-center py-4">
                                        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                                    </div>
                                ) : members.length === 0 ? (
                                    <p className="text-muted-foreground text-sm py-4 text-center">No members yet</p>
                                ) : (
                                    <div className="space-y-2">
                                        {members.map((member) => (
                                            <div key={member.id} className="flex items-center justify-between p-3 border rounded-lg">
                                                <div className="flex items-center gap-3">
                                                    <Avatar className="h-9 w-9">
                                                        <AvatarFallback className="text-sm">
                                                            {getInitials(member.user?.email || "", member.user?.first_name, member.user?.last_name)}
                                                        </AvatarFallback>
                                                    </Avatar>
                                                    <div>
                                                        <p className="font-medium text-sm">{getDisplayName(member.user)}</p>
                                                        <p className="text-xs text-muted-foreground capitalize">{member.role}</p>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    {member.role === "owner" && (
                                                        <Crown className="h-4 w-4 text-yellow-500" />
                                                    )}
                                                    {member.role === "admin" && (
                                                        <Shield className="h-4 w-4 text-muted-foreground" />
                                                    )}
                                                    {member.role !== "owner" && (
                                                        <DropdownMenu>
                                                            <DropdownMenuTrigger asChild>
                                                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
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
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    )}
                </div>
            </div>
        </div>
    );
}
