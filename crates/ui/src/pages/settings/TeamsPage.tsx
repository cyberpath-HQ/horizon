import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
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
  MoreHorizontal
} from "lucide-react";

export default function TeamsPage() {
  const [teams, setTeams] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [alert, setAlert] = useState<{ type: "success" | "error"; title: string; message: string } | null>(null);
  
  const [newTeamName, setNewTeamName] = useState("");
  const [newTeamDescription, setNewTeamDescription] = useState("");
  const [selectedTeam, setSelectedTeam] = useState<any>(null);
  const [members, setMembers] = useState<any[]>([]);
  
  const [showAddMember, setShowAddMember] = useState(false);
  const [newMemberEmail, setNewMemberEmail] = useState("");
  const [newMemberRole, setNewMemberRole] = useState("member");
  
  const [editingTeam, setEditingTeam] = useState<any>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");

  useEffect(() => {
    loadTeams();
  }, []);

  useEffect(() => {
    if (alert) {
      const timer = setTimeout(() => setAlert(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [alert]);

  const loadTeams = async () => {
    setLoading(true);
    try {
      const result = await api.getTeams();
      setTeams(result.items || []);
    } catch (err: any) {
      console.error("Failed to load teams:", err);
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to load teams" });
    } finally {
      setLoading(false);
    }
  };

  const loadTeamMembers = async (teamId: string) => {
    try {
      const result = await api.getTeamMembers(teamId);
      setMembers(result.items || []);
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to load members" });
    }
  };

  const handleCreateTeam = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setAlert(null);
    try {
      await api.createTeam({ name: newTeamName, description: newTeamDescription });
      setNewTeamName("");
      setNewTeamDescription("");
      loadTeams();
      setAlert({ type: "success", title: "Success", message: "Team created successfully" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to create team" });
    } finally {
      setSaving(false);
    }
  };

  const handleSelectTeam = (team: any) => {
    setSelectedTeam(team);
    setEditingTeam(null);
    setShowAddMember(false);
    loadTeamMembers(team.id);
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTeam) return;
    setSaving(true);
    try {
      await api.addTeamMember(selectedTeam.id, { user_id: newMemberEmail, role: newMemberRole });
      setNewMemberEmail("");
      setNewMemberRole("member");
      setShowAddMember(false);
      loadTeamMembers(selectedTeam.id);
      setAlert({ type: "success", title: "Success", message: "Member added successfully" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to add member" });
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveMember = async (memberId: string) => {
    if (!selectedTeam) return;
    try {
      await api.removeTeamMember(selectedTeam.id, memberId);
      loadTeamMembers(selectedTeam.id);
      setAlert({ type: "success", title: "Success", message: "Member removed" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to remove member" });
    }
  };

  const handleUpdateMemberRole = async (memberId: string, newRole: string) => {
    if (!selectedTeam) return;
    try {
      await api.updateTeamMember(selectedTeam.id, memberId, { role: newRole });
      loadTeamMembers(selectedTeam.id);
      setAlert({ type: "success", title: "Success", message: "Member role updated" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to update member role" });
    }
  };

  const handleUpdateTeam = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingTeam) return;
    setSaving(true);
    try {
      await api.updateTeam(editingTeam.id, { name: editName, description: editDescription });
      setEditingTeam(null);
      loadTeams();
      if (selectedTeam?.id === editingTeam.id) {
        setSelectedTeam({ ...selectedTeam, name: editName, description: editDescription });
      }
      setAlert({ type: "success", title: "Success", message: "Team updated" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to update team" });
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteTeam = async () => {
    if (!selectedTeam) return;
    try {
      await api.deleteTeam(selectedTeam.id);
      setSelectedTeam(null);
      loadTeams();
      setAlert({ type: "success", title: "Success", message: "Team deleted" });
    } catch (err: any) {
      setAlert({ type: "error", title: "Error", message: err.message || "Failed to delete team" });
    }
  };

  const startEditTeam = (team: any) => {
    setEditingTeam(team);
    setEditName(team.name);
    setEditDescription(team.description || "");
    setShowAddMember(false);
  };

  const getInitials = (email: string) => email?.[0]?.toUpperCase() || "?";

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
            {loading ? (
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
                      selectedTeam?.id === team.id 
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
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Create Team</CardTitle>
              <CardDescription>
                Create a new team to organize members
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateTeam} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="teamName">Team Name</Label>
                  <Input
                    id="teamName"
                    value={newTeamName}
                    onChange={(e) => setNewTeamName(e.target.value)}
                    placeholder="Engineering"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="teamDesc">Description (optional)</Label>
                  <Input
                    id="teamDesc"
                    value={newTeamDescription}
                    onChange={(e) => setNewTeamDescription(e.target.value)}
                    placeholder="Engineering team description"
                  />
                </div>
                <Button type="submit" disabled={saving} className="w-full">
                  {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                  <Plus className="w-4 h-4 mr-2" />
                  Create Team
                </Button>
              </form>
            </CardContent>
          </Card>

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
                            Are you sure you want to delete "{selectedTeam.name}"? This action cannot be undone.
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
                {editingTeam && (
                  <form onSubmit={handleUpdateTeam} className="space-y-3 p-4 bg-muted rounded-lg">
                    <Label className="text-sm font-medium">Edit Team</Label>
                    <Input
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      placeholder="Team name"
                      required
                    />
                    <Input
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      placeholder="Description"
                    />
                    <div className="flex gap-2">
                      <Button type="submit" disabled={saving} size="sm">
                        {saving && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
                        Save
                      </Button>
                      <Button type="button" variant="ghost" size="sm" onClick={() => setEditingTeam(null)}>
                        Cancel
                      </Button>
                    </div>
                  </form>
                )}

                <div className="flex items-center justify-between">
                  <Label className="text-sm font-medium">Members</Label>
                  {!showAddMember && !editingTeam && (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                          <UserPlus className="w-4 h-4 mr-1" />
                          Add Member
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-[300px]">
                        <form onSubmit={handleAddMember} className="space-y-3 p-3">
                          <div className="space-y-1">
                            <Label className="text-xs">Email</Label>
                            <Input
                              value={newMemberEmail}
                              onChange={(e) => setNewMemberEmail(e.target.value)}
                              placeholder="user@example.com"
                              required
                            />
                          </div>
                          <div className="space-y-1">
                            <Label className="text-xs">Role</Label>
                            <Select value={newMemberRole} onValueChange={setNewMemberRole}>
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="member">Member</SelectItem>
                                <SelectItem value="admin">Admin</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="flex gap-2">
                            <Button type="submit" disabled={saving} size="sm" className="flex-1">
                              {saving && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
                              Add
                            </Button>
                          </div>
                        </form>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}
                </div>

                {showAddMember && (
                  <form onSubmit={handleAddMember} className="flex gap-2 items-end p-3 border rounded-lg">
                    <div className="flex-1 space-y-1">
                      <Label className="text-xs">Email</Label>
                      <Input
                        value={newMemberEmail}
                        onChange={(e) => setNewMemberEmail(e.target.value)}
                        placeholder="user@example.com"
                        required
                      />
                    </div>
                    <div className="w-24 space-y-1">
                      <Label className="text-xs">Role</Label>
                      <Select value={newMemberRole} onValueChange={setNewMemberRole}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="member">Member</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button type="submit" disabled={saving} size="sm">
                      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                    </Button>
                    <Button type="button" variant="ghost" size="sm" onClick={() => setShowAddMember(false)}>
                      <X className="w-4 h-4" />
                    </Button>
                  </form>
                )}

                {members.length === 0 ? (
                  <p className="text-muted-foreground text-sm py-4 text-center">No members yet</p>
                ) : (
                  <div className="space-y-2">
                    {members.map((member) => (
                      <div key={member.id} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center gap-3">
                          <Avatar className="h-9 w-9">
                            <AvatarFallback className="text-sm">
                              {getInitials(member.user?.email)}
                            </AvatarFallback>
                          </Avatar>
                          <div>
                            <p className="font-medium text-sm">{member.user?.email}</p>
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
