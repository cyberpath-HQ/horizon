import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Users, Loader2, Plus, Crown } from "lucide-react";

export default function TeamsPage() {
  const [teams, setTeams] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  
  const [newTeamName, setNewTeamName] = useState("");
  const [newTeamDescription, setNewTeamDescription] = useState("");
  const [selectedTeam, setSelectedTeam] = useState<any>(null);
  const [members, setMembers] = useState<any[]>([]);

  useEffect(() => {
    loadTeams();
  }, []);

  const loadTeams = async () => {
    setLoading(true);
    try {
      const result = await api.getTeams();
      setTeams(result.items || []);
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to load teams" });
    } finally {
      setLoading(false);
    }
  };

  const loadTeamMembers = async (teamId: string) => {
    try {
      const result = await api.getTeamMembers(teamId);
      setMembers(result.items || []);
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to load members" });
    }
  };

  const handleCreateTeam = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setMessage(null);
    try {
      await api.createTeam({ name: newTeamName, description: newTeamDescription });
      setNewTeamName("");
      setNewTeamDescription("");
      loadTeams();
      setMessage({ type: "success", text: "Team created successfully" });
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to create team" });
    } finally {
      setSaving(false);
    }
  };

  const handleSelectTeam = (team: any) => {
    setSelectedTeam(team);
    loadTeamMembers(team.id);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Teams</h1>
        <p className="text-muted-foreground">
          Manage teams and team members.
        </p>
      </div>

      {message && (
        <div className={`p-4 rounded-lg flex items-center gap-2 ${message.type === "success" ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"}`}>
          {message.text}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Your Teams</CardTitle>
            <CardDescription>
              Teams you belong to.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {loading ? (
              <div className="flex justify-center py-8">
                <Loader2 className="w-6 h-6 animate-spin" />
              </div>
            ) : teams.length === 0 ? (
              <p className="text-muted-foreground text-sm">No teams yet.</p>
            ) : (
              <div className="space-y-2">
                {teams.map((team, index) => (
                  <button
                    key={team.id}
                    onClick={() => handleSelectTeam(team)}
                    className={`w-full p-3 text-left border rounded-lg transition-all animate-stagger-${Math.min(index + 1, 5)} ${
                      selectedTeam?.id === team.id 
                        ? "border-primary bg-primary/5" 
                        : "border-border hover:border-primary/50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium">{team.name}</p>
                        {team.description && (
                          <p className="text-xs text-muted-foreground">{team.description}</p>
                        )}
                      </div>
                      <Users className="w-4 h-4 text-muted-foreground" />
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
              <CardTitle>Create Team</CardTitle>
              <CardDescription>
                Create a new team to organize members.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreateTeam} className="space-y-4">
                <div className="space-y-2">
                  <Label>Team Name</Label>
                  <Input
                    value={newTeamName}
                    onChange={(e) => setNewTeamName(e.target.value)}
                    placeholder="Engineering"
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label>Description (optional)</Label>
                  <Input
                    value={newTeamDescription}
                    onChange={(e) => setNewTeamDescription(e.target.value)}
                    placeholder="Engineering team description"
                  />
                </div>
                <Button type="submit" disabled={saving}>
                  {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                  <Plus className="w-4 h-4 mr-2" />
                  Create Team
                </Button>
              </form>
            </CardContent>
          </Card>

          {selectedTeam && (
            <Card>
              <CardHeader>
                <CardTitle>Team Members</CardTitle>
                <CardDescription>
                  Members of {selectedTeam.name}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {members.length === 0 ? (
                  <p className="text-muted-foreground text-sm">No members yet.</p>
                ) : (
                  <div className="space-y-2">
                    {members.map((member) => (
                      <div key={member.id} className="flex items-center justify-between p-2 border rounded">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                            <span className="text-xs font-medium">
                              {member.user?.email?.charAt(0).toUpperCase() || "?"}
                            </span>
                          </div>
                          <div>
                            <p className="text-sm font-medium">{member.user?.email}</p>
                            <p className="text-xs text-muted-foreground">{member.role}</p>
                          </div>
                        </div>
                        {member.role === "owner" && <Crown className="w-4 h-4 text-yellow-500" />}
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
