import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Bot, Download, Settings } from "lucide-react";

export default function AgentsPage() {
  const [agents, setAgents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  useEffect(() => {
    // Placeholder: Load agents from backend
    setLoading(false);
    setAgents([
      {
        id: "agent-1",
        name: "Data Collector",
        description: "Collects system and infrastructure data",
        version: "1.0.0",
        status: "active",
        lastRun: "2025-02-13T10:30:00Z",
      },
      {
        id: "agent-2",
        name: "Security Scanner",
        description: "Scans for security vulnerabilities",
        version: "1.2.1",
        status: "active",
        lastRun: "2025-02-13T11:15:00Z",
      },
      {
        id: "agent-3",
        name: "Performance Monitor",
        description: "Monitors system performance metrics",
        version: "0.9.5",
        status: "inactive",
        lastRun: "2025-02-12T14:45:00Z",
      },
    ]);
  }, []);

  const handleDownloadAgent = (agentName: string) => {
    setMessage({ type: "success", text: `Downloading ${agentName}...` });
    // Placeholder: Implement actual download logic
  };

  const handleConfigureAgent = (agentId: string) => {
    setMessage({ type: "success", text: `Configuring agent ${agentId}...` });
    // Placeholder: Navigate to agent configuration
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
        <p className="text-muted-foreground">
          Manage and configure collection agents.
        </p>
      </div>

      {message && (
        <div
          className={`p-4 rounded-lg flex items-center gap-2 ${
            message.type === "success" ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"
          }`}
        >
          {message.text}
        </div>
      )}

      <Tabs defaultValue="available" className="space-y-4">
        <TabsList>
          <TabsTrigger value="available" className="gap-2">
            <Bot className="w-4 h-4" />
            Available Agents
          </TabsTrigger>
          <TabsTrigger value="installed" className="gap-2">
            <Download className="w-4 h-4" />
            Installed
          </TabsTrigger>
          <TabsTrigger value="configure" className="gap-2">
            <Settings className="w-4 h-4" />
            Configure
          </TabsTrigger>
        </TabsList>

        <TabsContent value="available" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Available Agents</CardTitle>
              <CardDescription>
                Download and install agents to extend Horizon's capabilities.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {loading ? (
                <div className="flex justify-center py-8">
                  <p className="text-muted-foreground">Loading agents...</p>
                </div>
              ) : agents.length === 0 ? (
                <p className="text-muted-foreground text-sm">No agents available.</p>
              ) : (
                <div className="space-y-3">
                  {agents.map((agent) => (
                    <div
                      key={agent.id}
                      className="flex items-center justify-between p-4 border rounded-lg hover:bg-accent/50 transition-colors"
                    >
                      <div className="flex-1">
                        <h3 className="font-medium">{agent.name}</h3>
                        <p className="text-sm text-muted-foreground">{agent.description}</p>
                        <p className="text-xs text-muted-foreground mt-1">Version: {agent.version}</p>
                      </div>
                      <Button onClick={() => handleDownloadAgent(agent.name)} size="sm">
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="installed" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Installed Agents</CardTitle>
              <CardDescription>
                Manage your installed collection agents.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {agents.filter((a) => a.status === "active").length === 0 ? (
                <p className="text-muted-foreground text-sm">No installed agents.</p>
              ) : (
                <div className="space-y-3">
                  {agents
                    .filter((a) => a.status === "active")
                    .map((agent) => (
                      <div
                        key={agent.id}
                        className="flex items-center justify-between p-4 border rounded-lg bg-green-500/5"
                      >
                        <div className="flex-1">
                          <h3 className="font-medium">{agent.name}</h3>
                          <p className="text-xs text-muted-foreground">Last run: {new Date(agent.lastRun).toLocaleString()}</p>
                        </div>
                        <div className="flex gap-2">
                          <Button onClick={() => handleConfigureAgent(agent.id)} variant="outline" size="sm">
                            <Settings className="w-4 h-4 mr-2" />
                            Configure
                          </Button>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="configure" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Agent Configuration</CardTitle>
              <CardDescription>
                Configure agent behavior and settings.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Default Data Collection Interval</Label>
                  <Input type="number" placeholder="300" defaultValue="300" />
                  <p className="text-xs text-muted-foreground">Interval in seconds between data collections</p>
                </div>

                <div className="space-y-2">
                  <Label>Max Concurrent Agents</Label>
                  <Input type="number" placeholder="5" defaultValue="5" />
                  <p className="text-xs text-muted-foreground">Maximum number of agents running simultaneously</p>
                </div>

                <div className="space-y-2">
                  <Label>Data Retention (days)</Label>
                  <Input type="number" placeholder="30" defaultValue="30" />
                  <p className="text-xs text-muted-foreground">How long to keep collected data</p>
                </div>

                <Button className="w-full">
                  Save Configuration
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
