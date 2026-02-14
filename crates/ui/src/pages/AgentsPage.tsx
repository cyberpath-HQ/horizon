import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Alert, 
  AlertDescription, 
  AlertTitle 
} from "@/components/ui/alert";
import { 
  Bot, 
  Download, 
  Settings, 
  Play, 
  Square, 
  Loader2,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertCircle
} from "lucide-react";

interface Agent {
  id: string;
  name: string;
  description: string;
  version: string;
  status: "active" | "inactive" | "installing";
  lastRun?: string;
  downloadUrl?: string;
}

const MOCK_AGENTS: Agent[] = [
  {
    id: "agent-data-collector",
    name: "Data Collector",
    description: "Collects system and infrastructure data",
    version: "1.0.0",
    status: "active",
    lastRun: new Date().toISOString(),
    downloadUrl: "https://example.com/download/data-collector",
  },
  {
    id: "agent-security-scanner",
    name: "Security Scanner",
    description: "Scans for security vulnerabilities",
    version: "1.2.1",
    status: "active",
    lastRun: new Date(Date.now() - 3600000).toISOString(),
    downloadUrl: "https://example.com/download/security-scanner",
  },
  {
    id: "agent-performance-monitor",
    name: "Performance Monitor",
    description: "Monitors system performance metrics",
    version: "0.9.5",
    status: "inactive",
    lastRun: new Date(Date.now() - 86400000).toISOString(),
    downloadUrl: "https://example.com/download/performance-monitor",
  },
];

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [configLoading, setConfigLoading] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Configuration state
  const [dataCollectionInterval, setDataCollectionInterval] = useState("300");
  const [maxConcurrentAgents, setMaxConcurrentAgents] = useState("5");
  const [dataRetentionDays, setDataRetentionDays] = useState("30");

  useEffect(() => {
    loadAgents();
  }, []);

  const loadAgents = async () => {
    setLoading(true);
    try {
      // Simulate API call - replace with actual API call
      // const response = await api.getAgents();
      // setAgents(response);
      setAgents(MOCK_AGENTS);
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to load agents" });
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadAgent = async (agent: Agent) => {
    setDownloading(agent.id);
    setMessage(null);
    try {
      // Simulate download - replace with actual API call
      // await api.downloadAgent(agent.id);
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      setMessage({ type: "success", text: `${agent.name} downloaded successfully` });
      
      // Update agent status to installed
      setAgents(prev => prev.map(a => 
        a.id === agent.id 
          ? { ...a, status: "active" as const, lastRun: new Date().toISOString() }
          : a
      ));
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || `Failed to download ${agent.name}` });
    } finally {
      setDownloading(null);
    }
  };

  const handleToggleAgent = async (agentId: string) => {
    setAgents(prev => prev.map(a => {
      if (a.id === agentId) {
        return { 
          ...a, 
          status: a.status === "active" ? "inactive" as const : "active" as const,
          lastRun: a.status === "inactive" ? new Date().toISOString() : a.lastRun
        };
      }
      return a;
    }));
    setMessage({ type: "success", text: "Agent status updated" });
  };

  const handleSaveConfiguration = async () => {
    setConfigLoading(true);
    try {
      // Simulate API call - replace with actual API call
      // await api.saveAgentConfig({ dataCollectionInterval, maxConcurrentAgents, dataRetentionDays });
      await new Promise(resolve => setTimeout(resolve, 1000));
      setMessage({ type: "success", text: "Configuration saved successfully" });
    } catch (err: any) {
      setMessage({ type: "error", text: err.message || "Failed to save configuration" });
    } finally {
      setConfigLoading(false);
    }
  };

  const getStatusBadge = (status: Agent["status"]) => {
    switch (status) {
      case "active":
        return (
          <span className="flex items-center gap-1 text-green-600">
            <CheckCircle className="h-3 w-3" />
            Active
          </span>
        );
      case "installing":
        return (
          <span className="flex items-center gap-1 text-blue-600">
            <Loader2 className="h-3 w-3 animate-spin" />
            Installing
          </span>
        );
      case "inactive":
        return (
          <span className="flex items-center gap-1 text-gray-500">
            <XCircle className="h-3 w-3" />
            Inactive
          </span>
        );
    }
  };

  const installedAgents = agents.filter(a => a.status !== "installing");
  const availableAgents = agents;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Agents</h1>
          <p className="text-muted-foreground">
            Manage and configure collection agents.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadAgents} disabled={loading} className="gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {message && (
        <Alert variant={message.type === "error" ? "destructive" : "default"}>
          {message.type === "error" ? <AlertCircle className="h-4 w-4" /> : <CheckCircle className="h-4 w-4" />}
          <AlertTitle>{message.type === "error" ? "Error" : "Success"}</AlertTitle>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
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
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : availableAgents.length === 0 ? (
                <p className="text-muted-foreground text-sm">No agents available.</p>
              ) : (
                <div className="space-y-3">
                  {availableAgents.map((agent) => (
                    <div
                      key={agent.id}
                      className="flex items-center justify-between p-4 border rounded-lg hover:bg-accent/50 transition-colors"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <h3 className="font-medium">{agent.name}</h3>
                          {getStatusBadge(agent.status)}
                        </div>
                        <p className="text-sm text-muted-foreground">{agent.description}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Version: {agent.version}
                          {agent.lastRun && ` • Last run: ${new Date(agent.lastRun).toLocaleString()}`}
                        </p>
                      </div>
                      <div className="flex gap-2">
                        {agent.status === "inactive" || agent.status === "installing" ? (
                          <Button 
                            onClick={() => handleDownloadAgent(agent)} 
                            size="sm"
                            disabled={downloading === agent.id}
                          >
                            {downloading === agent.id ? (
                              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            ) : (
                              <Download className="w-4 h-4 mr-2" />
                            )}
                            {agent.status === "installing" ? "Installing..." : "Download"}
                          </Button>
                        ) : (
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleToggleAgent(agent.id)}
                          >
                            <Square className="w-4 h-4 mr-2" />
                            Stop
                          </Button>
                        )}
                        {agent.status === "active" && (
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleToggleAgent(agent.id)}
                          >
                            <Play className="w-4 h-4 mr-2" />
                            Run Now
                          </Button>
                        )}
                      </div>
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
              {installedAgents.filter(a => a.status === "active" || a.status === "inactive").length === 0 ? (
                <div className="text-center py-8">
                  <Bot className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground text-sm">No installed agents.</p>
                  <Button variant="outline" className="mt-4" onClick={() => {
                    const tab = document.querySelector('[data-state][value="available"]') as HTMLButtonElement;
                    tab?.click();
                  }}>
                    Browse Available Agents
                  </Button>
                </div>
              ) : (
                <div className="space-y-3">
                  {installedAgents
                    .filter(a => a.status === "active" || a.status === "inactive")
                    .map((agent) => (
                      <div
                        key={agent.id}
                        className={`flex items-center justify-between p-4 border rounded-lg ${
                          agent.status === "active" ? "bg-green-500/5 border-green-200" : "bg-muted/50"
                        }`}
                      >
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h3 className="font-medium">{agent.name}</h3>
                            {getStatusBadge(agent.status)}
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">
                            Version: {agent.version}
                            {agent.lastRun && ` • Last run: ${new Date(agent.lastRun).toLocaleString()}`}
                          </p>
                        </div>
                        <div className="flex gap-2">
                          {agent.status === "active" ? (
                            <>
                              <Button variant="outline" size="sm" onClick={() => handleToggleAgent(agent.id)}>
                                <Square className="w-4 h-4 mr-2" />
                                Stop
                              </Button>
                              <Button variant="outline" size="sm">
                                <Settings className="w-4 h-4 mr-2" />
                                Configure
                              </Button>
                            </>
                          ) : (
                            <Button size="sm" onClick={() => handleToggleAgent(agent.id)}>
                              <Play className="w-4 h-4 mr-2" />
                              Start
                            </Button>
                          )}
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
                  <Input 
                    type="number" 
                    placeholder="300" 
                    value={dataCollectionInterval}
                    onChange={(e) => setDataCollectionInterval(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">Interval in seconds between data collections</p>
                </div>

                <div className="space-y-2">
                  <Label>Max Concurrent Agents</Label>
                  <Input 
                    type="number" 
                    placeholder="5" 
                    value={maxConcurrentAgents}
                    onChange={(e) => setMaxConcurrentAgents(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">Maximum number of agents running simultaneously</p>
                </div>

                <div className="space-y-2">
                  <Label>Data Retention (days)</Label>
                  <Input 
                    type="number" 
                    placeholder="30" 
                    value={dataRetentionDays}
                    onChange={(e) => setDataRetentionDays(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">How long to keep collected data</p>
                </div>

                <Button 
                  className="w-full" 
                  onClick={handleSaveConfiguration}
                  disabled={configLoading}
                >
                  {configLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
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
