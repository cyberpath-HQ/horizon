import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  FolderKanban,
  Shield,
  Network,
  AlertTriangle,
  Activity,
  TrendingUp,
  Server,
  CheckCircle,
  XCircle,
  Loader2,
} from "lucide-react";
import { useEffect, useState } from "react";

interface HealthStatus {
  status: string;
  database: string;
  redis: string;
  timestamp: string;
}

export default function DashboardPage() {
  const { user } = useAuth();
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  const checkHealth = async () => {
    try {
      setHealthLoading(true);
      const healthData = await api.healthCheck();
      setHealth(healthData);
      setHealthError(null);
    } catch (err) {
      setHealthError("Unable to connect to server");
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  };

  // Check health on mount and then every 30 seconds
  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const stats = [
    {
      title: "Total Assets",
      value: "1,234",
      change: "+12%",
      changeType: "positive",
      icon: FolderKanban,
    },
    {
      title: "Security Score",
      value: "87%",
      change: "+5%",
      changeType: "positive",
      icon: Shield,
    },
    {
      title: "Active Vulnerabilities",
      value: "23",
      change: "-8%",
      changeType: "positive",
      icon: AlertTriangle,
    },
    {
      title: "Network Devices",
      value: "156",
      change: "+3%",
      changeType: "positive",
      icon: Network,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Health Status Banner */}
      <Card className={healthError ? "border-destructive" : health?.status === "healthy" ? "border-green-500" : "border-yellow-500"}>
        <CardContent className="py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="h-5 w-5" />
              <div>
                <p className="font-medium">System Status</p>
                <p className="text-sm text-muted-foreground">
                  {healthLoading ? (
                    <span className="flex items-center gap-1">
                      <Loader2 className="h-3 w-3 animate-spin" />
                      Checking...
                    </span>
                  ) : healthError ? (
                    <span className="text-destructive flex items-center gap-1">
                      <XCircle className="h-3 w-3" />
                      {healthError}
                    </span>
                  ) : health?.status === "healthy" ? (
                    <span className="text-green-500 flex items-center gap-1">
                      <CheckCircle className="h-3 w-3" />
                      All systems operational
                    </span>
                  ) : (
                    <span className="text-yellow-500 flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3" />
                      Systems degraded
                    </span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm text-muted-foreground">
              {health && (
                <>
                  <span className="flex items-center gap-1">
                    Database: 
                    <span className={health.database === "healthy" ? "text-green-500" : "text-destructive"}>
                      {health.database}
                    </span>
                  </span>
                  <span className="flex items-center gap-1">
                    Cache: 
                    <span className={health.redis === "healthy" ? "text-green-500" : "text-destructive"}>
                      {health.redis}
                    </span>
                  </span>
                </>
              )}
              <Button variant="ghost" size="sm" onClick={checkHealth} disabled={healthLoading}>
                <Activity className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Welcome Header */}
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">
          Welcome back, {user?.displayName?.split(" ")[0] || "User"}
        </h1>
        <p className="text-muted-foreground">
          Here's what's happening with your infrastructure today.
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.title} className="hover-lift">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {stat.title}
              </CardTitle>
              <stat.icon className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground flex items-center gap-1 mt-1">
                <TrendingUp className="h-3 w-3" />
                <span className={stat.changeType === "positive" ? "text-green-600" : "text-red-600"}>
                  {stat.change}
                </span>
                <span className="text-muted-foreground">from last month</span>
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Activity Chart Placeholder */}
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Asset Activity</CardTitle>
            <CardDescription>
              Asset changes over the past 30 days
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] flex items-center justify-center border-2 border-dashed rounded-lg">
              <div className="text-center">
                <Activity className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">
                  Activity chart coming soon
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Recent Changes</CardTitle>
            <CardDescription>
              Latest asset modifications
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                    <FolderKanban className="h-4 w-4 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      Asset updated
                    </p>
                    <p className="text-xs text-muted-foreground">
                      2 hours ago
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
