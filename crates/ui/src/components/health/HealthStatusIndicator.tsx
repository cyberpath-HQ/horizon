import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { AlertCircle, CheckCircle, Loader2 } from "lucide-react";

export function HealthStatusIndicator() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        setError(null);
        const data = await api.healthCheck();
        setHealth(data);
      } catch (err: any) {
        setError(err.message || "Failed to check health");
        setHealth(null);
      } finally {
        setLoading(false);
      }
    };

    checkHealth();

    // Refresh health status every 30 seconds
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = () => {
    if (loading) {
      return <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />;
    }
    if (error || !health || health.status !== "healthy") {
      return <AlertCircle className="w-4 h-4 text-yellow-500" />;
    }
    return <CheckCircle className="w-4 h-4 text-green-500" />;
  };

  const getStatusTitle = () => {
    if (loading) return "Checking system status...";
    if (error) return `System status: Error`;
    if (!health) return "System status: Unknown";
    return `System status: ${health.status}`;
  };

  const dbHealth = health?.checks?.database?.status;
  const redisHealth = health?.checks?.redis?.status;

  return (
    <div className="relative">
      <button
        className="p-2 rounded-lg hover:bg-accent transition-colors"
        title={getStatusTitle()}
        onClick={() => setShowDetails(!showDetails)}
      >
        {getStatusIcon()}
      </button>

      {showDetails && (
        <div className="absolute right-0 top-full mt-2 w-64 bg-card border rounded-lg shadow-lg p-4 space-y-3 z-50">
          <div>
            <h3 className="font-semibold text-sm">System Status</h3>
            {error ? (
              <p className="text-xs text-red-500">Error: {error}</p>
            ) : (
              <p className="text-xs text-muted-foreground capitalize">
                Overall: {health?.status || "unknown"}
              </p>
            )}
          </div>

          {!error && health && (
            <div className="space-y-2">
              {dbHealth && (
                <div className="flex items-center justify-between p-2 rounded bg-background/50 text-xs">
                  <span>Database</span>
                  <span
                    className={`capitalize font-medium ${
                      dbHealth === "healthy" ? "text-green-500" : "text-yellow-500"
                    }`}
                  >
                    {dbHealth}
                  </span>
                </div>
              )}

              {redisHealth && (
                <div className="flex items-center justify-between p-2 rounded bg-background/50 text-xs">
                  <span>Cache (Redis)</span>
                  <span
                    className={`capitalize font-medium ${
                      redisHealth === "healthy"
                        ? "text-green-500"
                        : "text-yellow-500"
                    }`}
                  >
                    {redisHealth}
                  </span>
                </div>
              )}
            </div>
          )}

          <div className="pt-2 border-t text-xs text-muted-foreground">
            {health && (
              <p>
                Uptime: {Math.floor(health.uptime_seconds / 3600)}h{" "}
                {Math.floor((health.uptime_seconds % 3600) / 60)}m
              </p>
            )}
            <p>Last checked: {new Date().toLocaleTimeString()}</p>
          </div>
        </div>
      )}

      {showDetails && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setShowDetails(false)}
        />
      )}
    </div>
  );
}