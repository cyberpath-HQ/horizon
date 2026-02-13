import {
    useEffect, useState
} from "react";
import { api } from "@/lib/api";
import {
    AlertCircle, CheckCircle
} from "lucide-react";

export function HealthStatusIndicator() {
    const [
        health,
        setHealth,
    ] = useState<any>(null);
    const [
        loading,
        setLoading,
    ] = useState(true);
    const [
        showDetails,
        setShowDetails,
    ] = useState(false);

    useEffect(() => {
        const checkHealth = async() => {
            try {
                const data = await api.healthCheck();
                setHealth(data);
            }
            catch (err) {
                setHealth(null);
            }
            finally {
                setLoading(false);
            }
        };

        checkHealth();

        // Refresh health status every 30 seconds
        const interval = setInterval(checkHealth, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading || !health) {
        return null;
    }

    const isHealthy = health.status === `healthy`;
    const dbHealth = health.checks?.database?.status;
    const redisHealth = health.checks?.redis?.status;

    return (
        <div className="relative">
            <button
                className="p-2 rounded-lg hover:bg-accent transition-colors"
                title={`System Status: ${ health.status }`}
                onClick={() => setShowDetails(!showDetails)}
            >
                {isHealthy
? (
          <CheckCircle className="w-4 h-4 text-green-500" />
        )
: (
          <AlertCircle className="w-4 h-4 text-yellow-500" />
        )}
            </button>

            {showDetails && (
                <div className="absolute right-0 top-full mt-2 w-64 bg-card border rounded-lg shadow-lg p-4 space-y-3 z-50">
                    <div>
                        <h3 className="font-semibold text-sm">System Status</h3>
                        <p className="text-xs text-muted-foreground capitalize">
                            Overall: {health.status}
                        </p>
                    </div>

                    <div className="space-y-2">
                        {dbHealth && (
                            <div className="flex items-center justify-between p-2 rounded bg-background/50 text-xs">
                                <span>Database</span>
                                <span
                                    className={`capitalize font-medium ${
                    dbHealth === `healthy` ? `text-green-500` : `text-yellow-500`
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
                    redisHealth === `healthy`
                      ? `text-green-500`
                      : `text-yellow-500`
                                    }`}
                                >
                                    {redisHealth}
                                </span>
                            </div>
                        )}
                    </div>

                    <div className="pt-2 border-t text-xs text-muted-foreground">
                        <p>
                            Uptime: {Math.floor(health.uptime_seconds / 3600)}h{` `}
                            {Math.floor((health.uptime_seconds % 3600) / 60)}m
                        </p>
                        <p>Last checked: {new Date(health.timestamp).toLocaleTimeString()}</p>
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
