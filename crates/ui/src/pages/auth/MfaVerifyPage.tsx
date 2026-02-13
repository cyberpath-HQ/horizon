import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import { Loader2, Shield, KeyRound, RotateCcw } from "lucide-react";

export default function MfaVerifyPage() {
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isBackupMode, setIsBackupMode] = useState(false);
  const [attempts, setAttempts] = useState(0);
  
  const { verifyMfa, verifyMfaBackupCode } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (code.length !== 6 && !isBackupMode) {
      setError("Please enter a 6-digit code");
      return;
    }

    setIsLoading(true);

    try {
      const response = isBackupMode 
        ? await verifyMfaBackupCode(code)
        : await verifyMfa(code);
      
      if (response.success) {
        navigate("/");
      } else {
        setAttempts((prev) => prev + 1);
        setError("Invalid code. Please try again.");
      }
    } catch (err) {
      setAttempts((prev) => prev + 1);
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Verification failed. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const toggleMode = () => {
    setIsBackupMode(!isBackupMode);
    setCode("");
    setError("");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4 relative overflow-hidden auth-gradient">
      {/* Amber glow decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-secondary/10 rounded-full blur-3xl" />
      </div>

      <Card className="w-full max-w-md relative z-10 border-border/50 shadow-xl">
        <CardHeader className="space-y-4 text-center pb-2">
          <div className="mx-auto w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center">
            <Shield className="w-7 h-7 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl font-semibold tracking-tight">
              Two-Factor Authentication
            </CardTitle>
            <CardDescription className="mt-2">
              {isBackupMode 
                ? "Enter one of your backup codes" 
                : "Enter the 6-digit code from your authenticator app"
              }
            </CardDescription>
          </div>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4 pt-4">
            {error && (
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
                {error}
                {attempts > 2 && (
                  <button
                    type="button"
                    onClick={toggleMode}
                    className="block mt-2 text-sm underline hover:text-destructive/80"
                  >
                    Try using a backup code instead
                  </button>
                )}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="code">
                {isBackupMode ? "Backup Code" : "Authentication Code"}
              </Label>
              <Input
                id="code"
                type="text"
                inputMode={isBackupMode ? "text" : "numeric"}
                placeholder={isBackupMode ? "XXXX-XXXX" : "000000"}
                value={code}
                onChange={(e) => setCode(isBackupMode ? e.target.value : e.target.value.replace(/\D/g, "").slice(0, 6))}
                required
                autoComplete={isBackupMode ? "off" : "one-time-code"}
                className="h-12 text-center text-lg tracking-widest font-mono"
                maxLength={isBackupMode ? 9 : 6}
              />
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-4 pt-2">
            <Button 
              type="submit" 
              className="w-full h-10" 
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  <KeyRound className="w-4 h-4" />
                  Verify
                </>
              )}
            </Button>
            
            <div className="flex items-center justify-center gap-2 text-sm">
              <button
                type="button"
                onClick={toggleMode}
                className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors"
              >
                <RotateCcw className="w-3 h-3" />
                {isBackupMode ? "Use authenticator code" : "Use backup code"}
              </button>
            </div>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
