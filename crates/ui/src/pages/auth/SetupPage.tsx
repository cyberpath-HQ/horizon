import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { checkSystemSetup, ApiError } from "@/lib/api";
import { Leaf, Loader2, ShieldCheck } from "lucide-react";

export default function SetupPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isChecking, setIsChecking] = useState(true);
  
  const { setup } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Check if system is already set up
    checkSystemSetup().then((isSetup) => {
      setIsChecking(false);
      if (!isSetup) {
        // System is already set up, redirect to login
        navigate("/login");
      }
    });
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (password.length < 12) {
      setError("Password must be at least 12 characters");
      return;
    }

    setIsLoading(true);

    try {
      const response = await setup(email, password, displayName);
      
      if (response.success) {
        navigate("/");
      } else {
        setError("Setup failed. Please try again.");
      }
    } catch (err) {
      if (err instanceof ApiError) {
        // Provide more helpful messages based on error type
        let displayMessage = err.message;
        
        if (err.code === "VALIDATION_ERROR") {
          // Parse validation errors to be more readable
          if (err.message.includes("email")) {
            displayMessage = "Please enter a valid email address";
          } else if (err.message.includes("password")) {
            displayMessage = "Password must be 12-256 characters";
          } else if (err.message.includes("display_name")) {
            displayMessage = "Display name is required (1-255 characters)";
          } else {
            displayMessage = `Please check your input: ${err.message}`;
          }
        } else if (err.code === "CONFLICT") {
          displayMessage = "System is already configured. Please use the login page.";
        }
        
        setError(displayMessage);
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setIsLoading(false);
    }
  };

  if (isChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex items-center gap-2">
          <Loader2 className="h-6 w-6 animate-spin text-primary" />
          <span className="text-muted-foreground">Checking configuration...</span>
        </div>
      </div>
    );
  }

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
            <ShieldCheck className="w-7 h-7 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl font-semibold tracking-tight">
              Initialize Horizon
            </CardTitle>
            <CardDescription className="mt-2">
              Create your administrator account to get started
            </CardDescription>
          </div>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4 pt-4">
            {error && (
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
                {error}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="displayName">Full Name</Label>
              <Input
                id="displayName"
                type="text"
                placeholder="John Doe"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                required
                autoComplete="name"
                className="h-10"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="admin@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="h-10"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="new-password"
                placeholder="Min. 12 characters"
                className="h-10"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                className="h-10"
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
                  Creating account...
                </>
              ) : (
                <>
                  <Leaf className="w-4 h-4" />
                  Create Account
                </>
              )}
            </Button>
            <p className="text-xs text-center text-muted-foreground">
              Choose a strong password with at least 12 characters
            </p>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}
