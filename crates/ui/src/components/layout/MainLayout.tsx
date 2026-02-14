import { useState } from "react";
import { Outlet, useNavigate } from "@tanstack/react-router";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/hooks/useTheme";
import { Sidebar } from "./Sidebar";
import { HealthStatusIndicator } from "@/components/health/HealthStatusIndicator";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Menu,
  Search,
  Bell,
  BellDot,
  LogOut,
  User,
  Settings,
  Moon,
  Sun,
} from "lucide-react";
import { useNotifications } from "@/hooks/useApi";
import { motion, AnimatePresence } from "motion/react";

export function MainLayout() {
  const { user, logout } = useAuth();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  
  const { data: notificationsData } = useNotifications();
  const hasUnreadNotifications = (notificationsData?.items?.length ?? 0) > 0;

  const handleLogout = async () => {
    await logout();
    navigate({ to: "/login" });
  };

  const cycleTheme = () => {
    setTheme(theme === "light" ? "dark" : "light");
  };

  return (
    <div className="flex h-screen bg-background relative overflow-hidden">
      {/* PROMINENT Animated Background - z-index negative to not block interactions */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none -z-20">
        {/* Large slow-moving gradient orbs */}
        <motion.div 
          className="absolute -top-1/3 -right-1/4 w-[800px] h-[800px] bg-gradient-to-br from-amber-400/15 via-orange-500/10 to-transparent rounded-full blur-3xl"
          animate={{
            scale: [1, 1.4, 1.2, 1],
            x: [0, 80, 40, 0],
            y: [0, -50, -30, 0],
            opacity: [0.5, 0.8, 0.6, 0.5],
          }}
          transition={{ duration: 12, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div 
          className="absolute -bottom-1/3 -left-1/4 w-[700px] h-[700px] bg-gradient-to-tr from-violet-500/12 via-purple-500/8 to-transparent rounded-full blur-3xl"
          animate={{
            scale: [1, 1.5, 1.3, 1],
            x: [0, -60, -30, 0],
            y: [0, 60, 40, 0],
            opacity: [0.4, 0.7, 0.5, 0.4],
          }}
          transition={{ duration: 15, repeat: Infinity, ease: "easeInOut", delay: 3 }}
        />
        <motion.div 
          className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-gradient-to-r from-blue-500/8 via-cyan-500/5 to-transparent rounded-full blur-3xl"
          animate={{
            scale: [1, 1.3, 1.1, 1],
            x: [0, 100, 50, 0],
            opacity: [0.3, 0.5, 0.4, 0.3],
          }}
          transition={{ duration: 18, repeat: Infinity, ease: "easeInOut", delay: 5 }}
        />
        
        {/* Animated mesh/grain pattern */}
        <motion.div 
          className="absolute inset-0 opacity-[0.03]"
          animate={{
            backgroundPosition: ["0% 0%", "100% 100%"],
          }}
          transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
          style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
          }}
        />
      </div>

      {/* Sidebar - Desktop */}
      <div className="hidden md:flex relative z-50">
        <Sidebar />
      </div>

      {/* Mobile Sidebar Overlay */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div 
            className="fixed inset-0 z-50 md:hidden"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <motion.div 
              className="fixed inset-0 bg-background/90 backdrop-blur-sm"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
            />
            <motion.div 
              className="fixed inset-y-0 left-0 z-50 w-72"
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
            >
              <Sidebar />
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 relative z-10">
        {/* Header */}
        <motion.header 
          className="h-16 border-b bg-card/80 backdrop-blur-md sticky top-0 z-40"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <div className="h-full px-4 flex items-center justify-between gap-4">
            {/* Mobile Menu Button */}
            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
              <Button
                variant="ghost"
                size="icon"
                className="md:hidden"
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              >
                <Menu className="w-5 h-5" />
              </Button>
            </motion.div>

            {/* Search */}
            <div className="flex-1 max-w-md">
              <motion.div 
                className="relative"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.2 }}
              >
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search assets, software..."
                  className="w-full h-10 pl-10 pr-4 rounded-xl bg-background/80 border border-input text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:bg-background transition-all"
                />
              </motion.div>
            </div>

            {/* Right Side Actions */}
            <div className="flex items-center gap-2">
              {/* Health Status */}
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <HealthStatusIndicator />
              </motion.div>

              {/* Theme Toggle */}
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button variant="ghost" size="icon" onClick={cycleTheme} className="hidden sm:flex" title={`Current: ${theme}`}>
                  <motion.div
                    animate={{ rotate: theme === "dark" ? 180 : 0, scale: theme === "dark" ? 0 : 1 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Sun className="w-4 h-4" />
                  </motion.div>
                  <motion.div
                    animate={{ rotate: theme === "light" ? -180 : 0, scale: theme === "light" ? 0 : 1 }}
                    transition={{ duration: 0.3 }}
                    className="absolute"
                  >
                    <Moon className="w-4 h-4" />
                  </motion.div>
                  <span className="sr-only">Toggle theme</span>
                </Button>
              </motion.div>

              {/* Notifications */}
              <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Button variant="ghost" size="icon" className="relative" onClick={() => navigate({ to: "/dashboard/settings/notifications" })}>
                  <AnimatePresence mode="wait">
                    {hasUnreadNotifications ? (
                      <motion.div
                        key="bell-dot"
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        exit={{ scale: 0 }}
                      >
                        <BellDot className="w-5 h-5 text-amber-500" />
                      </motion.div>
                    ) : (
                      <motion.div
                        key="bell"
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        exit={{ scale: 0 }}
                      >
                        <Bell className="w-5 h-5" />
                      </motion.div>
                    )}
                  </AnimatePresence>
                  {hasUnreadNotifications && (
                    <motion.span 
                      className="absolute top-1 right-1 w-2.5 h-2.5 bg-amber-500 rounded-full"
                      animate={{ scale: [1, 1.2, 1] }}
                      transition={{ duration: 1, repeat: Infinity }}
                    />
                  )}
                </Button>
              </motion.div>

              {/* User Menu */}
              <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" className="gap-2 h-10 px-2">
                      <motion.div 
                        className="w-8 h-8 rounded-full bg-gradient-to-br from-amber-400 to-orange-500 flex items-center justify-center"
                        whileHover={{ rotate: 5, scale: 1.05 }}
                      >
                        <span className="text-sm font-medium text-white">
                          {user?.displayName?.charAt(0).toUpperCase() || "U"}
                        </span>
                      </motion.div>
                      <span className="hidden sm:inline text-sm font-medium">
                        {user?.displayName || "User"}
                      </span>
                    </Button>
                  </DropdownMenuTrigger>
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                  >
                    <DropdownMenuContent align="end" className="w-56">
                      <DropdownMenuLabel className="font-normal">
                        <div className="flex flex-col space-y-1">
                          <p className="text-sm font-medium">{user?.displayName}</p>
                          <p className="text-xs text-muted-foreground">{user?.email}</p>
                        </div>
                      </DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => navigate({ to: "/dashboard/profile", search: { tab: "profile" } })}>
                        <User className="mr-2 w-4 h-4" />
                        Profile
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => navigate({ to: "/dashboard/settings", search: { tab: "modules" } })}>
                        <Settings className="mr-2 w-4 h-4" />
                        Settings
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                        <LogOut className="mr-2 w-4 h-4" />
                        Log out
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </motion.div>
                </DropdownMenu>
              </motion.div>
            </div>
          </div>
        </motion.header>

        {/* Page Content */}
        <main className="flex-1 overflow-auto">
          <div className="container mx-auto p-6 max-w-7xl">
            <AnimatePresence mode="wait">
              <motion.div
                key={window.location.pathname}
                initial={{ opacity: 0, y: 10, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -10, scale: 0.98 }}
                transition={{ duration: 0.25, ease: "easeOut" }}
              >
                <Outlet />
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>
    </div>
  );
}
