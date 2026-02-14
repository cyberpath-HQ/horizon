import { createFileRoute } from "@tanstack/react-router";
import { motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { Home, Search, Sparkles, Compass, MapPin } from "lucide-react";
import { getAccessToken } from "@/lib/api";

export const Route = createFileRoute("/404")({
    component: NotFoundPage,
});

export default function NotFoundPage() {
    const isAuthenticated = !!getAccessToken();

    return (
        <div className="min-h-screen flex items-center justify-center relative overflow-hidden bg-background">
            {/* Animated Background */}
            <div className="fixed inset-0 overflow-hidden pointer-events-none">
                <motion.div
                    className="absolute -top-40 -right-40 w-[600px] h-[600px] bg-gradient-to-br from-primary/20 via-primary/10 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.3, 1],
                        x: [0, 50, 0],
                        y: [0, -30, 0],
                        opacity: [0.4, 0.7, 0.4],
                    }}
                    transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                />
                <motion.div
                    className="absolute -bottom-40 -left-40 w-[500px] h-[500px] bg-gradient-to-tr from-violet-500/15 via-purple-500/10 to-transparent rounded-full blur-3xl"
                    animate={{
                        scale: [1, 1.4, 1],
                        x: [0, -40, 0],
                        y: [0, 40, 0],
                        opacity: [0.3, 0.6, 0.3],
                    }}
                    transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 2 }}
                />
                {/* Floating Elements */}
                {[...Array(6)].map((_, i) => (
                    <motion.div
                        key={i}
                        className="absolute w-2 h-2 bg-primary/30 rounded-full"
                        initial={{
                            x: Math.random() * window.innerWidth,
                            y: Math.random() * window.innerHeight,
                        }}
                        animate={{
                            y: [null, Math.random() * -100, null],
                            opacity: [0.2, 0.5, 0.2],
                        }}
                        transition={{
                            duration: 3 + Math.random() * 2,
                            repeat: Infinity,
                            delay: Math.random() * 2,
                        }}
                    />
                ))}
            </div>

            <div className="relative z-10 text-center px-4 max-w-lg">
                <motion.div
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    transition={{ delay: 0.2, type: "spring", stiffness: 200, damping: 15 }}
                >
                    <div className="relative inline-block mb-8">
                        <motion.div
                            className="w-32 h-32 mx-auto"
                            animate={{
                                y: [0, -10, 0],
                            }}
                            transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                        >
                            <Compass className="w-full h-full text-primary opacity-80" strokeWidth={1} />
                        </motion.div>
                        <motion.div
                            className="absolute -top-2 -right-2"
                            animate={{ rotate: 360 }}
                            transition={{ duration: 10, repeat: Infinity, ease: "linear" }}
                        >
                            <Sparkles className="w-8 h-8 text-amber-500" />
                        </motion.div>
                    </div>
                </motion.div>

                <motion.h1
                    className="text-8xl font-bold bg-gradient-to-r from-primary via-purple-500 to-primary bg-clip-text text-transparent mb-4"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                >
                    404
                </motion.h1>

                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.4 }}
                >
                    <h2 className="text-2xl font-semibold mb-3">
                        You've drifted off course
                    </h2>
                </motion.div>

                <motion.p
                    className="text-muted-foreground text-lg mb-8"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 }}
                >
                    The page you're looking for doesn't exist in this universe.
                    Let's get you back on track.
                </motion.p>

                <motion.div
                    className="flex flex-col sm:flex-row gap-4 justify-center"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 }}
                >
                    <motion.div
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Button
                            size="lg"
                            onClick={() => window.history.back()}
                            variant="outline"
                            className="gap-2"
                        >
                            <MapPin className="w-4 h-4" />
                            Go Back
                        </Button>
                    </motion.div>
                    <motion.div
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                    >
                        <Button
                            size="lg"
                            onClick={() => window.location.href = isAuthenticated ? "/dashboard" : "/login"}
                            className="gap-2"
                        >
                            <Home className="w-4 h-4" />
                            {isAuthenticated ? "Go to Dashboard" : "Go to Login"}
                        </Button>
                    </motion.div>
                </motion.div>

                <motion.div
                    className="mt-12 p-6 rounded-xl bg-muted/50 border"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.8 }}
                >
                    <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground mb-2">
                        <Search className="w-4 h-4" />
                        <span>Looking for something specific?</span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                        Try using the search bar or navigating through the sidebar menu.
                    </p>
                </motion.div>
            </div>
        </div>
    );
}
