import {
    useQuery, useMutation, useQueryClient
} from "@tanstack/react-query";
import { api } from "@/lib/api";

// Query Keys
export const queryKeys = {
    // User queries
    users:    [ `users` ] as const,
    user:     (id: string) => [
        `users`,
        id,
    ] as const,
    profile:  [ `profile` ] as const,
    sessions: [ `sessions` ] as const,
    apiKeys:  [ `apiKeys` ] as const,

    // Team queries
    teams:       [ `teams` ] as const,
    team:        (id: string) => [
        `teams`,
        id,
    ] as const,
    teamMembers: (teamId: string) => [
        `teams`,
        teamId,
        `members`,
    ] as const,

    // Settings queries
    settings: [ `settings` ] as const,
    setting:  (key: string) => [
        `settings`,
        key,
    ] as const,

    // Health queries
    health: [ `health` ] as const,

    // MFA queries
    mfaStatus: [ `mfaStatus` ] as const,

    // Notifications queries
    notifications: [ `notifications` ] as const,
};

// User Hooks
export function useUsers(params?: { page?: number
    per_page?:                             number
    search?:                               string }) {
    return useQuery({
        queryKey: [
            ...queryKeys.users,
            params,
        ],
        queryFn: async() => api.listUsers(params),
    });
}

export function useUser(id: string) {
    return useQuery({
        queryKey: queryKeys.user(id),
        queryFn:  async() => api.getUser(id),
        enabled:  Boolean(id),
    });
}

export function useCreateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(data: Parameters<typeof api.createUser>[0]) => api.createUser(data),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.users,
            });
        },
    });
}

export function useUpdateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            id, data,
        }: { id:  string
            data: Parameters<typeof api.updateUser>[1] }) => api.updateUser(id, data),
        onSuccess: (_, {
            id,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.users,
            });
            queryClient.invalidateQueries({
                queryKey: queryKeys.user(id),
            });
        },
    });
}

export function useDeleteUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(id: string) => api.deleteUser(id),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.users,
            });
        },
    });
}

export function useBulkDeleteUsers() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(ids: Array<string>) => Promise.all(ids.map(async(id) => api.deleteUser(id))),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.users,
            });
        },
    });
}

// Profile Hooks
export function useProfile() {
    return useQuery({
        queryKey: queryKeys.profile,
        queryFn:  async() => api.getProfile(),
    });
}

export function useUpdateProfile() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(data: Parameters<typeof api.updateProfile>[0]) => api.updateProfile(data),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.profile,
            });
        },
    });
}

export function useChangePassword() {
    return useMutation({
        mutationFn: async({
            currentPassword, newPassword,
        }: { currentPassword: string
            newPassword:      string }) => api.changePassword(currentPassword, newPassword),
    });
}

// Session Hooks
export function useSessions() {
    return useQuery({
        queryKey: queryKeys.sessions,
        queryFn:  async() => api.getSessions(),
    });
}

export function useDeleteSession() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(sessionId: string) => api.deleteSession(sessionId),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.sessions,
            });
        },
    });
}

export function useDeleteAllSessions() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async() => api.deleteAllSessions(),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.sessions,
            });
        },
    });
}

// API Key Hooks
export function useApiKeys() {
    return useQuery({
        queryKey: queryKeys.apiKeys,
        queryFn:  async() => api.getApiKeys(),
    });
}

export function useCreateApiKey() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(data: Parameters<typeof api.createApiKey>[0]) => api.createApiKey(data),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.apiKeys,
            });
        },
    });
}

export function useDeleteApiKey() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(id: string) => api.deleteApiKey(id),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.apiKeys,
            });
        },
    });
}

export function useRotateApiKey() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(id: string) => api.rotateApiKey(id),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.apiKeys,
            });
        },
    });
}

// Team Hooks
export function useTeams() {
    return useQuery({
        queryKey: queryKeys.teams,
        queryFn:  async() => api.getTeams(),
    });
}

export function useTeam(id: string) {
    return useQuery({
        queryKey: queryKeys.team(id),
        queryFn:  async() => api.getTeam(id),
        enabled:  Boolean(id),
    });
}

export function useTeamMembers(teamId: string) {
    return useQuery({
        queryKey: queryKeys.teamMembers(teamId),
        queryFn:  async() => api.getTeamMembers(teamId),
        enabled:  Boolean(teamId),
    });
}

export function useCreateTeam() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(data: Parameters<typeof api.createTeam>[0]) => api.createTeam(data),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teams,
            });
        },
    });
}

export function useUpdateTeam() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            id, data,
        }: { id:  string
            data: Parameters<typeof api.updateTeam>[1] }) => api.updateTeam(id, data),
        onSuccess: (_, {
            id,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teams,
            });
            queryClient.invalidateQueries({
                queryKey: queryKeys.team(id),
            });
        },
    });
}

export function useDeleteTeam() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(id: string) => api.deleteTeam(id),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teams,
            });
        },
    });
}

export function useAddTeamMember() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            teamId, data,
        }: { teamId: string
            data:    Parameters<typeof api.addTeamMember>[1] }) => api.addTeamMember(teamId, data),
        onSuccess: (_, {
            teamId,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teamMembers(teamId),
            });
        },
    });
}

export function useUpdateTeamMember() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            teamId, memberId, data,
        }: {
            teamId:   string
            memberId: string
            data:     Parameters<typeof api.updateTeamMember>[2]
        }) => api.updateTeamMember(teamId, memberId, data),
        onSuccess: (_, {
            teamId,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teamMembers(teamId),
            });
        },
    });
}

export function useRemoveTeamMember() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            teamId, memberId,
        }: { teamId:  string
            memberId: string }) => api.removeTeamMember(teamId, memberId),
        onSuccess: (_, {
            teamId,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.teamMembers(teamId),
            });
        },
    });
}

// Settings Hooks
export function useSettings() {
    return useQuery({
        queryKey: queryKeys.settings,
        queryFn:  async() => api.getSettings(),
    });
}

export function useSetting(key: string) {
    return useQuery({
        queryKey: queryKeys.setting(key),
        queryFn:  async() => api.getSetting(key),
        enabled:  Boolean(key),
    });
}

export function useUpdateSetting() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async({
            key, value,
        }: { key:  string
            value: string }) => api.updateSetting(key, value),
        onSuccess: (_, {
            key,
        }) => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.settings,
            });
            queryClient.invalidateQueries({
                queryKey: queryKeys.setting(key),
            });
        },
    });
}

// Health Hooks
export function useHealth() {
    return useQuery({
        queryKey:        queryKeys.health,
        queryFn:         async() => api.healthCheck(),
        refetchInterval: 30000, // Refetch every 30 seconds
    });
}

// MFA Hooks
export function useMfaStatus() {
    return useQuery({
        queryKey: queryKeys.mfaStatus,
        queryFn:  async() => api.getMfaStatus(),
    });
}

export function useEnableMfa() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(password: string) => api.enableMfa(password),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.mfaStatus,
            });
        },
    });
}

export function useVerifyMfaSetup() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(code: string) => api.verifyMfaSetup(code),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.mfaStatus,
            });
        },
    });
}

export function useDisableMfa() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(password: string) => api.disableMfa(password),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.mfaStatus,
            });
        },
    });
}

export function useRegenerateBackupCodes() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async(password: string) => api.regenerateBackupCodes(password),
        onSuccess:  () => {
            queryClient.invalidateQueries({
                queryKey: queryKeys.mfaStatus,
            });
        },
    });
}

// User search hook for autocomplete
export function useSearchUsers(search: string, enabled = true) {
    return useQuery({
        queryKey: [
            ...queryKeys.users,
            {
                search,
            },
        ],
        queryFn: async() => api.listUsers({
            search,
            per_page: 20,
        }),
        enabled:  enabled && search.length >= 2,
    });
}

// Notifications Hooks
export function useNotifications(params?: { page?: number
    per_page?:                          number
    unread_only?:                       boolean }) {
    return useQuery({
        queryKey: [
            ...queryKeys.notifications,
            params,
        ],
        queryFn: async() => api.getNotifications(params),
    });
}
