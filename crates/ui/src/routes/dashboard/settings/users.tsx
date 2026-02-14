import { useState, useEffect } from "react";
import { useForm } from "@tanstack/react-form";
import { createFileRoute, redirect } from "@tanstack/react-router";
import { getAccessToken, getStoredUser } from "@/lib/api";
import {
    useUsers,
    useCreateUser,
    useUpdateUser,
    useDeleteUser,
    useBulkDeleteUsers,
} from "@/hooks/useApi";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/dashboard/settings/users")({
    beforeLoad: () => {
        // Check if user is authenticated
        const token = getAccessToken();
        const user = getStoredUser();
        
        if (!token || !user) {
            throw redirect({
                to: '/login',
                replace: true,
            });
        }
    },
    component: UsersPage,
});
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow
} from "@/components/ui/table";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue
} from "@/components/ui/select";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import {
    Avatar, AvatarFallback
} from "@/components/ui/avatar";
import {
    Pagination,
    PaginationContent,
    PaginationEllipsis,
    PaginationItem,
    PaginationLink,
    PaginationNext,
    PaginationPrevious
} from "@/components/ui/pagination";
import {
    Alert,
    AlertDescription,
    AlertTitle
} from "@/components/ui/alert";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import {
    Loader2, UserPlus, Users, AlertCircle, CheckCircle, MoreHorizontal, Trash2, RefreshCw, Search
} from "lucide-react";

// User type
interface User {
    id: string
    email: string
    first_name?: string
    last_name?: string
    role: string
    created_at: string
}

interface CreateUserFormValues {
    email: string
    password: string
    first_name: string
    last_name: string
    role: string
}

function CreateUserForm({
    onSuccess,
    onCancel,
}: {
    onSuccess: () => void;
    onCancel: () => void;
}) {
    const createUser = useCreateUser();

    const form = useForm<CreateUserFormValues>({
        defaultValues: {
            email: "",
            password: "",
            first_name: "",
            last_name: "",
            role: "viewer",
        },
        onSubmit: async ({ value }) => {
            try {
                await createUser.mutateAsync({
                    email: value.email,
                    password: value.password,
                    first_name: value.first_name,
                    last_name: value.last_name,
                    role: value.role || "viewer",
                });
                onSuccess();
            } catch (err: unknown) {
                const error = err as { message?: string };
                throw new Error(error.message || "Failed to create user");
            }
        },
    });

    return (
        <form
            onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
            }}
        >
            <div className="grid grid-cols-2 gap-4">
                <form.Field
                    name="first_name"
                    children={(field) => (
                        <div className="space-y-2">
                            <Label htmlFor={field.name}>First Name</Label>
                            <Input
                                id={field.name}
                                placeholder="John"
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                            />
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </div>
                    )}
                />
                <form.Field
                    name="last_name"
                    children={(field) => (
                        <div className="space-y-2">
                            <Label htmlFor={field.name}>Last Name</Label>
                            <Input
                                id={field.name}
                                placeholder="Doe"
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                            />
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </div>
                    )}
                />
            </div>
            <div className="space-y-2 mt-4">
                <form.Field
                    name="email"
                    children={(field) => (
                        <>
                            <Label htmlFor={field.name}>Email</Label>
                            <Input
                                id={field.name}
                                type="email"
                                placeholder="john.doe@example.com"
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                                required
                            />
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </>
                    )}
                />
            </div>
            <div className="space-y-2 mt-4">
                <form.Field
                    name="password"
                    children={(field) => (
                        <>
                            <Label htmlFor={field.name}>Password</Label>
                            <Input
                                id={field.name}
                                type="password"
                                placeholder="••••••••"
                                value={field.state.value}
                                onChange={(e) => field.handleChange(e.target.value)}
                                onBlur={field.handleBlur}
                                required
                            />
                            <p className="text-xs text-muted-foreground">
                                Must be at least 8 characters
                            </p>
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </>
                    )}
                />
            </div>
            <div className="space-y-2 mt-4">
                <form.Field
                    name="role"
                    children={(field) => (
                        <>
                            <Label>Role</Label>
                            <Select
                                value={field.state.value}
                                onValueChange={field.handleChange}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Select role" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="viewer">Viewer</SelectItem>
                                    <SelectItem value="manager">Manager</SelectItem>
                                    <SelectItem value="admin">Admin</SelectItem>
                                    <SelectItem value="super_admin">Super Admin</SelectItem>
                                </SelectContent>
                            </Select>
                            {field.state.meta.errors ? (
                                <p className="text-sm text-destructive">{field.state.meta.errors.join(", ")}</p>
                            ) : null}
                        </>
                    )}
                />
            </div>
            <DialogFooter className="mt-6">
                <Button type="button" variant="outline" onClick={onCancel}>
                    Cancel
                </Button>
                <Button type="submit" disabled={form.state.isSubmitting}>
                    {form.state.isSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Create User
                </Button>
            </DialogFooter>
        </form>
    );
}

export default function UsersPage() {
    // State
    const [page, setPage] = useState(1);
    const [search, setSearch] = useState("");
    const [debouncedSearch, setDebouncedSearch] = useState("");
    const [sortBy, setSortBy] = useState<"created_at" | "email" | "first_name">("created_at");
    const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
    const [selectedUsers, setSelectedUsers] = useState<Set<string>>(new Set());

    // Dialog state
    const [isCreateOpen, setIsCreateOpen] = useState(false);

    // Alert state
    const [alert, setAlert] = useState<{ type: `success` | `error`
        title:           string
        message:         string } | null>(null);

    // Mutations
    const updateUser = useUpdateUser();
    const deleteUser = useDeleteUser();
    const bulkDeleteUsers = useBulkDeleteUsers();

    // Debounce search
    useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedSearch(search);
        }, 300);
        return () => clearTimeout(timer);
    }, [search]);

    // Query
    const { data, isLoading, refetch } = useUsers({
        page,
        per_page: 10,
        search: debouncedSearch || undefined,
    });

    const users: User[] = data?.items || [];
    const pagination = data?.pagination;

    // Alert auto-dismiss
    useEffect(() => {
        if (alert) {
            const timer = setTimeout(() => setAlert(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [alert]);

    // Handlers
    const handleSearch = (value: string) => {
        setSearch(value);
        setPage(1); // Reset to first page on search
    };

    const handleSort = (column: typeof sortBy) => {
        if (sortBy === column) {
            setSortOrder(sortOrder === "asc" ? "desc" : "asc");
        } else {
            setSortBy(column);
            setSortOrder("asc");
        }
    };

    const handleSelectAll = () => {
        if (selectedUsers.size === users.length) {
            setSelectedUsers(new Set());
        } else {
            setSelectedUsers(new Set(users.map(u => u.id)));
        }
    };

    const handleSelectUser = (userId: string) => {
        const newSelected = new Set(selectedUsers);
        if (newSelected.has(userId)) {
            newSelected.delete(userId);
        } else {
            newSelected.add(userId);
        }
        setSelectedUsers(newSelected);
    };

    const handleCreateSuccess = () => {
        setIsCreateOpen(false);
        setAlert({
            type:    `success`,
            title:   `Success`,
            message: `User created successfully`,
        });
    };

    const handleUpdateUserRole = async(userId: string, newRole: string) => {
        try {
            await updateUser.mutateAsync({
                id:   userId,
                data: { role: newRole },
            });

            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `User role updated successfully`,
            });
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: error.message || `Failed to update user role`,
            });
        }
    };

    const handleDeleteUser = async(userId: string) => {
        if (!confirm(`Are you sure you want to delete this user? This action cannot be undone.`)) {
            return;
        }

        try {
            await deleteUser.mutateAsync(userId);

            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `User deleted successfully`,
            });

            // Clear selection if deleted user was selected
            const newSelected = new Set(selectedUsers);
            newSelected.delete(userId);
            setSelectedUsers(newSelected);
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: error.message || `Failed to delete user`,
            });
        }
    };

    const handleBulkDelete = async() => {
        if (!confirm(`Are you sure you want to delete ${ selectedUsers.size } users? This action cannot be undone.`)) {
            return;
        }

        try {
            await bulkDeleteUsers.mutateAsync(Array.from(selectedUsers));

            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `${ selectedUsers.size } users deleted successfully`,
            });

            setSelectedUsers(new Set());
        }
        catch (err: unknown) {
            const error = err as { message?: string };
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: error.message || `Failed to delete users`,
            });
        }
    };

    const getInitials = (email: string, firstName?: string, lastName?: string) => {
        if (firstName || lastName) {
            return `${ firstName?.[0] || `` }${ lastName?.[0] || `` }`.toUpperCase();
        }
        return email?.[0]?.toUpperCase() || `?`;
    };

    const getPageNumbers = () => {
        if (!pagination) {
            return [];
        }
        const total = pagination.total_pages;
        const current = page;
        const pages: Array<number | `ellipsis`> = [];

        if (total <= 7) {
            for (let i = 1; i <= total; i++) {
                pages.push(i);
            }
        }
        else {
            pages.push(1);
            if (current > 3) {
                pages.push(`ellipsis`);
            }
            for (let i = Math.max(2, current - 1); i <= Math.min(total - 1, current + 1); i++) {
                pages.push(i);
            }
            if (current < total - 2) {
                pages.push(`ellipsis`);
            }
            pages.push(total);
        }
        return pages;
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Users</h1>
                    <p className="text-muted-foreground mt-1">
                        Manage system users and their permissions
                    </p>
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-2">
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </Button>
                    <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
                        <DialogTrigger asChild>
                            <Button className="gap-2">
                                <UserPlus className="w-4 h-4" />
                                Add User
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-[500px]">
                            <DialogHeader>
                                <DialogTitle>Create New User</DialogTitle>
                                <DialogDescription>
                                    Add a new user to the system. They will receive login credentials.
                                </DialogDescription>
                            </DialogHeader>
                            <CreateUserForm
                                onSuccess={handleCreateSuccess}
                                onCancel={() => setIsCreateOpen(false)}
                            />
                        </DialogContent>
                    </Dialog>
                </div>
            </div>

            {alert && (
                <Alert variant={alert.type === `error` ? `destructive` : `default`} className={alert.type === `success` ? `border-green-500 bg-green-50` : ``}>
                    {alert.type === `success` ? <CheckCircle className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
                    <AlertTitle>{alert.title}</AlertTitle>
                    <AlertDescription>{alert.message}</AlertDescription>
                </Alert>
            )}

            <Card>
                <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle className="text-lg">All Users</CardTitle>
                            <CardDescription>
                                {pagination?.total || 0} total users
                                {selectedUsers.size > 0 && ` • ${ selectedUsers.size } selected`}
                            </CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                            {selectedUsers.size > 0 && (
                                <Button
                                    variant="destructive"
                                    size="sm"
                                    onClick={handleBulkDelete}
                                    disabled={bulkDeleteUsers.isPending}
                                >
                                    <Trash2 className="w-4 h-4 mr-2" />
                                    Delete Selected ({selectedUsers.size})
                                </Button>
                            )}
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                                <Input
                                    placeholder="Search users..."
                                    value={search}
                                    onChange={(e) => handleSearch(e.target.value)}
                                    className="pl-9 w-[250px]"
                                />
                            </div>
                            <Users className="h-5 w-5 text-muted-foreground" />
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    {isLoading
? (
            <div className="flex justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )
: users.length === 0
? (
            <div className="text-center py-12">
                <Users className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <p className="text-muted-foreground">No users found</p>
                <Button variant="outline" className="mt-4" onClick={() => setIsCreateOpen(true)}>
                    Create the first user
                </Button>
            </div>
          )
: (
            <>
                <Table>
                    <TableHeader>
                        <TableRow>
                            <TableHead className="w-12">
                                <input
                                    type="checkbox"
                                    checked={selectedUsers.size === users.length && users.length > 0}
                                    onChange={handleSelectAll}
                                    className="h-4 w-4 rounded border-gray-300"
                                />
                            </TableHead>
                            <TableHead>User</TableHead>
                            <TableHead>Email</TableHead>
                            <TableHead
                                className="cursor-pointer hover:text-foreground"
                                onClick={() => handleSort("email")}
                            >
                                Email {sortBy === "email" && (sortOrder === "asc" ? "↑" : "↓")}
                            </TableHead>
                            <TableHead>Role</TableHead>
                            <TableHead
                                className="cursor-pointer hover:text-foreground"
                                onClick={() => handleSort("created_at")}
                            >
                                Created {sortBy === "created_at" && (sortOrder === "asc" ? "↑" : "↓")}
                            </TableHead>
                            <TableHead className="max-w-5"></TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {users.map((user) => (
                            <TableRow key={user.id}>
                                <TableCell>
                                    <input
                                        type="checkbox"
                                        checked={selectedUsers.has(user.id)}
                                        onChange={() => handleSelectUser(user.id)}
                                        className="h-4 w-4 rounded border-gray-300"
                                    />
                                </TableCell>
                                <TableCell className="flex items-center gap-3">
                                    <Avatar className="h-8 w-8">
                                        <AvatarFallback className="text-xs">
                                            {getInitials(user.email, user.first_name, user.last_name)}
                                        </AvatarFallback>
                                    </Avatar>
                                    <span className="font-medium">
                                        {[
                                            user.first_name,
                                            user.last_name,
                                        ].filter(Boolean).join(` `) || `—`}
                                    </span>
                                </TableCell>
                                <TableCell className="text-muted-foreground">
                                    {user.email}
                                </TableCell>
                                <TableCell>
                                    <Badge variant={user.role === `admin` ? `default` : user.role === `super_admin` ? `destructive` : `secondary`}>
                                        {user.role || `user`}
                                    </Badge>
                                </TableCell>
                                <TableCell className="text-muted-foreground text-sm">
                                    {user.created_at ? new Date(user.created_at).toLocaleDateString() : `—`}
                                </TableCell>
                                <TableCell className="text-right max-w-5">
                                    <DropdownMenu>
                                        <DropdownMenuTrigger>
                                            <Button variant="ghost" className="size-8 px-2">
                                                <MoreHorizontal className="h-4 w-4" />
                                            </Button>
                                        </DropdownMenuTrigger>
                                        <DropdownMenuContent align="end" className="max-w-[240px]">
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `user`)} disabled={updateUser.isPending}>
                                                Set as User
                                            </DropdownMenuItem>
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `admin`)} disabled={updateUser.isPending}>
                                                Set as Admin
                                            </DropdownMenuItem>
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `super_admin`)} disabled={updateUser.isPending}>
                                                Set as Super Admin
                                            </DropdownMenuItem>
                                            <DropdownMenuSeparator />
                                            <DropdownMenuItem onClick={async() => handleDeleteUser(user.id)} disabled={deleteUser.isPending} className="text-destructive focus:text-destructive">
                                                <Trash2 className="h-4 w-4 mr-2" />
                                                Delete User
                                            </DropdownMenuItem>
                                        </DropdownMenuContent>
                                    </DropdownMenu>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>

                {pagination && pagination.total_pages > 1 && (
                    <div className="mt-4">
                        <Pagination>
                            <PaginationContent>
                                <PaginationItem>
                                    <PaginationPrevious
                                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                                        className={page <= 1 ? `pointer-events-none opacity-50` : `cursor-pointer`}
                                    />
                                </PaginationItem>
                                {getPageNumbers().map((p, i) => (
                        p === `ellipsis`
? (
                                  <PaginationItem key={`ellipsis-${ i }`}>
                                      <PaginationEllipsis />
                                  </PaginationItem>
                        )
: (
                                  <PaginationItem key={p}>
                                      <PaginationLink
                                          onClick={() => setPage(p)}
                                          isActive={page === p}
                                      >
                                          {p}
                                      </PaginationLink>
                                  </PaginationItem>
                        )
                                ))}
                                <PaginationItem>
                                    <PaginationNext
                                        onClick={() => setPage((p) => Math.min(pagination.total_pages, p + 1))}
                                        className={page >= pagination.total_pages ? `pointer-events-none opacity-50` : `cursor-pointer`}
                                    />
                                </PaginationItem>
                            </PaginationContent>
                        </Pagination>
                    </div>
                )}
            </>
          )}
                </CardContent>
            </Card>
        </div>
    );
}
