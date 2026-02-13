import {
    useState, useEffect
} from "react";
import { api } from "@/lib/api";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
    Loader2, UserPlus, Users, AlertCircle, CheckCircle, MoreHorizontal, Trash2
} from "lucide-react";

export default function UsersPage() {
    const [
        users,
        setUsers,
    ] = useState<Array<any>>([]);
    const [
        loading,
        setLoading,
    ] = useState(true);
    const [
        saving,
        setSaving,
    ] = useState(false);
    const [
        pagination,
        setPagination,
    ] = useState<any>(null);
    const [
        page,
        setPage,
    ] = useState(1);

    const [
        isCreateOpen,
        setIsCreateOpen,
    ] = useState(false);
    const [
        newEmail,
        setNewEmail,
    ] = useState(``);
    const [
        newPassword,
        setNewPassword,
    ] = useState(``);
    const [
        newFirstName,
        setNewFirstName,
    ] = useState(``);
    const [
        newLastName,
        setNewLastName,
    ] = useState(``);
    const [
        newRole,
        setNewRole,
    ] = useState(`viewer`);
    const [
        alert,
        setAlert,
    ] = useState<{ type: `success` | `error`
        title:           string
        message:         string } | null>(null);

    // Role update state
    const [
        updatingRole,
        setUpdatingRole,
    ] = useState<string | null>(null);
    const [
        deletingUser,
        setDeletingUser,
    ] = useState<string | null>(null);

    useEffect(() => {
        loadUsers();
    }, [ page ]);

    useEffect(() => {
        if (alert) {
            const timer = setTimeout(() => setAlert(null), 5000);
            return () => clearTimeout(timer);
        }
    }, [ alert ]);

    const loadUsers = async() => {
        setLoading(true);
        try {
            const result = await api.listUsers({
                page,
                per_page: 10,
            });
            setUsers(result.items || []);
            setPagination(result.pagination);
        }
        catch (err: any) {
            console.error(`Failed to load users:`, err);
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: err.message || `Failed to load users`,
            });
        }
        finally {
            setLoading(false);
        }
    };

    const handleCreateUser = async(e: React.FormEvent) => {
        e.preventDefault();
        setSaving(true);
        setAlert(null);
        try {
            await api.createUser({
                email:      newEmail,
                password:   newPassword,
                first_name: newFirstName,
                last_name:  newLastName,
                role:       newRole || `viewer`,
            });
            setNewEmail(``);
            setNewPassword(``);
            setNewFirstName(``);
            setNewLastName(``);
            setNewRole(`viewer`);
            setIsCreateOpen(false);
            loadUsers();
            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `User created successfully`,
            });
        }
        catch (err: any) {
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: err.message || `Failed to create user`,
            });
        }
        finally {
            setSaving(false);
        }
    };

    const handleUpdateUserRole = async(userId: string, newRole: string) => {
        setUpdatingRole(userId);
        setAlert(null);
        try {
            await api.updateUser(userId, {
                role: newRole,
            });
            loadUsers();
            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `User role updated successfully`,
            });
        }
        catch (err: any) {
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: err.message || `Failed to update user role`,
            });
        }
        finally {
            setUpdatingRole(null);
        }
    };

    const handleDeleteUser = async(userId: string) => {
        if (!confirm(`Are you sure you want to delete this user? This action cannot be undone.`)) {
            return;
        }
        setDeletingUser(userId);
        setAlert(null);
        try {
            await api.deleteUser(userId);
            loadUsers();
            setAlert({
                type:    `success`,
                title:   `Success`,
                message: `User deleted successfully`,
            });
        }
        catch (err: any) {
            setAlert({
                type:    `error`,
                title:   `Error`,
                message: err.message || `Failed to delete user`,
            });
        }
        finally {
            setDeletingUser(null);
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
                        <form onSubmit={handleCreateUser} className="space-y-4 py-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-2">
                                    <Label htmlFor="firstName">First Name</Label>
                                    <Input
                                        id="firstName"
                                        placeholder="John"
                                        value={newFirstName}
                                        onChange={(e) => setNewFirstName(e.target.value)}
                                    />
                                </div>
                                <div className="space-y-2">
                                    <Label htmlFor="lastName">Last Name</Label>
                                    <Input
                                        id="lastName"
                                        placeholder="Doe"
                                        value={newLastName}
                                        onChange={(e) => setNewLastName(e.target.value)}
                                    />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="email">Email</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="john.doe@example.com"
                                    value={newEmail}
                                    onChange={(e) => setNewEmail(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <Input
                                    id="password"
                                    type="password"
                                    placeholder="••••••••"
                                    value={newPassword}
                                    onChange={(e) => setNewPassword(e.target.value)}
                                    required
                                />
                            </div>
                            <div className="space-y-2">
                                <Label>Role</Label>
                                <Select value={newRole} onValueChange={setNewRole}>
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
                            </div>
                            <DialogFooter>
                                <Button type="button" variant="outline" onClick={() => setIsCreateOpen(false)}>
                                    Cancel
                                </Button>
                                <Button type="submit" disabled={saving}>
                                    {saving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    Create User
                                </Button>
                            </DialogFooter>
                        </form>
                    </DialogContent>
                </Dialog>
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
                            </CardDescription>
                        </div>
                        <Users className="h-5 w-5 text-muted-foreground" />
                    </div>
                </CardHeader>
                <CardContent>
                    {loading
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
                            <TableHead>User</TableHead>
                            <TableHead>Email</TableHead>
                            <TableHead>Role</TableHead>
                            <TableHead>Created</TableHead>
                            <TableHead className="max-w-5"></TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {users.map((user) => (
                            <TableRow key={user.id}>
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
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `user`)} disabled={updatingRole === user.id}>
                                                Set as User
                                            </DropdownMenuItem>
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `admin`)} disabled={updatingRole === user.id}>
                                                Set as Admin
                                            </DropdownMenuItem>
                                            <DropdownMenuItem onClick={async() => handleUpdateUserRole(user.id, `super_admin`)} disabled={updatingRole === user.id}>
                                                Set as Super Admin
                                            </DropdownMenuItem>
                                            <DropdownMenuSeparator />
                                            <DropdownMenuItem onClick={async() => handleDeleteUser(user.id)} disabled={deletingUser === user.id} className="text-destructive focus:text-destructive">
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
