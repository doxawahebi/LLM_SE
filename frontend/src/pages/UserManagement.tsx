import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { listUsers, updateUserRole, deleteUser, type User } from "@/api/client";
import { formatTimestamp } from "@/lib/formatters";

const ROLES = ["viewer", "operator", "intervener", "admin"] as const;
type Role = (typeof ROLES)[number];

export function UserManagement() {
  const can = useAuth((s) => s.can);
  const currentUsername = useAuth((s) => s.username);
  const qc = useQueryClient();

  const { data: users, isLoading } = useQuery({
    queryKey: ["users"],
    queryFn: listUsers,
    enabled: can("manage_settings"),
  });

  const { mutate: changeRole } = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: Role }) =>
      updateUserRole(userId, role),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });

  const { mutate: remove } = useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["users"] }),
  });

  if (!can("manage_settings")) return <Navigate to="/" replace />;

  if (isLoading) {
    return (
      <div className="p-6 space-y-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-12 bg-muted rounded animate-pulse" />
        ))}
      </div>
    );
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4">
      <h1 className="text-lg font-bold text-foreground">User Management</h1>
      <p className="text-xs text-muted-foreground">
        Manage user roles and access. Role changes take effect on the user's next request.
      </p>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Username</th>
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Email</th>
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Role</th>
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Registered</th>
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Last login</th>
              <th className="px-4 py-2 text-left text-muted-foreground font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(users ?? []).map((user: User) => {
              const isSelf = user.username === currentUsername;
              return (
                <tr key={user.id} className="border-b border-border/50 hover:bg-accent/10">
                  <td className="px-4 py-2 font-mono text-foreground">
                    {user.username}
                    {isSelf && (
                      <span className="ml-1 text-muted-foreground">(you)</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">{user.email}</td>
                  <td className="px-4 py-2">
                    <select
                      value={user.role}
                      disabled={isSelf}
                      onChange={(e) =>
                        changeRole({ userId: user.id, role: e.target.value as Role })
                      }
                      className="px-2 py-1 bg-secondary border border-border rounded text-foreground disabled:opacity-50"
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {user.registered_at ? formatTimestamp(user.registered_at) : "—"}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {user.last_login_at ? formatTimestamp(user.last_login_at) : "Never"}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      disabled={isSelf}
                      onClick={() => {
                        if (confirm(`Delete user ${user.username}?`)) {
                          remove(user.id);
                        }
                      }}
                      className="px-2 py-1 text-xs text-red-400 hover:text-red-300 hover:bg-red-900/20 rounded transition-colors disabled:opacity-30"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {(users ?? []).length === 0 && (
          <p className="text-xs text-muted-foreground p-4 text-center">No users found.</p>
        )}
      </div>
    </div>
  );
}
