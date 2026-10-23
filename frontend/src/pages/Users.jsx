import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Alert,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import {
  UserPlus,
  Shield,
  Trash2,
  RefreshCw,
  Edit2,
  AlertTriangle,
  UserCheck,
} from 'lucide-react';
import { threatApi } from '../api/client';
import { useAuth } from '../contexts/AuthContext';

const ROLE_COLORS = {
  Admin: { bg: 'rgba(8, 145, 178, 0.1)', text: '#0891B2', border: 'rgba(8, 145, 178, 0.3)' },
  'Senior Analyst': { bg: 'rgba(22, 163, 74, 0.1)', text: '#16A34A', border: 'rgba(22, 163, 74, 0.3)' },
  'Read-Only Analyst': { bg: 'rgba(217, 119, 6, 0.1)', text: '#D97706', border: 'rgba(217, 119, 6, 0.3)' },
};

export default function Users() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Create User Modal state
  const [createOpen, setCreateOpen] = useState(false);
  const [createData, setCreateData] = useState({
    username: '',
    full_name: '',
    email: '',
    password: '',
    role: 'Senior Analyst',
  });
  const [createLoading, setCreateLoading] = useState(false);
  const [createError, setCreateError] = useState('');

  // Edit Role Modal state
  const [editUser, setEditUser] = useState(null);
  const [editRole, setEditRole] = useState('');
  const [editActive, setEditActive] = useState(true);
  const [editLoading, setEditLoading] = useState(false);

  // Delete User Modal state
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await threatApi.getUsers();
      setUsers(data.users || []);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load user accounts.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    if (!createData.username.trim() || !createData.email.trim() || !createData.password) {
      setCreateError('Please complete all required fields.');
      return;
    }

    setCreateLoading(true);
    setCreateError('');
    try {
      await threatApi.createUser({
        username: createData.username.trim(),
        full_name: createData.full_name.trim() || createData.username.trim(),
        email: createData.email.trim(),
        password: createData.password,
        role: createData.role,
      });
      setSuccessMsg("User '" + createData.username + "' successfully provisioned.");
      setCreateOpen(false);
      setCreateData({ username: '', full_name: '', email: '', password: '', role: 'Senior Analyst' });
      fetchUsers();
    } catch (err) {
      setCreateError(err.response?.data?.detail || 'Failed to create user account.');
    } finally {
      setCreateLoading(false);
    }
  };

  const handleEditSubmit = async () => {
    if (!editUser) return;
    setEditLoading(true);
    try {
      await threatApi.updateUser(editUser.id, {
        role: editRole,
        is_active: editActive,
      });
      setSuccessMsg("User '" + editUser.username + "' updated.");
      setEditUser(null);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update user.');
    } finally {
      setEditLoading(false);
    }
  };

  const handleDeleteSubmit = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    try {
      await threatApi.deleteUser(deleteTarget.id);
      setSuccessMsg("User '" + deleteTarget.username + "' deleted.");
      setDeleteTarget(null);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete user.');
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto', p: { xs: 2, md: 3 } }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2 }}>
            <Shield size={24} color="#0891B2" />
            <Typography variant="h5" sx={{ fontWeight: 800, color: '#172B4D' }}>
              Identity & Access Management
            </Typography>
          </Box>
          <Typography variant="body2" sx={{ color: '#64748B', mt: 0.5 }}>
            Role-Based Access Control (RBAC) governance for ThreatLens AI analysts and administrators.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshCw size={16} />}
            onClick={fetchUsers}
            disabled={loading}
            sx={{ borderColor: '#DCE4EE', color: '#64748B' }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<UserPlus size={16} />}
            onClick={() => {
              setCreateError('');
              setCreateOpen(true);
            }}
            sx={{
              bgcolor: '#0891B2',
              color: '#FFFFFF',
              fontWeight: 700,
              '&:hover': { bgcolor: '#0e7490' },
            }}
          >
            Add New User
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" onClose={() => setError('')} sx={{ mb: 2.5, borderRadius: 2 }}>
          {error}
        </Alert>
      )}

      {successMsg && (
        <Alert severity="success" onClose={() => setSuccessMsg('')} sx={{ mb: 2.5, borderRadius: 2 }}>
          {successMsg}
        </Alert>
      )}

      {/* Users Table */}
      <Paper
        elevation={0}
        sx={{
          borderRadius: 3,
          border: '1px solid #DCE4EE',
          bgcolor: '#FFFFFF',
          overflow: 'hidden',
          boxShadow: '0 2px 10px rgba(15, 23, 42, 0.04)',
        }}
      >
        <TableContainer>
          <Table>
            <TableHead sx={{ bgcolor: '#F8FAFC' }}>
              <TableRow>
                <TableCell sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>USER</TableCell>
                <TableCell sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>EMAIL</TableCell>
                <TableCell sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>ASSIGNED ROLE</TableCell>
                <TableCell sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>STATUS</TableCell>
                <TableCell sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>CREATED</TableCell>
                <TableCell align="right" sx={{ fontWeight: 700, color: '#64748B', fontSize: '0.75rem' }}>ACTIONS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 6 }}>
                    <CircularProgress size={30} sx={{ color: '#0891B2' }} />
                  </TableCell>
                </TableRow>
              ) : users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 6, color: '#64748B' }}>
                    No users found.
                  </TableCell>
                </TableRow>
              ) : (
                users.map((u) => {
                  const roleStyle = ROLE_COLORS[u.role] || ROLE_COLORS['Read-Only Analyst'];
                  const isSelf = u.id === currentUser?.id;

                  return (
                    <TableRow key={u.id} hover sx={{ '&:last-child td, &:last-child th': { border: 0 } }}>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                          <Box
                            sx={{
                              width: 34,
                              height: 34,
                              borderRadius: '50%',
                              bgcolor: 'rgba(8, 145, 178, 0.12)',
                              color: '#0891B2',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontWeight: 700,
                              fontSize: '0.82rem',
                            }}
                          >
                            {(u.full_name || u.username)[0].toUpperCase()}
                          </Box>
                          <Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.8 }}>
                              <Typography variant="body2" sx={{ fontWeight: 700, color: '#172B4D' }}>
                                {u.full_name || u.username}
                              </Typography>
                              {isSelf && (
                                <Chip label="You" size="small" sx={{ height: 18, fontSize: '0.65rem', bgcolor: '#F1F5F9', fontWeight: 600 }} />
                              )}
                            </Box>
                            <Typography variant="caption" sx={{ color: '#64748B', fontFamily: 'monospace' }}>
                              @{u.username}
                            </Typography>
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ color: '#172B4D' }}>
                          {u.email}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={u.role}
                          size="small"
                          sx={{
                            fontWeight: 700,
                            fontSize: '0.72rem',
                            bgcolor: roleStyle.bg,
                            color: roleStyle.text,
                            border: '1px solid ' + roleStyle.border,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={u.is_active ? 'Active' : 'Inactive'}
                          size="small"
                          sx={{
                            fontWeight: 600,
                            fontSize: '0.7rem',
                            bgcolor: u.is_active ? 'rgba(22, 163, 74, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                            color: u.is_active ? '#16A34A' : '#EF4444',
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="caption" sx={{ color: '#64748B' }}>
                          {new Date(u.created_at).toLocaleDateString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 0.5 }}>
                          <Tooltip title="Edit Role / Status">
                            <IconButton
                              size="small"
                              onClick={() => {
                                setEditUser(u);
                                setEditRole(u.role);
                                setEditActive(u.is_active);
                              }}
                              sx={{ color: '#64748B', '&:hover': { color: '#0891B2' } }}
                            >
                              <Edit2 size={16} />
                            </IconButton>
                          </Tooltip>

                          <Tooltip title={isSelf ? 'Cannot delete your own account' : 'Delete User'}>
                            <span>
                              <IconButton
                                size="small"
                                disabled={isSelf}
                                onClick={() => setDeleteTarget(u)}
                                sx={{ color: '#64748B', '&:hover': { color: '#EF4444' } }}
                              >
                                <Trash2 size={16} />
                              </IconButton>
                            </span>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Create User Dialog */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ fontWeight: 800, color: '#172B4D', pb: 1 }}>
          Provision New SOC Analyst Account
        </DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
          {createError && (
            <Alert severity="error" sx={{ borderRadius: 2, mb: 1 }}>
              {createError}
            </Alert>
          )}
          <TextField
            label="Username"
            fullWidth
            required
            value={createData.username}
            onChange={(e) => setCreateData({ ...createData, username: e.target.value })}
          />
          <TextField
            label="Full Name"
            fullWidth
            value={createData.full_name}
            onChange={(e) => setCreateData({ ...createData, full_name: e.target.value })}
          />
          <TextField
            label="Email"
            type="email"
            fullWidth
            required
            value={createData.email}
            onChange={(e) => setCreateData({ ...createData, email: e.target.value })}
          />
          <TextField
            label="Temporary Password"
            type="password"
            fullWidth
            required
            value={createData.password}
            onChange={(e) => setCreateData({ ...createData, password: e.target.value })}
            helperText="Must be at least 8 characters with letters, numbers, and symbols."
          />
          <TextField
            select
            label="Role Assignment"
            fullWidth
            value={createData.role}
            onChange={(e) => setCreateData({ ...createData, role: e.target.value })}
          >
            <MenuItem value="Senior Analyst">Senior Analyst (Investigate, Bulk Triage, Reporting)</MenuItem>
            <MenuItem value="Read-Only Analyst">Read-Only Analyst (Inspect telemetry & stats only)</MenuItem>
            <MenuItem value="Admin">Administrator (Full access & user management)</MenuItem>
          </TextField>
        </DialogContent>
        <DialogActions sx={{ p: 2.5, pt: 1 }}>
          <Button onClick={() => setCreateOpen(false)} sx={{ color: '#64748B' }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreateSubmit}
            disabled={createLoading}
            sx={{ bgcolor: '#0891B2', color: '#FFFFFF', fontWeight: 700, '&:hover': { bgcolor: '#0e7490' } }}
          >
            {createLoading ? 'Provisioning...' : 'Create Account'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={Boolean(editUser)} onClose={() => setEditUser(null)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ fontWeight: 800, color: '#172B4D' }}>
          Modify User: @{editUser?.username}
        </DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2.5, pt: 2 }}>
          <TextField
            select
            label="Role"
            fullWidth
            value={editRole}
            onChange={(e) => setEditRole(e.target.value)}
          >
            <MenuItem value="Admin">Admin</MenuItem>
            <MenuItem value="Senior Analyst">Senior Analyst</MenuItem>
            <MenuItem value="Read-Only Analyst">Read-Only Analyst</MenuItem>
          </TextField>

          <TextField
            select
            label="Account Status"
            fullWidth
            value={editActive ? 'active' : 'inactive'}
            onChange={(e) => setEditActive(e.target.value === 'active')}
          >
            <MenuItem value="active">Active</MenuItem>
            <MenuItem value="inactive">Deactivated / Suspended</MenuItem>
          </TextField>
        </DialogContent>
        <DialogActions sx={{ p: 2.5 }}>
          <Button onClick={() => setEditUser(null)} sx={{ color: '#64748B' }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleEditSubmit}
            disabled={editLoading}
            sx={{ bgcolor: '#0891B2', color: '#FFFFFF', fontWeight: 700, '&:hover': { bgcolor: '#0e7490' } }}
          >
            {editLoading ? 'Saving...' : 'Save Changes'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={Boolean(deleteTarget)} onClose={() => setDeleteTarget(null)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ fontWeight: 800, color: '#EF4444', display: 'flex', alignItems: 'center', gap: 1 }}>
          <AlertTriangle size={20} />
          Confirm Deletion
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ color: '#172B4D', lineHeight: 1.5 }}>
            Are you sure you want to permanently delete user account <strong>@{deleteTarget?.username}</strong>?
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 2.5 }}>
          <Button onClick={() => setDeleteTarget(null)} sx={{ color: '#64748B' }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            color="error"
            onClick={handleDeleteSubmit}
            disabled={deleteLoading}
            sx={{ fontWeight: 700 }}
          >
            {deleteLoading ? 'Deleting...' : 'Delete Account'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
