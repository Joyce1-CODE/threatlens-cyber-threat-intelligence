import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  MenuItem,
  Button,
  Chip,
  Pagination,
  IconButton,
  Tooltip,
  Skeleton,
  Alert,
} from '@mui/material';
import { Search, Eye, Trash2, Filter, ShieldCheck, AlertTriangle } from 'lucide-react';

import { threatApi } from '../api/client';
import SeverityBadge from '../components/Common/SeverityBadge';
import EmptyState from '../components/Common/EmptyState';

export default function History() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchHistory();
  }, [page, typeFilter, severityFilter]);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      const params = {
        page,
        page_size: 10,
        search: search.trim() || undefined,
        indicator_type: typeFilter !== 'all' ? typeFilter : undefined,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
      };
      const res = await threatApi.getInvestigations(params);
      setItems(res.items || []);
      setTotal(res.total || 0);
      setTotalPages(res.total_pages || 1);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Failed to load investigation history.');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchHistory();
  };

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Delete this investigation record permanently?')) return;
    try {
      await threatApi.deleteInvestigation(id);
      fetchHistory();
    } catch (err) {
      alert('Failed to delete investigation record.');
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#f8fafc', mb: 0.5 }}>
            Investigation History
          </Typography>
          <Typography variant="body2" sx={{ color: '#94a3b8' }}>
            Archived threat intelligence queries, evidence signals, and score audits ({total} total records).
          </Typography>
        </Box>
        <Button
          variant="contained"
          onClick={() => navigate('/investigate')}
          startIcon={<Search size={16} />}
        >
          New Investigation
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5' }}>
          {error}
        </Alert>
      )}

      {/* Filter and Search Bar */}
      <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <CardContent sx={{ p: 2.5 }}>
          <Box
            component="form"
            onSubmit={handleSearchSubmit}
            sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 1.5, alignItems: 'center' }}
          >
            <TextField
              fullWidth
              size="small"
              placeholder="Filter by indicator (IP, domain, hash, or URL)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              sx={{
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#080c14',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.9rem',
                },
              }}
            />

            <TextField
              select
              size="small"
              value={typeFilter}
              onChange={(e) => {
                setTypeFilter(e.target.value);
                setPage(1);
              }}
              sx={{ minWidth: 150, '& .MuiOutlinedInput-root': { bgcolor: '#080c14' } }}
            >
              <MenuItem value="all">All Types</MenuItem>
              <MenuItem value="ipv4">IPv4</MenuItem>
              <MenuItem value="ipv6">IPv6</MenuItem>
              <MenuItem value="domain">Domain</MenuItem>
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="md5">MD5</MenuItem>
              <MenuItem value="sha1">SHA-1</MenuItem>
              <MenuItem value="sha256">SHA-256</MenuItem>
            </TextField>

            <TextField
              select
              size="small"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              sx={{ minWidth: 150, '& .MuiOutlinedInput-root': { bgcolor: '#080c14' } }}
            >
              <MenuItem value="all">All Severities</MenuItem>
              <MenuItem value="Low">Low Risk</MenuItem>
              <MenuItem value="Medium">Medium Risk</MenuItem>
              <MenuItem value="High">High Risk</MenuItem>
              <MenuItem value="Critical">Critical Risk</MenuItem>
            </TextField>

            <Button
              type="submit"
              variant="outlined"
              sx={{
                borderColor: 'rgba(0, 242, 254, 0.3)',
                color: '#00f2fe',
                minWidth: 100,
                py: 0.9,
                '&:hover': { borderColor: '#00f2fe' },
              }}
            >
              Search
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* History Table */}
      <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <CardContent sx={{ p: 0 }}>
          {loading ? (
            <Box sx={{ p: 3 }}>
              <Skeleton variant="rounded" height={300} />
            </Box>
          ) : items.length === 0 ? (
            <Box sx={{ p: 4 }}>
              <EmptyState
                title="No History Matches Found"
                description="Try clearing your search query or filter settings, or investigate a new indicator."
                actionText="Investigate an IOC"
                actionLink="/investigate"
              />
            </Box>
          ) : (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>INDICATOR</TableCell>
                    <TableCell>TYPE</TableCell>
                    <TableCell>RISK SCORE</TableCell>
                    <TableCell>SEVERITY</TableCell>
                    <TableCell>PROVIDERS</TableCell>
                    <TableCell>TIMESTAMP</TableCell>
                    <TableCell align="right">ACTIONS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {items.map((row) => (
                    <TableRow
                      key={row.id}
                      hover
                      onClick={() => navigate(`/investigation/${row.id}`)}
                      sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.02)' } }}
                    >
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#f8fafc' }}>
                        {row.normalized_indicator}
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={row.indicator_type.toUpperCase()}
                          sx={{
                            bgcolor: 'rgba(255, 255, 255, 0.04)',
                            color: '#94a3b8',
                            fontSize: '0.7rem',
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 700, color: '#f1f5f9' }}>
                          {row.risk_score} / 100
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={row.severity} size="small" />
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.8 }}>
                          <Chip
                            size="small"
                            label={`VT: ${row.vt_detections}`}
                            sx={{
                              bgcolor: row.vt_detections > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                              color: row.vt_detections > 0 ? '#ef4444' : '#94a3b8',
                              fontSize: '0.68rem',
                            }}
                          />
                          <Chip
                            size="small"
                            label={`OTX: ${row.otx_pulse_count}`}
                            sx={{
                              bgcolor: row.otx_pulse_count > 0 ? 'rgba(168, 85, 247, 0.15)' : 'rgba(255, 255, 255, 0.04)',
                              color: row.otx_pulse_count > 0 ? '#c084fc' : '#94a3b8',
                              fontSize: '0.68rem',
                            }}
                          />
                        </Box>
                      </TableCell>
                      <TableCell sx={{ color: '#64748b', fontSize: '0.8rem' }}>
                        {new Date(row.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell align="right">
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 0.5 }}>
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/investigation/${row.id}`);
                              }}
                              sx={{ color: '#00f2fe' }}
                            >
                              <Eye size={16} />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Record">
                            <IconButton
                              size="small"
                              onClick={(e) => handleDelete(row.id, e)}
                              sx={{ color: '#ef4444' }}
                            >
                              <Trash2 size={16} />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <Box sx={{ p: 2.5, display: 'flex', justifyContent: 'center', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={(_, val) => setPage(val)}
                color="primary"
                shape="rounded"
              />
            </Box>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
