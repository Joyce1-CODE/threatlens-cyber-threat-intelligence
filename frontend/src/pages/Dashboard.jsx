import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Chip,
  Alert,
  Skeleton,
} from '@mui/material';
import {
  ShieldAlert,
  Search,
  Activity,
  Layers,
  ShieldCheck,
  ArrowRight,
  KeyRound,
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip as RechartsTooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';

import { threatApi } from '../api/client';
import { useAuth } from '../contexts/AuthContext';
import { Tooltip } from '@mui/material';
import StatCard from '../components/Common/StatCard';
import SeverityBadge from '../components/Common/SeverityBadge';
import EmptyState from '../components/Common/EmptyState';

const SEVERITY_COLORS = {
  Low: '#16A34A',
  Medium: '#D97706',
  High: '#EA580C',
  Critical: '#DC2626',
};

export default function Dashboard() {
  const { isReadOnly } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await threatApi.getDashboardStats();
      setStats(data);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Unable to load dashboard metrics. Verify backend service is running.');
    } finally {
      setLoading(false);
    }
  };

  const isSetupNeeded =
    stats &&
    !stats.provider_health?.virustotal?.configured &&
    !stats.provider_health?.alienvault_otx?.configured;

  const severityChartData = stats
    ? Object.entries(stats.severity_breakdown || {}).map(([key, value]) => ({
        name: key,
        value: value,
        color: SEVERITY_COLORS[key] || '#64748B',
      })).filter(d => d.value > 0)
    : [];

  const typeChartData = stats
    ? Object.entries(stats.indicator_type_breakdown || {}).map(([key, value]) => ({
        type: key.toUpperCase(),
        count: value,
      })).filter(d => d.count > 0)
    : [];

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Header Banner */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#172B4D', mb: 0.5 }}>
            Threat Intelligence Overview
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748B' }}>
            Multi-source IOC correlation, telemetry consensus, and proactive vulnerability triage.
          </Typography>
        </Box>
        <Tooltip title={isReadOnly ? 'Action restricted: Read-Only Analysts cannot initiate new investigations.' : ''}>
          <span>
            <Button
              variant="contained"
              disabled={isReadOnly}
              startIcon={<Search size={18} />}
              onClick={() => navigate('/investigate')}
          sx={{
            bgcolor: '#0891B2',
            color: '#FFFFFF',
            px: 3,
            py: 1,
            '&:hover': { bgcolor: '#0E7490' },
          }}
        >
          New Investigation
        </Button>
          </span>
        </Tooltip>
      </Box>

      {/* Setup Alert Banner if no API keys configured */}
      {isSetupNeeded && (
        <Alert
          severity="warning"
          icon={<KeyRound size={20} />}
          action={
            <Button
              color="inherit"
              size="small"
              onClick={() => navigate('/settings')}
              sx={{ fontWeight: 700 }}
            >
              Configure API Keys
            </Button>
          }
          sx={{
            bgcolor: 'rgba(217, 119, 6, 0.08)',
            border: '1px solid rgba(217, 119, 6, 0.3)',
            color: '#172B4D',
          }}
        >
          <strong>API Keys Not Configured:</strong> ThreatLens AI is currently running in offline mock demonstration mode. Add your free VirusTotal and AlienVault OTX keys in Settings to enable live vendor intelligence.
        </Alert>
      )}

      {error && <Alert severity="error">{error}</Alert>}

      {/* KPI Metrics Grid */}
      <Grid container spacing={2.5}>
        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={130} />
          ) : (
            <StatCard
              title="Total Ingested IOCs"
              value={stats?.total_investigations || 0}
              subtitle="All historical indicators"
              icon={Layers}
              accentColor="#0891B2"
            />
          )}
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={130} />
          ) : (
            <StatCard
              title="Actionable Threats"
              value={(stats?.severity_breakdown?.Critical || 0) + (stats?.severity_breakdown?.High || 0)}
              subtitle="High & Critical severity"
              icon={ShieldAlert}
              accentColor="#DC2626"
            />
          )}
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={130} />
          ) : (
            <StatCard
              title="Benign Telemetry"
              value={stats?.severity_breakdown?.Low || 0}
              subtitle="Low risk / clean indicators"
              icon={ShieldCheck}
              accentColor="#16A34A"
            />
          )}
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={130} />
          ) : (
            <StatCard
              title="Suspicious / Moderate"
              value={stats?.severity_breakdown?.Medium || 0}
              subtitle="Medium risk warnings"
              icon={Activity}
              accentColor="#D97706"
            />
          )}
        </Grid>
      </Grid>

      {/* Interactive Threat Visualizations */}
      <Grid container spacing={3}>
        {/* Severity Breakdown Donut Chart */}
        <Grid item xs={12} md={5}>
          <Card sx={{ height: '100%', bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 0.5 }}>
                Severity Breakdown
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748B', display: 'block', mb: 2 }}>
                Distribution of risk levels across archived indicators
              </Typography>

              {loading ? (
                <Skeleton variant="circular" width={180} height={180} sx={{ mx: 'auto', my: 2 }} />
              ) : severityChartData.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center', color: '#64748B' }}>
                  <Typography variant="body2">No investigation telemetry yet.</Typography>
                </Box>
              ) : (
                <Box sx={{ height: 220, position: 'relative' }}>
                  <ResponsiveContainer width="100%" height="80%">
                    <PieChart>
                      <Pie
                        data={severityChartData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={80}
                        paddingAngle={4}
                      >
                        {severityChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{
                          backgroundColor: '#FFFFFF',
                          border: '1px solid #DCE4EE',
                          borderRadius: 8,
                          color: '#172B4D',
                          boxShadow: '0 4px 12px rgba(15, 23, 42, 0.08)',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  {/* Legend */}
                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 1, flexWrap: 'wrap' }}>
                    {severityChartData.map((d) => (
                      <Box key={d.name} sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
                        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: d.color }} />
                        <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 600 }}>
                          {d.name}: {d.value}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* IOC Types Bar Chart */}
        <Grid item xs={12} md={7}>
          <Card sx={{ height: '100%', bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 0.5 }}>
                Indicator Type Distribution
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748B', display: 'block', mb: 2 }}>
                Breakdown of investigated telemetry types (IP, Domain, URL, Hash)
              </Typography>

              {loading ? (
                <Skeleton variant="rounded" height={220} />
              ) : typeChartData.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center', color: '#64748B' }}>
                  <Typography variant="body2">No IOC telemetry logged yet.</Typography>
                </Box>
              ) : (
                <Box sx={{ height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={typeChartData}>
                      <XAxis dataKey="type" stroke="#64748B" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748B" fontSize={11} tickLine={false} allowDecimals={false} />
                      <RechartsTooltip
                        cursor={{ fill: 'rgba(8, 145, 178, 0.04)' }}
                        contentStyle={{
                          backgroundColor: '#FFFFFF',
                          border: '1px solid #DCE4EE',
                          borderRadius: 8,
                          color: '#172B4D',
                          boxShadow: '0 4px 12px rgba(15, 23, 42, 0.08)',
                        }}
                      />
                      <Bar dataKey="count" fill="#0891B2" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Investigations Table */}
      <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
        <CardContent sx={{ p: 2.8 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
                Recent Investigations
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748B' }}>
                Latest telemetry queries processed and archived
              </Typography>
            </Box>
            <Button
              size="small"
              endIcon={<ArrowRight size={14} />}
              onClick={() => navigate('/history')}
              sx={{ color: '#0891B2', fontWeight: 600 }}
            >
              View Full History
            </Button>
          </Box>

          {loading ? (
            <Skeleton variant="rounded" height={160} />
          ) : !stats?.recent_investigations || stats.recent_investigations.length === 0 ? (
            <EmptyState
              title="No Investigations Yet"
              description="Enter your first IP, domain, hash, or URL to see live threat intelligence."
              actionText="Run First Investigation"
              actionLink="/investigate"
            />
          ) : (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: '#F8FAFC' }}>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>INDICATOR</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>TYPE</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>RISK SCORE</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>SEVERITY</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>DATE / TIME</TableCell>
                    <TableCell align="right" sx={{ color: '#64748B', fontWeight: 600 }}>ACTION</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {stats.recent_investigations.map((row) => (
                    <TableRow key={row.id} hover sx={{ '&:hover': { bgcolor: '#F8FAFC' } }}>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#172B4D' }}>
                        {row.normalized_indicator}
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={row.indicator_type.toUpperCase()}
                          sx={{
                            bgcolor: '#F1F5F9',
                            color: '#64748B',
                            border: '1px solid #DCE4EE',
                            fontSize: '0.7rem',
                            fontWeight: 600,
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 700, color: '#172B4D' }}>
                          {row.risk_score} / 100
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={row.severity} size="small" />
                      </TableCell>
                      <TableCell sx={{ color: '#64748B', fontSize: '0.8rem' }}>
                        {new Date(row.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell align="right">
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => navigate(`/investigation/${row.id}`)}
                          sx={{
                            fontSize: '0.75rem',
                            py: 0.3,
                            px: 1.2,
                            borderColor: '#DCE4EE',
                            color: '#172B4D',
                            '&:hover': {
                              borderColor: '#0891B2',
                              color: '#0891B2',
                              bgcolor: 'rgba(8, 145, 178, 0.04)',
                            },
                          }}
                        >
                          Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
