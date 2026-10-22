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
  ExternalLink,
  KeyRound,
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip as RechartsTooltip, BarChart, Bar, XAxis, YAxis } from 'recharts';

import { threatApi } from '../api/client';
import StatCard from '../components/Common/StatCard';
import SeverityBadge from '../components/Common/SeverityBadge';
import EmptyState from '../components/Common/EmptyState';

const SEVERITY_COLORS = {
  Low: '#10b981',
  Medium: '#f59e0b',
  High: '#f97316',
  Critical: '#ef4444',
};

export default function Dashboard() {
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
        color: SEVERITY_COLORS[key] || '#94a3b8',
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
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#f8fafc', mb: 0.5 }}>
            Threat Intelligence Overview
          </Typography>
          <Typography variant="body2" sx={{ color: '#94a3b8' }}>
            Multi-source IOC correlation, telemetry consensus, and proactive vulnerability triage.
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<Search size={18} />}
          onClick={() => navigate('/investigate')}
          sx={{ px: 3, py: 1 }}
        >
          New Investigation
        </Button>
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
              Configure Keys
            </Button>
          }
          sx={{
            bgcolor: 'rgba(245, 158, 11, 0.1)',
            color: '#fbbf24',
            border: '1px solid rgba(245, 158, 11, 0.3)',
          }}
        >
          <strong>API Setup Required:</strong> VirusTotal and AlienVault OTX keys are currently unconfigured.
          The platform operates in setup mode. Add keys to <code>.env</code> to enable live lookups.
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5' }}>
          {error}
        </Alert>
      )}

      {/* Stat Cards Row */}
      <Grid container spacing={2.5}>
        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={120} sx={{ bgcolor: '#0f172a' }} />
          ) : (
            <StatCard
              title="Total Investigations"
              value={stats?.total_investigations || 0}
              subtitle="Persisted threat scans"
              icon={Layers}
              accentColor="#00f2fe"
            />
          )}
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={120} sx={{ bgcolor: '#0f172a' }} />
          ) : (
            <StatCard
              title="Unique Indicators"
              value={stats?.unique_indicators || 0}
              subtitle="Distinct IOCs investigated"
              icon={Search}
              accentColor="#6366f1"
            />
          )}
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={120} sx={{ bgcolor: '#0f172a' }} />
          ) : (
            <StatCard
              title="High & Critical Findings"
              value={stats?.high_critical_count || 0}
              subtitle="Actionable threats detected"
              icon={ShieldAlert}
              accentColor="#ef4444"
            />
          )}
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          {loading ? (
            <Skeleton variant="rounded" height={120} sx={{ bgcolor: '#0f172a' }} />
          ) : (
            <StatCard
              title="Active Intelligence Feeds"
              value={
                (stats?.provider_health?.virustotal?.configured ? 1 : 0) +
                (stats?.provider_health?.alienvault_otx?.configured ? 1 : 0)
              }
              subtitle="Out of 2 feeds connected"
              icon={Activity}
              accentColor="#10b981"
            />
          )}
        </Grid>
      </Grid>

      {/* Analytics Charts Row */}
      <Grid container spacing={2.5}>
        {/* Severity Distribution Donut Chart */}
        <Grid item xs={12} md={5}>
          <Card sx={{ height: '100%', bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 0.5 }}>
                Severity Breakdown
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b', display: 'block', mb: 2 }}>
                Risk classification based on multi-source scoring consensus
              </Typography>

              {loading ? (
                <Skeleton variant="circular" width={180} height={180} sx={{ mx: 'auto', my: 2 }} />
              ) : severityChartData.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center', color: '#64748b' }}>
                  <Typography variant="body2">No historical investigations recorded yet.</Typography>
                </Box>
              ) : (
                <Box sx={{ height: 220, position: 'relative' }}>
                  <ResponsiveContainer width="100%" height="100%">
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
                          backgroundColor: '#080c14',
                          border: '1px solid rgba(255, 255, 255, 0.1)',
                          borderRadius: 8,
                          color: '#f8fafc',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  {/* Legend */}
                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mt: 1, flexWrap: 'wrap' }}>
                    {severityChartData.map((d) => (
                      <Box key={d.name} sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
                        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: d.color }} />
                        <Typography variant="caption" sx={{ color: '#94a3b8', fontWeight: 600 }}>
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
          <Card sx={{ height: '100%', bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <CardContent sx={{ p: 2.8 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 0.5 }}>
                Indicator Type Distribution
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b', display: 'block', mb: 2 }}>
                Breakdown of investigated telemetry types (IP, Domain, URL, Hash)
              </Typography>

              {loading ? (
                <Skeleton variant="rounded" height={220} />
              ) : typeChartData.length === 0 ? (
                <Box sx={{ py: 6, textAlign: 'center', color: '#64748b' }}>
                  <Typography variant="body2">No IOC telemetry logged yet.</Typography>
                </Box>
              ) : (
                <Box sx={{ height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={typeChartData}>
                      <XAxis dataKey="type" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                      <RechartsTooltip
                        cursor={{ fill: 'rgba(255, 255, 255, 0.04)' }}
                        contentStyle={{
                          backgroundColor: '#080c14',
                          border: '1px solid rgba(255, 255, 255, 0.1)',
                          borderRadius: 8,
                          color: '#f8fafc',
                        }}
                      />
                      <Bar dataKey="count" fill="#00f2fe" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Recent Investigations Table */}
      <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <CardContent sx={{ p: 2.8 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                Recent Investigations
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b' }}>
                Latest telemetry queries processed and archived
              </Typography>
            </Box>
            <Button
              size="small"
              endIcon={<ArrowRight size={14} />}
              onClick={() => navigate('/history')}
              sx={{ color: '#00f2fe' }}
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
                  <TableRow>
                    <TableCell>INDICATOR</TableCell>
                    <TableCell>TYPE</TableCell>
                    <TableCell>RISK SCORE</TableCell>
                    <TableCell>SEVERITY</TableCell>
                    <TableCell>DATE / TIME</TableCell>
                    <TableCell align="right">ACTION</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {stats.recent_investigations.map((row) => (
                    <TableRow key={row.id} hover sx={{ '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.02)' } }}>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#f1f5f9' }}>
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
                        <Typography variant="body2" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                          {row.risk_score} / 100
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={row.severity} size="small" />
                      </TableCell>
                      <TableCell sx={{ color: '#64748b', fontSize: '0.8rem' }}>
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
                            borderColor: 'rgba(255, 255, 255, 0.12)',
                            color: '#94a3b8',
                            '&:hover': {
                              borderColor: '#00f2fe',
                              color: '#00f2fe',
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
