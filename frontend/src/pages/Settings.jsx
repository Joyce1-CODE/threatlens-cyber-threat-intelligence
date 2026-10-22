import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
  Divider,
  Alert,
  Skeleton,
} from '@mui/material';
import { KeyRound, ShieldCheck, AlertTriangle, ExternalLink, Terminal, Server, Database, Check } from 'lucide-react';
import { threatApi } from '../api/client';

export default function Settings() {
  const [providers, setProviders] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSystemStatus();
  }, []);

  const fetchSystemStatus = async () => {
    try {
      setLoading(true);
      const [provRes, healthRes] = await Promise.all([
        threatApi.getProviderStatus(),
        threatApi.getHealth(),
      ]);
      setProviders(provRes.providers);
      setHealth(healthRes);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const vt = providers?.virustotal;
  const otx = providers?.alienvault_otx;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Title */}
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#f8fafc', mb: 0.5 }}>
          Platform Configuration & Credentials
        </Typography>
        <Typography variant="body2" sx={{ color: '#94a3b8' }}>
          Inspect provider feed statuses, rate limit quotas, environment variables, and system telemetry.
        </Typography>
      </Box>

      {/* Provider Integration Cards */}
      <Grid container spacing={3}>
        {/* VirusTotal v3 Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)', height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                  VirusTotal v3 API
                </Typography>
                {vt?.configured ? (
                  <Chip
                    size="small"
                    label="Configured & Ready"
                    sx={{ bgcolor: 'rgba(16, 185, 129, 0.15)', color: '#10b981', fontWeight: 600 }}
                  />
                ) : (
                  <Chip
                    size="small"
                    label="Not Configured"
                    sx={{ bgcolor: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', fontWeight: 600 }}
                  />
                )}
              </Box>

              <Typography variant="body2" sx={{ color: '#cbd5e1', mb: 2 }}>
                Enables passive reputation analysis across 70+ leading antivirus engines and security vendors.
              </Typography>

              <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2, mb: 2.5 }}>
                <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, display: 'block', mb: 0.5 }}>
                  RATE LIMIT & QUOTAS:
                </Typography>
                <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                  {vt?.rate_limit_info || '4 requests/minute, 500 requests/day (Free tier)'}
                </Typography>
              </Box>

              <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, display: 'block', mb: 0.8 }}>
                HOW TO CONFIGURE:
              </Typography>
              <Typography variant="body2" sx={{ color: '#94a3b8', mb: 2 }}>
                1. Sign up for a free account at virustotal.com.<br />
                2. Copy your API key from your profile menu.<br />
                3. Add the following entry to your <code>.env</code> file:
              </Typography>

              <Box sx={{ p: 1.5, bgcolor: '#080c14', borderRadius: 1.5, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.82rem', color: '#00f2fe', mb: 2.5 }}>
                VIRUSTOTAL_API_KEY="your_api_key_here"
              </Box>

              <Button
                variant="outlined"
                size="small"
                endIcon={<ExternalLink size={14} />}
                href="https://www.virustotal.com/gui/join-us"
                target="_blank"
                rel="noreferrer"
                sx={{ borderColor: 'rgba(255, 255, 255, 0.15)', color: '#94a3b8' }}
              >
                Get Free VirusTotal Key
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* AlienVault OTX Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)', height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc' }}>
                  AlienVault OTX API
                </Typography>
                {otx?.configured ? (
                  <Chip
                    size="small"
                    label="Configured & Ready"
                    sx={{ bgcolor: 'rgba(16, 185, 129, 0.15)', color: '#10b981', fontWeight: 600 }}
                  />
                ) : (
                  <Chip
                    size="small"
                    label="Not Configured"
                    sx={{ bgcolor: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', fontWeight: 600 }}
                  />
                )}
              </Box>

              <Typography variant="body2" sx={{ color: '#cbd5e1', mb: 2 }}>
                Open Threat Exchange community threat pulses, targeted threat groups, and malware family links.
              </Typography>

              <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2, mb: 2.5 }}>
                <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, display: 'block', mb: 0.5 }}>
                  RATE LIMIT & QUOTAS:
                </Typography>
                <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                  {otx?.rate_limit_info || 'Generous community tier with real-time adversary tagging'}
                </Typography>
              </Box>

              <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, display: 'block', mb: 0.8 }}>
                HOW TO CONFIGURE:
              </Typography>
              <Typography variant="body2" sx={{ color: '#94a3b8', mb: 2 }}>
                1. Create a free account at otx.alienvault.com.<br />
                2. Navigate to your profile to find your OTX Key.<br />
                3. Add the following entry to your <code>.env</code> file:
              </Typography>

              <Box sx={{ p: 1.5, bgcolor: '#080c14', borderRadius: 1.5, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.82rem', color: '#c084fc', mb: 2.5 }}>
                OTX_API_KEY="your_api_key_here"
              </Box>

              <Button
                variant="outlined"
                size="small"
                endIcon={<ExternalLink size={14} />}
                href="https://otx.alienvault.com"
                target="_blank"
                rel="noreferrer"
                sx={{ borderColor: 'rgba(255, 255, 255, 0.15)', color: '#94a3b8' }}
              >
                Get Free AlienVault Key
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Security Architecture & Principles Card */}
      <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <CardContent sx={{ p: 3.5 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 1.5 }}>
            Security Architecture & Operational Guarantees
          </Typography>

          <Grid container spacing={2.5}>
            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#00f2fe', fontWeight: 700, mb: 0.5 }}>
                  Passive Lookups Only
                </Typography>
                <Typography variant="caption" sx={{ color: '#94a3b8', lineHeight: 1.5, display: 'block' }}>
                  ThreatLens AI never interacts with target endpoints, executes files, or scans client infrastructure.
                </Typography>
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#10b981', fontWeight: 700, mb: 0.5 }}>
                  Backend Secret Isolation
                </Typography>
                <Typography variant="caption" sx={{ color: '#94a3b8', lineHeight: 1.5, display: 'block' }}>
                  API credentials remain strictly on the Python backend. No tokens or keys are exposed to the browser.
                </Typography>
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#f59e0b', fontWeight: 700, mb: 0.5 }}>
                  Zero Fabricated Data
                </Typography>
                <Typography variant="caption" sx={{ color: '#94a3b8', lineHeight: 1.5, display: 'block' }}>
                  When keys are absent or endpoints return 404, unverified states are shown rather than fabricated metrics.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    </Box>
  );
}
