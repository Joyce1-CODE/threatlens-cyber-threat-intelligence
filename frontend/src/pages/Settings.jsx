import React, { useEffect, useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  Button,
} from '@mui/material';
import { ExternalLink } from 'lucide-react';
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
        <Typography variant="h4" sx={{ fontWeight: 800, color: '#172B4D', mb: 0.5 }}>
          Platform Configuration & Credentials
        </Typography>
        <Typography variant="body2" sx={{ color: '#64748B' }}>
          Inspect provider feed statuses, rate limit quotas, environment variables, and system telemetry.
        </Typography>
      </Box>

      {/* Provider Integration Cards */}
      <Grid container spacing={3}>
        {/* VirusTotal v3 Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5, height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
                  VirusTotal v3 API
                </Typography>
                {vt?.configured ? (
                  <Chip
                    size="small"
                    label="Configured & Ready"
                    sx={{ bgcolor: 'rgba(22, 163, 74, 0.08)', color: '#16A34A', border: '1px solid rgba(22, 163, 74, 0.25)', fontWeight: 600 }}
                  />
                ) : (
                  <Chip
                    size="small"
                    label="Not Configured"
                    sx={{ bgcolor: 'rgba(217, 119, 6, 0.08)', color: '#D97706', border: '1px solid rgba(217, 119, 6, 0.25)', fontWeight: 600 }}
                  />
                )}
              </Box>

              <Typography variant="body2" sx={{ color: '#172B4D', mb: 2, lineHeight: 1.5 }}>
                Enables passive reputation analysis across 70+ leading antivirus engines and security vendors.
              </Typography>

              <Box sx={{ p: 2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2, mb: 2.5 }}>
                <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, display: 'block', mb: 0.5 }}>
                  RATE LIMIT & QUOTAS:
                </Typography>
                <Typography variant="body2" sx={{ color: '#172B4D' }}>
                  {vt?.rate_limit_info || '4 requests/minute, 500 requests/day (Free tier)'}
                </Typography>
              </Box>

              <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, display: 'block', mb: 0.8 }}>
                HOW TO CONFIGURE:
              </Typography>
              <Typography variant="body2" sx={{ color: '#64748B', mb: 2 }}>
                1. Sign up for a free account at virustotal.com.<br />
                2. Copy your API key from your profile menu.<br />
                3. Add the following entry to your <code>.env</code> file:
              </Typography>

              <Box sx={{ p: 1.5, bgcolor: '#F1F5F9', border: '1px solid #DCE4EE', borderRadius: 1.5, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.82rem', color: '#0891B2', fontWeight: 600, mb: 2.5 }}>
                VIRUSTOTAL_API_KEY="your_api_key_here"
              </Box>

              <Button
                variant="outlined"
                size="small"
                endIcon={<ExternalLink size={14} />}
                href="https://www.virustotal.com/gui/join-us"
                target="_blank"
                rel="noreferrer"
                sx={{
                  borderColor: '#DCE4EE',
                  color: '#172B4D',
                  '&:hover': { borderColor: '#0891B2', color: '#0891B2' },
                }}
              >
                Get Free VirusTotal Key
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* AlienVault OTX Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5, height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
                  AlienVault OTX API
                </Typography>
                {otx?.configured ? (
                  <Chip
                    size="small"
                    label="Configured & Ready"
                    sx={{ bgcolor: 'rgba(22, 163, 74, 0.08)', color: '#16A34A', border: '1px solid rgba(22, 163, 74, 0.25)', fontWeight: 600 }}
                  />
                ) : (
                  <Chip
                    size="small"
                    label="Not Configured"
                    sx={{ bgcolor: 'rgba(217, 119, 6, 0.08)', color: '#D97706', border: '1px solid rgba(217, 119, 6, 0.25)', fontWeight: 600 }}
                  />
                )}
              </Box>

              <Typography variant="body2" sx={{ color: '#172B4D', mb: 2, lineHeight: 1.5 }}>
                Open Threat Exchange community threat pulses, targeted threat groups, and malware family links.
              </Typography>

              <Box sx={{ p: 2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2, mb: 2.5 }}>
                <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, display: 'block', mb: 0.5 }}>
                  RATE LIMIT & QUOTAS:
                </Typography>
                <Typography variant="body2" sx={{ color: '#172B4D' }}>
                  {otx?.rate_limit_info || 'Generous community tier with real-time adversary tagging'}
                </Typography>
              </Box>

              <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, display: 'block', mb: 0.8 }}>
                HOW TO CONFIGURE:
              </Typography>
              <Typography variant="body2" sx={{ color: '#64748B', mb: 2 }}>
                1. Create a free account at otx.alienvault.com.<br />
                2. Navigate to your profile to find your OTX Key.<br />
                3. Add the following entry to your <code>.env</code> file:
              </Typography>

              <Box sx={{ p: 1.5, bgcolor: '#F1F5F9', border: '1px solid #DCE4EE', borderRadius: 1.5, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.82rem', color: '#4F46E5', fontWeight: 600, mb: 2.5 }}>
                OTX_API_KEY="your_api_key_here"
              </Box>

              <Button
                variant="outlined"
                size="small"
                endIcon={<ExternalLink size={14} />}
                href="https://otx.alienvault.com"
                target="_blank"
                rel="noreferrer"
                sx={{
                  borderColor: '#DCE4EE',
                  color: '#172B4D',
                  '&:hover': { borderColor: '#0891B2', color: '#0891B2' },
                }}
              >
                Get Free AlienVault Key
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Security Architecture & Principles Card */}
      <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
        <CardContent sx={{ p: 3.5 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 2 }}>
            Security Architecture & Operational Guarantees
          </Typography>

          <Grid container spacing={2.5}>
            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2.2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#0891B2', fontWeight: 700, mb: 0.5 }}>
                  Passive Lookups Only
                </Typography>
                <Typography variant="caption" sx={{ color: '#64748B', lineHeight: 1.5, display: 'block' }}>
                  ThreatLens AI never interacts with target endpoints, executes files, or scans client infrastructure.
                </Typography>
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2.2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#16A34A', fontWeight: 700, mb: 0.5 }}>
                  Backend Secret Isolation
                </Typography>
                <Typography variant="caption" sx={{ color: '#64748B', lineHeight: 1.5, display: 'block' }}>
                  API credentials remain strictly on the Python backend. No tokens or keys are exposed to the browser.
                </Typography>
              </Box>
            </Grid>

            <Grid item xs={12} sm={4}>
              <Box sx={{ p: 2.2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ color: '#D97706', fontWeight: 700, mb: 0.5 }}>
                  Zero Fabricated Data
                </Typography>
                <Typography variant="caption" sx={{ color: '#64748B', lineHeight: 1.5, display: 'block' }}>
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
