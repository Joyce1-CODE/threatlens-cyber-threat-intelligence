import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
import { Shield, ArrowRight, ExternalLink, Calendar, Hash, Globe, Lock } from 'lucide-react';

import { threatApi } from '../api/client';
import IOCInputForm from '../components/Investigation/IOCInputForm';
import ProviderResultCard from '../components/Investigation/ProviderResultCard';
import RiskScoreMeter from '../components/Common/RiskScoreMeter';
import EvidenceTimeline from '../components/Investigation/EvidenceTimeline';
import RecommendationsCard from '../components/Investigation/RecommendationsCard';
import FactorBreakdownCard from '../components/Investigation/FactorBreakdownModal';

export default function Investigate() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleInvestigate = async (indicator, indicatorType) => {
    try {
      setLoading(true);
      setError(null);
      const data = await threatApi.investigateIOC(indicator, indicatorType);
      setResult(data);
    } catch (err) {
      console.error(err);
      if (err.response?.data?.detail) {
        const d = err.response.data.detail;
        setError(typeof d === 'object' ? d.message || JSON.stringify(d) : String(d));
      } else {
        setError('Failed to complete investigation. Please check input syntax and backend connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Input Form */}
      <IOCInputForm onInvestigate={handleInvestigate} loading={loading} error={error} />

      {/* Loading Skeleton */}
      {loading && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Skeleton variant="rounded" height={280} sx={{ bgcolor: '#0f172a' }} />
          </Grid>
          <Grid item xs={12} md={8}>
            <Skeleton variant="rounded" height={280} sx={{ bgcolor: '#0f172a' }} />
          </Grid>
        </Grid>
      )}

      {/* Active Scan Results */}
      {!loading && result && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Result Banner */}
          <Card
            sx={{
              bgcolor: '#0f172a',
              border: '1px solid rgba(0, 242, 254, 0.25)',
              boxShadow: '0 0 20px rgba(0, 242, 254, 0.08)',
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2, mb: 2 }}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 0.8 }}>
                    <Chip
                      size="small"
                      label={result.indicator_type.toUpperCase()}
                      sx={{
                        bgcolor: 'rgba(0, 242, 254, 0.1)',
                        color: '#00f2fe',
                        border: '1px solid rgba(0, 242, 254, 0.3)',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}
                    />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 800,
                        color: '#f8fafc',
                        fontFamily: "'JetBrains Mono', monospace",
                        wordBreak: 'break-all',
                      }}
                    >
                      {result.normalized_indicator}
                    </Typography>
                  </Box>
                  <Typography variant="caption" sx={{ color: '#64748b' }}>
                    Data Coverage: <strong style={{ color: '#94a3b8' }}>{result.data_coverage}</strong> • Queried at{' '}
                    {new Date(result.created_at).toLocaleString()}
                  </Typography>
                </Box>

                <Button
                  variant="outlined"
                  size="small"
                  endIcon={<ArrowRight size={14} />}
                  onClick={() => navigate(`/investigation/${result.id}`)}
                  sx={{ borderColor: 'rgba(255, 255, 255, 0.2)', color: '#f8fafc' }}
                >
                  View Permanent Archive
                </Button>
              </Box>

              {/* Verdict Summary Callout */}
              <Alert
                severity={result.severity === 'Critical' || result.severity === 'High' ? 'error' : result.severity === 'Medium' ? 'warning' : 'success'}
                sx={{
                  bgcolor: 'rgba(0, 0, 0, 0.25)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  color: '#f1f5f9',
                  '& .MuiAlert-icon': { mt: 0.2 },
                }}
              >
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {result.verdict_summary}
                </Typography>
              </Alert>
            </CardContent>
          </Card>

          {/* Score & Factor Overview */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <RiskScoreMeter
                score={result.risk_score}
                severity={result.severity}
                confidence={result.confidence}
              />
            </Grid>
            <Grid item xs={12} md={8}>
              <FactorBreakdownCard factorBreakdown={result.factor_breakdown} />
            </Grid>
          </Grid>

          {/* Provider Findings Cards */}
          <Box>
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 1.5 }}>
              Provider Intelligence Findings
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <ProviderResultCard
                  providerKey="virustotal"
                  result={result.provider_results?.virustotal}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <ProviderResultCard
                  providerKey="alienvault_otx"
                  result={result.provider_results?.alienvault_otx}
                />
              </Grid>
            </Grid>
          </Box>

          {/* Evidence Timeline */}
          <EvidenceTimeline evidence={result.evidence} />

          {/* Recommendations Card */}
          <RecommendationsCard recommendations={result.recommendations} severity={result.severity} />
        </Box>
      )}
    </Box>
  );
}
