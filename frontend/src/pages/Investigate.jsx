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
  Alert,
  Skeleton,
} from '@mui/material';
import { ArrowRight, Download } from 'lucide-react';

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
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const handleDownloadPDF = async () => {
    if (!result) return;
    try {
      setDownloadingPdf(true);
      const safeInd = result.normalized_indicator.replace(/[^a-zA-Z0-9_\-\.]/g, '_').slice(0, 30);
      await threatApi.downloadReportPDF(result.id, `ThreatLens_Report_${result.id.slice(0, 8)}_${safeInd}.pdf`);
    } catch (err) {
      console.error(err);
      alert('Failed to generate PDF report.');
    } finally {
      setDownloadingPdf(false);
    }
  };

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
            <Skeleton variant="rounded" height={280} sx={{ bgcolor: '#E2E8F0' }} />
          </Grid>
          <Grid item xs={12} md={8}>
            <Skeleton variant="rounded" height={280} sx={{ bgcolor: '#E2E8F0' }} />
          </Grid>
        </Grid>
      )}

      {/* Active Scan Results */}
      {!loading && result && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Result Banner */}
          <Card
            sx={{
              bgcolor: '#FFFFFF',
              border: '1px solid #DCE4EE',
              boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)',
              borderRadius: 2.5,
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
                        bgcolor: 'rgba(8, 145, 178, 0.08)',
                        color: '#0891B2',
                        border: '1px solid rgba(8, 145, 178, 0.25)',
                        fontWeight: 700,
                        fontSize: '0.75rem',
                      }}
                    />
                    <Typography
                      variant="h5"
                      sx={{
                        fontWeight: 800,
                        color: '#172B4D',
                        fontFamily: "'JetBrains Mono', monospace",
                        wordBreak: 'break-all',
                      }}
                    >
                      {result.normalized_indicator}
                    </Typography>
                  </Box>
                  <Typography variant="caption" sx={{ color: '#64748B' }}>
                    Data Coverage: <strong style={{ color: '#172B4D' }}>{result.data_coverage}</strong> • Queried at{' '}
                    {new Date(result.created_at).toLocaleString()}
                  </Typography>
                </Box>

                <Box sx={{ display: 'flex', gap: 1.5 }}>
                  <Button
                    variant="contained"
                    size="small"
                    disabled={downloadingPdf}
                    startIcon={<Download size={14} />}
                    onClick={handleDownloadPDF}
                    sx={{
                      px: 2,
                      bgcolor: '#0891B2',
                      color: '#FFFFFF',
                      '&:hover': { bgcolor: '#0E7490' },
                    }}
                  >
                    {downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    endIcon={<ArrowRight size={14} />}
                    onClick={() => navigate(`/investigation/${result.id}`)}
                    sx={{
                      borderColor: '#DCE4EE',
                      color: '#172B4D',
                      '&:hover': { borderColor: '#0891B2', color: '#0891B2' },
                    }}
                  >
                    View Details
                  </Button>
                </Box>
              </Box>

              {/* Verdict Summary Callout */}
              <Alert
                severity={
                  result.severity === 'Critical' || result.severity === 'High'
                    ? 'error'
                    : result.severity === 'Medium'
                    ? 'warning'
                    : result.severity === 'Unknown' || result.severity === 'Unverified' || result.confidence === 'None'
                    ? 'info'
                    : 'success'
                }
                sx={{
                  border: '1px solid #DCE4EE',
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
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 1.5 }}>
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
