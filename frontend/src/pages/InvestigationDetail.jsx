import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
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
  CircularProgress,
} from '@mui/material';
import { ArrowLeft, Download } from 'lucide-react';

import { threatApi } from '../api/client';
import RiskScoreMeter from '../components/Common/RiskScoreMeter';
import ProviderResultCard from '../components/Investigation/ProviderResultCard';
import EvidenceTimeline from '../components/Investigation/EvidenceTimeline';
import RecommendationsCard from '../components/Investigation/RecommendationsCard';
import FactorBreakdownCard from '../components/Investigation/FactorBreakdownModal';

export default function InvestigationDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDetail();
  }, [id]);

  const fetchDetail = async () => {
    try {
      setLoading(true);
      const res = await threatApi.getInvestigationById(id);
      setData(res);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Unable to load investigation record. It may have been deleted or the ID is invalid.');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadPDF = async () => {
    if (!data) return;
    try {
      setDownloadingPdf(true);
      const safeInd = data.normalized_indicator.replace(/[^a-zA-Z0-9_\-\.]/g, '_').slice(0, 30);
      await threatApi.downloadReportPDF(data.id, `ThreatLens_Report_${data.id.slice(0, 8)}_${safeInd}.pdf`);
    } catch (err) {
      console.error(err);
      alert('Failed to generate PDF report.');
    } finally {
      setDownloadingPdf(false);
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <Skeleton variant="rounded" height={60} sx={{ bgcolor: '#E2E8F0' }} />
        <Skeleton variant="rounded" height={220} sx={{ bgcolor: '#E2E8F0' }} />
        <Skeleton variant="rounded" height={300} sx={{ bgcolor: '#E2E8F0' }} />
      </Box>
    );
  }

  if (error || !data) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
        <Button
          startIcon={<ArrowLeft size={16} />}
          onClick={() => navigate('/history')}
          sx={{ alignSelf: 'flex-start', color: '#64748B', '&:hover': { color: '#0891B2' } }}
        >
          Back to History
        </Button>
        <Alert severity="error">{error || 'Investigation not found.'}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Top Action Bar */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Button
          startIcon={<ArrowLeft size={16} />}
          onClick={() => navigate('/history')}
          sx={{ color: '#64748B', '&:hover': { color: '#0891B2' } }}
        >
          Back to History
        </Button>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="caption" sx={{ color: '#64748B', fontFamily: "'JetBrains Mono', monospace" }}>
            ARCHIVE ID: {data.id}
          </Typography>

          <Button
            variant="contained"
            disabled={downloadingPdf}
            startIcon={downloadingPdf ? <CircularProgress size={16} color="inherit" /> : <Download size={16} />}
            onClick={handleDownloadPDF}
            sx={{
              px: 2.5,
              bgcolor: '#0891B2',
              color: '#FFFFFF',
              '&:hover': { bgcolor: '#0E7490' },
            }}
          >
            {downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}
          </Button>
        </Box>
      </Box>

      {/* Main IOC Banner */}
      <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
        <CardContent sx={{ p: 3.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <Chip
              size="small"
              label={data.indicator_type.toUpperCase()}
              sx={{
                bgcolor: 'rgba(8, 145, 178, 0.08)',
                color: '#0891B2',
                border: '1px solid rgba(8, 145, 178, 0.25)',
                fontWeight: 700,
              }}
            />
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                color: '#172B4D',
                fontFamily: "'JetBrains Mono', monospace",
                wordBreak: 'break-all',
              }}
            >
              {data.normalized_indicator}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap', mt: 1.5 }}>
            <Typography variant="caption" sx={{ color: '#64748B' }}>
              Original Input: <code style={{ color: '#172B4D', background: '#F1F5F9', padding: '2px 6px', borderRadius: 4 }}>{data.indicator}</code>
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748B' }}>
              Data Coverage: <strong style={{ color: '#172B4D' }}>{data.data_coverage}</strong>
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748B' }}>
              Archived: {new Date(data.created_at).toLocaleString()}
            </Typography>
          </Box>

          <Alert
            severity={
              data.severity === 'Critical' || data.severity === 'High'
                ? 'error'
                : data.severity === 'Medium'
                ? 'warning'
                : data.severity === 'Unknown' || data.severity === 'Unverified' || data.confidence === 'None'
                ? 'info'
                : 'success'
            }
            sx={{
              mt: 2.5,
              border: '1px solid #DCE4EE',
            }}
          >
            <Typography variant="body2" sx={{ fontWeight: 600 }}>
              {data.verdict_summary}
            </Typography>
          </Alert>
        </CardContent>
      </Card>

      {/* Score and Factor Overview */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <RiskScoreMeter
            score={data.risk_score}
            severity={data.severity}
            confidence={data.confidence}
          />
        </Grid>
        <Grid item xs={12} md={8}>
          <FactorBreakdownCard factorBreakdown={data.factor_breakdown} />
        </Grid>
      </Grid>

      {/* Provider Details */}
      <Box>
        <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 1.5 }}>
          Threat Intelligence Sources
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <ProviderResultCard
              providerKey="virustotal"
              result={data.provider_results?.virustotal}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <ProviderResultCard
              providerKey="alienvault_otx"
              result={data.provider_results?.alienvault_otx}
            />
          </Grid>
        </Grid>
      </Box>

      {/* Evidence Signals */}
      <EvidenceTimeline evidence={data.evidence} />

      {/* Remediation Checklist */}
      <RecommendationsCard recommendations={data.recommendations} severity={data.severity} />
    </Box>
  );
}
