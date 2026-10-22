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
  Divider,
} from '@mui/material';
import { ArrowLeft, Clock, ShieldAlert, Layers, Hash } from 'lucide-react';

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

  if (loading) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <Skeleton variant="rounded" height={60} />
        <Skeleton variant="rounded" height={220} />
        <Skeleton variant="rounded" height={300} />
      </Box>
    );
  }

  if (error || !data) {
    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
        <Button
          startIcon={<ArrowLeft size={16} />}
          onClick={() => navigate('/history')}
          sx={{ alignSelf: 'flex-start', color: '#94a3b8' }}
        >
          Back to History
        </Button>
        <Alert severity="error">{error || 'Investigation not found.'}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Back button and Record Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Button
          startIcon={<ArrowLeft size={16} />}
          onClick={() => navigate('/history')}
          sx={{ color: '#94a3b8', '&:hover': { color: '#00f2fe' } }}
        >
          Back to History
        </Button>
        <Typography variant="caption" sx={{ color: '#64748b', fontFamily: "'JetBrains Mono', monospace" }}>
          ARCHIVE ID: {data.id}
        </Typography>
      </Box>

      {/* Main IOC Banner */}
      <Card sx={{ bgcolor: '#0f172a', border: '1px solid rgba(0, 242, 254, 0.25)' }}>
        <CardContent sx={{ p: 3.5 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
            <Chip
              size="small"
              label={data.indicator_type.toUpperCase()}
              sx={{
                bgcolor: 'rgba(0, 242, 254, 0.1)',
                color: '#00f2fe',
                border: '1px solid rgba(0, 242, 254, 0.3)',
                fontWeight: 700,
              }}
            />
            <Typography
              variant="h4"
              sx={{
                fontWeight: 800,
                color: '#f8fafc',
                fontFamily: "'JetBrains Mono', monospace",
                wordBreak: 'break-all',
              }}
            >
              {data.normalized_indicator}
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap', mt: 1.5 }}>
            <Typography variant="caption" sx={{ color: '#64748b' }}>
              Original Input: <code style={{ color: '#94a3b8' }}>{data.indicator}</code>
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748b' }}>
              Data Coverage: <strong style={{ color: '#f1f5f9' }}>{data.data_coverage}</strong>
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748b' }}>
              Archived: {new Date(data.created_at).toLocaleString()}
            </Typography>
          </Box>

          <Alert
            severity={data.severity === 'Critical' || data.severity === 'High' ? 'error' : data.severity === 'Medium' ? 'warning' : 'success'}
            sx={{
              mt: 2.5,
              bgcolor: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              color: '#f1f5f9',
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
        <Typography variant="h6" sx={{ fontWeight: 700, color: '#f8fafc', mb: 1.5 }}>
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
