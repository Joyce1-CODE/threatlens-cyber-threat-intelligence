import React from 'react';
import { Card, CardContent, Typography, Box, Divider, Grid } from '@mui/material';
import { Calculator } from 'lucide-react';

export default function FactorBreakdownCard({ factorBreakdown = {} }) {
  const {
    virustotal_weight = 0.6,
    virustotal_score = 0,
    alienvault_weight = 0.4,
    alienvault_score = 0,
    synergy_boost = 0,
    final_score = 0,
  } = factorBreakdown;

  return (
    <Card sx={{ bgcolor: '#0c1322', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
      <CardContent sx={{ p: 2.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
          <Calculator size={16} color="#00f2fe" />
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#f8fafc' }}>
            ThreatLens AI Heuristic Scoring Breakdown
          </Typography>
        </Box>
        <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block', mb: 2 }}>
          Deterministic formula combining multi-engine vendor consensus and community pulse corroboration.
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, p: 1.8, bgcolor: '#080c14', borderRadius: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="caption" sx={{ color: '#94a3b8' }}>
              VirusTotal Factor (Score: {virustotal_score} × {Math.round(virustotal_weight * 100)}% weight)
            </Typography>
            <Typography variant="caption" sx={{ color: '#f8fafc', fontWeight: 600 }}>
              +{(virustotal_score * virustotal_weight).toFixed(1)} pts
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="caption" sx={{ color: '#94a3b8' }}>
              AlienVault OTX Factor (Score: {alienvault_score} × {Math.round(alienvault_weight * 100)}% weight)
            </Typography>
            <Typography variant="caption" sx={{ color: '#f8fafc', fontWeight: 600 }}>
              +{(alienvault_score * alienvault_weight).toFixed(1)} pts
            </Typography>
          </Box>

          {synergy_boost > 0 && (
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="caption" sx={{ color: '#38bdf8' }}>
                Cross-Platform Synergy Bonus (Independent dual-detection)
              </Typography>
              <Typography variant="caption" sx={{ color: '#38bdf8', fontWeight: 700 }}>
                +{synergy_boost.toFixed(1)} pts
              </Typography>
            </Box>
          )}

          <Divider sx={{ my: 0.5, borderColor: 'rgba(255, 255, 255, 0.08)' }} />

          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="body2" sx={{ color: '#f1f5f9', fontWeight: 700 }}>
              Calculated Overall Risk Score
            </Typography>
            <Typography variant="body2" sx={{ color: '#00f2fe', fontWeight: 800 }}>
              {final_score} / 100
            </Typography>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}
