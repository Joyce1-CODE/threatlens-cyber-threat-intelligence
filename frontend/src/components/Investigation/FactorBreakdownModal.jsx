import React from 'react';
import { Card, CardContent, Typography, Box, Divider } from '@mui/material';
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
    <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5, height: '100%' }}>
      <CardContent sx={{ p: 2.8, display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.8 }}>
            <Calculator size={18} color="#0891B2" />
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#172B4D' }}>
              ThreatLens AI Heuristic Scoring Breakdown
            </Typography>
          </Box>
          <Typography variant="caption" sx={{ color: '#64748B', display: 'block', mb: 2 }}>
            Deterministic formula combining multi-engine vendor consensus and community pulse corroboration.
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.2, p: 2, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 500 }}>
              VirusTotal Factor (Score: {virustotal_score} × {Math.round(virustotal_weight * 100)}% weight)
            </Typography>
            <Typography variant="caption" sx={{ color: '#172B4D', fontWeight: 700 }}>
              +{(virustotal_score * virustotal_weight).toFixed(1)} pts
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 500 }}>
              AlienVault OTX Factor (Score: {alienvault_score} × {Math.round(alienvault_weight * 100)}% weight)
            </Typography>
            <Typography variant="caption" sx={{ color: '#172B4D', fontWeight: 700 }}>
              +{(alienvault_score * alienvault_weight).toFixed(1)} pts
            </Typography>
          </Box>

          {synergy_boost > 0 && (
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="caption" sx={{ color: '#0891B2', fontWeight: 600 }}>
                Cross-Platform Synergy Bonus (Independent dual-detection)
              </Typography>
              <Typography variant="caption" sx={{ color: '#0891B2', fontWeight: 700 }}>
                +{synergy_boost.toFixed(1)} pts
              </Typography>
            </Box>
          )}

          <Divider sx={{ my: 0.5, borderColor: '#DCE4EE' }} />

          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="body2" sx={{ color: '#172B4D', fontWeight: 700 }}>
              Calculated Overall Risk Score
            </Typography>
            <Typography variant="body2" sx={{ color: '#0891B2', fontWeight: 800, fontSize: '1rem' }}>
              {final_score} / 100
            </Typography>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}
