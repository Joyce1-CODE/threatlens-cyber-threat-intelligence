import React from 'react';
import { Card, CardContent, Typography, Box, Chip, Divider, Tooltip } from '@mui/material';
import { ShieldCheck, AlertTriangle, ShieldAlert, KeyRound, Clock, ExternalLink } from 'lucide-react';

export default function ProviderResultCard({ providerKey, result }) {
  if (!result) return null;

  const isVT = providerKey === 'virustotal';
  const name = isVT ? 'VirusTotal v3' : 'AlienVault OTX';
  const status = result.status;
  const isMalicious = result.is_malicious;
  const detections = result.detections || 0;
  const total = result.total_engines || 0;
  const attrs = result.attributes || {};

  const isMissingKey = status === 'missing_key';
  const isRateLimited = status === 'rate_limited';
  const isNotFound = status === 'not_found';
  const isClean = status === 'clean' || (!isMalicious && !isMissingKey && !isNotFound);

  return (
    <Card
      sx={{
        bgcolor: '#0f172a',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <CardContent sx={{ p: 2.8, flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.2 }}>
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: 1.5,
                bgcolor: isVT ? 'rgba(59, 130, 246, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                color: isVT ? '#60a5fa' : '#c084fc',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: '0.85rem',
              }}
            >
              {isVT ? 'VT' : 'OTX'}
            </Box>
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#f8fafc', lineHeight: 1.2 }}>
                {name}
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748b' }}>
                {isVT ? 'Multi-Vendor Antivirus Consensus' : 'Community Threat Exchange Pulses'}
              </Typography>
            </Box>
          </Box>

          {/* Status Badge */}
          {isMissingKey ? (
            <Chip
              size="small"
              icon={<KeyRound size={12} />}
              label="Key Missing"
              sx={{ bgcolor: 'rgba(245, 158, 11, 0.12)', color: '#f59e0b', border: '1px solid rgba(245, 158, 11, 0.3)' }}
            />
          ) : isRateLimited ? (
            <Chip
              size="small"
              icon={<AlertTriangle size={12} />}
              label="Rate Limited"
              sx={{ bgcolor: 'rgba(249, 115, 22, 0.12)', color: '#f97316', border: '1px solid rgba(249, 115, 22, 0.3)' }}
            />
          ) : isMalicious ? (
            <Chip
              size="small"
              icon={<ShieldAlert size={12} />}
              label="Malicious"
              sx={{ bgcolor: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.4)' }}
            />
          ) : (
            <Chip
              size="small"
              icon={<ShieldCheck size={12} />}
              label={isNotFound ? "No Records" : "Clean"}
              sx={{ bgcolor: 'rgba(16, 185, 129, 0.12)', color: '#10b981', border: '1px solid rgba(16, 185, 129, 0.3)' }}
            />
          )}
        </Box>

        {/* Content Body */}
        {isMissingKey ? (
          <Box sx={{ p: 2, bgcolor: '#080c14', borderRadius: 2, border: '1px dashed rgba(245, 158, 11, 0.3)', my: 'auto' }}>
            <Typography variant="body2" sx={{ color: '#fbbf24', fontWeight: 600, mb: 0.5 }}>
              Provider Credentials Not Configured
            </Typography>
            <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block', mb: 1 }}>
              Add {isVT ? 'VIRUSTOTAL_API_KEY' : 'OTX_API_KEY'} in your .env file to enable live lookups.
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748b', fontStyle: 'italic' }}>
              Free API keys can be generated at {isVT ? 'virustotal.com' : 'otx.alienvault.com'}.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
            {/* Metric Banner */}
            <Box sx={{ p: 1.8, bgcolor: '#080c14', borderRadius: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                {isVT ? 'Malicious Vendor Engines' : 'Community Threat Pulses'}
              </Typography>
              <Typography variant="h6" sx={{ fontWeight: 800, color: isMalicious ? '#ef4444' : '#10b981' }}>
                {isVT ? `${detections} / ${total}` : `${detections} pulses`}
              </Typography>
            </Box>

            {/* Provider Summary */}
            <Typography variant="body2" sx={{ color: '#cbd5e1', fontSize: '0.85rem' }}>
              {result.summary}
            </Typography>

            {/* Provider Details & Attributes */}
            {isVT && attrs.flagged_engines && attrs.flagged_engines.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  FLAGGED ENGINES ({attrs.flagged_engines.length}):
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.flagged_engines.map((e, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={`${e.engine}: ${e.result || 'malicious'}`}
                      sx={{ bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', fontSize: '0.7rem' }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {!isVT && attrs.malware_families && attrs.malware_families.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  ASSOCIATED MALWARE FAMILIES:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.malware_families.map((mf, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={mf}
                      sx={{ bgcolor: 'rgba(168, 85, 247, 0.15)', color: '#d8b4fe', fontSize: '0.72rem', fontWeight: 600 }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {!isVT && attrs.adversaries && attrs.adversaries.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  ATTRIBUTED ADVERSARIES:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.adversaries.map((adv, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={adv}
                      sx={{ bgcolor: 'rgba(249, 115, 22, 0.15)', color: '#fdba74', fontSize: '0.72rem', fontWeight: 600 }}
                    />
                  ))}
                </Box>
              </Box>
            )}
          </Box>
        )}

        {/* Footer Timestamp */}
        <Divider sx={{ my: 1.5, borderColor: 'rgba(255, 255, 255, 0.06)' }} />
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#64748b', fontSize: '0.75rem' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Clock size={12} />
            <span>{result.queried_at ? new Date(result.queried_at).toLocaleTimeString() : 'N/A'}</span>
          </Box>
          <span>Passive Lookup</span>
        </Box>
      </CardContent>
    </Card>
  );
}
