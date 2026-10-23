import React from 'react';
import { Card, CardContent, Typography, Box, Chip, Divider } from '@mui/material';
import { ShieldAlert, ShieldCheck, AlertTriangle, KeyRound, Clock } from 'lucide-react';

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
        bgcolor: '#FFFFFF',
        border: '1px solid #DCE4EE',
        boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)',
        borderRadius: 2.5,
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
                width: 34,
                height: 34,
                borderRadius: 1.5,
                bgcolor: isVT ? 'rgba(8, 145, 178, 0.1)' : 'rgba(79, 70, 229, 0.1)',
                color: isVT ? '#0891B2' : '#4F46E5',
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
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#172B4D', lineHeight: 1.2 }}>
                {name}
              </Typography>
              <Typography variant="caption" sx={{ color: '#64748B' }}>
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
              sx={{ bgcolor: 'rgba(217, 119, 6, 0.08)', color: '#D97706', border: '1px solid rgba(217, 119, 6, 0.25)', fontWeight: 600 }}
            />
          ) : isRateLimited ? (
            <Chip
              size="small"
              icon={<AlertTriangle size={12} />}
              label="Rate Limited"
              sx={{ bgcolor: 'rgba(234, 88, 12, 0.08)', color: '#EA580C', border: '1px solid rgba(234, 88, 12, 0.25)', fontWeight: 600 }}
            />
          ) : isMalicious ? (
            <Chip
              size="small"
              icon={<ShieldAlert size={12} />}
              label="Malicious"
              sx={{ bgcolor: 'rgba(220, 38, 38, 0.08)', color: '#DC2626', border: '1px solid rgba(220, 38, 38, 0.25)', fontWeight: 600 }}
            />
          ) : (
            <Chip
              size="small"
              icon={<ShieldCheck size={12} />}
              label={isNotFound ? "No Records" : "Clean"}
              sx={{ bgcolor: 'rgba(22, 163, 74, 0.08)', color: '#16A34A', border: '1px solid rgba(22, 163, 74, 0.25)', fontWeight: 600 }}
            />
          )}
        </Box>

        {/* Content Body */}
        {isMissingKey ? (
          <Box sx={{ p: 2, bgcolor: '#F8FAFC', borderRadius: 2, border: '1px dashed #D97706', my: 'auto' }}>
            <Typography variant="body2" sx={{ color: '#D97706', fontWeight: 600, mb: 0.5 }}>
              Provider Credentials Not Configured
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748B', display: 'block', mb: 1 }}>
              Add {isVT ? 'VIRUSTOTAL_API_KEY' : 'OTX_API_KEY'} in your .env file to enable live lookups.
            </Typography>
            <Typography variant="caption" sx={{ color: '#64748B', fontStyle: 'italic' }}>
              Free API keys can be generated at {isVT ? 'virustotal.com' : 'otx.alienvault.com'}.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
            {/* Metric Banner */}
            <Box sx={{ p: 1.8, bgcolor: '#F8FAFC', border: '1px solid #DCE4EE', borderRadius: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Typography variant="body2" sx={{ color: '#64748B', fontWeight: 500 }}>
                {isVT ? 'Malicious Vendor Engines' : 'Community Threat Pulses'}
              </Typography>
              <Typography variant="h6" sx={{ fontWeight: 800, color: isMalicious ? '#DC2626' : '#16A34A' }}>
                {isVT ? `${detections} / ${total}` : `${detections} pulses`}
              </Typography>
            </Box>

            {/* Provider Summary */}
            <Typography variant="body2" sx={{ color: '#172B4D', fontSize: '0.85rem', lineHeight: 1.5 }}>
              {result.summary}
            </Typography>

            {/* Provider Details & Attributes */}
            {isVT && attrs.flagged_engines && attrs.flagged_engines.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  FLAGGED ENGINES ({attrs.flagged_engines.length}):
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.flagged_engines.map((e, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={`${e.engine}: ${e.result || 'malicious'}`}
                      sx={{ bgcolor: 'rgba(220, 38, 38, 0.08)', color: '#DC2626', border: '1px solid rgba(220, 38, 38, 0.2)', fontSize: '0.7rem' }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {!isVT && attrs.malware_families && attrs.malware_families.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  ASSOCIATED MALWARE FAMILIES:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.malware_families.map((mf, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={mf}
                      sx={{ bgcolor: 'rgba(79, 70, 229, 0.08)', color: '#4F46E5', border: '1px solid rgba(79, 70, 229, 0.2)', fontSize: '0.72rem', fontWeight: 600 }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {!isVT && attrs.adversaries && attrs.adversaries.length > 0 && (
              <Box>
                <Typography variant="caption" sx={{ color: '#64748B', fontWeight: 700, mb: 0.8, display: 'block' }}>
                  ATTRIBUTED ADVERSARIES:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.6 }}>
                  {attrs.adversaries.map((adv, idx) => (
                    <Chip
                      key={idx}
                      size="small"
                      label={adv}
                      sx={{ bgcolor: 'rgba(234, 88, 12, 0.08)', color: '#EA580C', border: '1px solid rgba(234, 88, 12, 0.2)', fontSize: '0.72rem', fontWeight: 600 }}
                    />
                  ))}
                </Box>
              </Box>
            )}
          </Box>
        )}

        {/* Footer Timestamp */}
        <Divider sx={{ my: 1.5, borderColor: '#DCE4EE' }} />
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#64748B', fontSize: '0.75rem' }}>
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
