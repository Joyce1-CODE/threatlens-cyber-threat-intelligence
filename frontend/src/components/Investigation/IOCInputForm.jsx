import React, { useState } from 'react';
import {
  Card,
  CardContent,
  TextField,
  Button,
  Box,
  Typography,
  MenuItem,
  Chip,
  CircularProgress,
  Alert,
} from '@mui/material';
import { Search, ShieldAlert, Sparkles } from 'lucide-react';

const sampleIOCs = [
  { label: '8.8.8.8 (Clean IPv4)', value: '8.8.8.8', type: 'ipv4' },
  { label: 'evil[.]c2-beacon.ru (Defanged Domain)', value: 'evil[.]c2-beacon.ru', type: 'domain' },
  { label: 'hxxps://phish-login[.]xyz/auth (URL)', value: 'hxxps://phish-login[.]xyz/auth', type: 'url' },
  { label: '44d88612... (EICAR MD5)', value: '44d88612fea8a8f36de82e1278abb02f', type: 'md5' },
  { label: '2001:db8::8a2e:370:7334 (IPv6)', value: '2001:db8::8a2e:370:7334', type: 'ipv6' },
];

export default function IOCInputForm({ onInvestigate, loading, error }) {
  const [indicator, setIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState('auto');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!indicator.trim()) return;
    onInvestigate(indicator.trim(), indicatorType);
  };

  const handleSelectSample = (sample) => {
    setIndicator(sample.value);
    setIndicatorType(sample.type);
  };

  return (
    <Card
      sx={{
        bgcolor: '#0f172a',
        border: '1px solid rgba(0, 242, 254, 0.2)',
        boxShadow: '0 4px 24px rgba(0, 0, 0, 0.4)',
      }}
    >
      <CardContent sx={{ p: { xs: 2.5, md: 3.5 } }}>
        <Box sx={{ mb: 2.5 }}>
          <Typography variant="h5" sx={{ fontWeight: 700, color: '#f8fafc', mb: 0.5 }}>
            Investigate Indicator of Compromise (IOC)
          </Typography>
          <Typography variant="body2" sx={{ color: '#94a3b8' }}>
            Passively query VirusTotal v3 and AlienVault OTX. Supports IPv4, IPv6, Domain, URL, MD5, SHA-1, and SHA-256.
          </Typography>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2.5, bgcolor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5' }}>
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={handleSubmit}>
          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', md: 'row' }, gap: 1.5, mb: 2.5 }}>
            <TextField
              fullWidth
              placeholder="e.g. 198.51.100.1, evil-domain[.]com, hxxps://..., or SHA256 hash"
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              disabled={loading}
              sx={{
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#080c14',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.95rem',
                  '& fieldset': { borderColor: 'rgba(255, 255, 255, 0.12)' },
                  '&:hover fieldset': { borderColor: '#00f2fe' },
                  '&.Mui-focused fieldset': { borderColor: '#00f2fe' },
                },
              }}
            />

            <TextField
              select
              value={indicatorType}
              onChange={(e) => setIndicatorType(e.target.value)}
              disabled={loading}
              sx={{
                minWidth: { md: 170 },
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#080c14',
                  '& fieldset': { borderColor: 'rgba(255, 255, 255, 0.12)' },
                },
              }}
            >
              <MenuItem value="auto">Auto-Detect Type</MenuItem>
              <MenuItem value="ipv4">IPv4 Address</MenuItem>
              <MenuItem value="ipv6">IPv6 Address</MenuItem>
              <MenuItem value="domain">Domain Name</MenuItem>
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="md5">MD5 Hash</MenuItem>
              <MenuItem value="sha1">SHA-1 Hash</MenuItem>
              <MenuItem value="sha256">SHA-256 Hash</MenuItem>
            </TextField>

            <Button
              type="submit"
              variant="contained"
              disabled={loading || !indicator.trim()}
              startIcon={loading ? <CircularProgress size={18} color="inherit" /> : <Search size={18} />}
              sx={{ px: 3.5, py: { xs: 1.2, md: 'auto' }, whiteSpace: 'nowrap' }}
            >
              {loading ? 'Analyzing...' : 'Investigate IOC'}
            </Button>
          </Box>

          {/* Sample IOCs for easy testing / demo */}
          <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
            <Typography variant="caption" sx={{ color: '#64748b', fontWeight: 600, mr: 0.5 }}>
              Sample IOCs for testing:
            </Typography>
            {sampleIOCs.map((s, idx) => (
              <Chip
                key={idx}
                label={s.label}
                size="small"
                onClick={() => handleSelectSample(s)}
                disabled={loading}
                sx={{
                  bgcolor: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  color: '#94a3b8',
                  fontSize: '0.72rem',
                  fontFamily: "'JetBrains Mono', monospace",
                  cursor: 'pointer',
                  '&:hover': {
                    bgcolor: 'rgba(0, 242, 254, 0.1)',
                    borderColor: 'rgba(0, 242, 254, 0.3)',
                    color: '#00f2fe',
                  },
                }}
              />
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}
