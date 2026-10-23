import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  Alert,
  Tooltip,
} from '@mui/material';
import {
  UploadCloud,
  Download,
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Eye,
  RefreshCw,
  Sparkles,
} from 'lucide-react';

import { threatApi } from '../api/client';
import { useAuth } from '../contexts/AuthContext';
import { ShieldAlert } from 'lucide-react';
import SeverityBadge from '../components/Common/SeverityBadge';
import StatCard from '../components/Common/StatCard';

const SAMPLE_CSV = `indicator,source,notes
8.8.8.8,DNS,Google Public DNS
1.1.1.1,DNS,Cloudflare Resolver
evil[.]c2-beacon.ru,Telemetry,Defanged domain
hxxps://phish-secure-portal[.]xyz/login,Email,Phishing lure
44d88612fea8a8f36de82e1278abb02f,File,EICAR Standard Test Hash
8.8.8.8,Duplicate,Duplicate entry to test deduplication
not_a_valid_indicator...,Malformed,Syntax error demonstration
`;

export default function BulkTriage() {
  const { isReadOnly } = useAuth();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [preview, setPreview] = useState(null);
  const [selectedColumn, setSelectedColumn] = useState('');
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [triaging, setTriaging] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [filterSeverity, setFilterSeverity] = useState('all');

  const handleFileUpload = async (uploadedFile) => {
    if (!uploadedFile) return;
    try {
      setLoadingPreview(true);
      setError(null);
      setResults(null);
      setFile(uploadedFile);

      const previewData = await threatApi.previewBulkCSV(uploadedFile);
      setPreview(previewData);
      setSelectedColumn(previewData.detected_column);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to parse CSV file. Ensure valid CSV formatting.');
      setPreview(null);
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleDownloadSampleCSV = () => {
    const blob = new Blob([SAMPLE_CSV], { type: 'text/csv;charset=utf-8;' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'ThreatLens_Sample_IOCs.csv');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handleLoadSampleDemo = () => {
    const sampleBlob = new Blob([SAMPLE_CSV], { type: 'text/csv' });
    const sampleFile = new File([sampleBlob], 'ThreatLens_Sample_IOCs.csv', { type: 'text/csv' });
    handleFileUpload(sampleFile);
  };

  const handleStartTriage = async () => {
    if (!preview || !preview.items) return;

    // Filter valid unique items (cap at 50)
    const validItems = preview.items
      .filter((it) => it.is_valid && !it.is_duplicate && !it.is_exceeded)
      .slice(0, 50)
      .map((it) => ({
        indicator: it.original,
        indicator_type: it.type === 'unknown' ? 'auto' : it.type,
      }));

    if (validItems.length === 0) {
      setError('No valid indicators available to triage.');
      return;
    }

    try {
      setTriaging(true);
      setError(null);
      const triageData = await threatApi.executeBulkTriage(validItems);
      setResults(triageData);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Batch triage failed. Check network or server connection.');
    } finally {
      setTriaging(false);
    }
  };

  const handleExportCSV = async () => {
    if (!results || !results.results) return;
    try {
      await threatApi.exportBulkCSV(results.results);
    } catch (err) {
      alert('Failed to export CSV results.');
    }
  };

  const filteredResults = results?.results
    ? results.results.filter((r) => {
        if (filterSeverity === 'threats') return r.severity === 'Critical' || r.severity === 'High';
        if (filterSeverity === 'clean') return r.severity === 'Low';
        if (filterSeverity === 'invalid') return r.status === 'invalid';
        return true;
      })
    : [];

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3.5 }}>
      {/* Page Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, color: '#172B4D', mb: 0.5 }}>
            Bulk IOC Triage & CSV Analysis
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748B' }}>
            Batch correlate up to 50 indicators across VirusTotal v3 and AlienVault OTX feeds with automated deduplication.
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<Download size={15} />}
            onClick={handleDownloadSampleCSV}
            sx={{
              borderColor: '#DCE4EE',
              color: '#172B4D',
              '&:hover': { borderColor: '#0891B2', color: '#0891B2' },
            }}
          >
            Sample Template
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<Sparkles size={15} />}
            onClick={handleLoadSampleDemo}
            sx={{
              borderColor: '#0891B2',
              color: '#0891B2',
              '&:hover': { bgcolor: 'rgba(8, 145, 178, 0.06)' },
            }}
          >
            Load Demo Batch
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ bgcolor: 'rgba(220, 38, 38, 0.08)', color: '#DC2626', border: '1px solid rgba(220, 38, 38, 0.2)' }}>
          {error}
        </Alert>
      )}

      {/* Upload Box */}
      <Card
        sx={{
          bgcolor: '#FFFFFF',
          border: '1px dashed #CBD5E1',
          boxShadow: '0 1px 3px rgba(15, 23, 42, 0.03)',
          cursor: 'pointer',
          borderRadius: 2.5,
          transition: 'all 0.2s ease',
          '&:hover': { borderColor: '#0891B2', bgcolor: '#F8FAFC' },
        }}
        onClick={() => fileInputRef.current?.click()}
      >
        <CardContent sx={{ p: 4, textAlign: 'center' }}>
          <input
            type="file"
            ref={fileInputRef}
            accept=".csv,.txt"
            style={{ display: 'none' }}
            onChange={(e) => handleFileUpload(e.target.files[0])}
          />

          <Box
            sx={{
              width: 52,
              height: 52,
              borderRadius: '50%',
              bgcolor: 'rgba(8, 145, 178, 0.08)',
              color: '#0891B2',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              mx: 'auto',
              mb: 1.5,
            }}
          >
            <UploadCloud size={26} />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D', mb: 0.5 }}>
            {file ? file.name : 'Upload Indicators CSV File'}
          </Typography>
          <Typography variant="body2" sx={{ color: '#64748B', mb: 2 }}>
            Drag & drop or click to browse. Supports standard CSV with IP, domain, URL, or hash columns.
          </Typography>

          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 1.5, flexWrap: 'wrap' }}>
            <Chip size="small" label="Max 50 Indicators" sx={{ bgcolor: '#F1F5F9', color: '#64748B', border: '1px solid #DCE4EE' }} />
            <Chip size="small" label="Auto-Deduplication" sx={{ bgcolor: '#F1F5F9', color: '#64748B', border: '1px solid #DCE4EE' }} />
            <Chip size="small" label="Defanging Parsing" sx={{ bgcolor: '#F1F5F9', color: '#64748B', border: '1px solid #DCE4EE' }} />
          </Box>
        </CardContent>
      </Card>

      {/* Pre-Flight Preview */}
      {preview && !results && (
        <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
          <CardContent sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2, mb: 2.5 }}>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
                  Pre-Flight Batch Validation ({preview.total_rows} rows parsed)
                </Typography>
                <Typography variant="caption" sx={{ color: '#64748B' }}>
                  Review parsed indicators and duplicate counts before initiating external threat queries.
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Button
                  variant="contained"
                  disabled={triaging || preview.valid_count === 0 || isReadOnly}
                  startIcon={triaging ? <RefreshCw size={16} className="spin" /> : <Play size={16} />}
                  onClick={handleStartTriage}
                  sx={{
                    px: 3,
                    py: 1,
                    bgcolor: '#0891B2',
                    color: '#FFFFFF',
                    '&:hover': { bgcolor: '#0E7490' },
                  }}
                >
                  {triaging ? 'Executing Triage...' : `Start Batch Triage (${preview.valid_count} IOCs)`}
                </Button>
              </Box>
            </Box>

            {/* Validation Breakdown Chips */}
            <Box sx={{ display: 'flex', gap: 1.5, flexWrap: 'wrap', mb: 3 }}>
              <Chip
                icon={<CheckCircle2 size={14} />}
                label={`${preview.valid_count} Valid Unique IOCs`}
                sx={{ bgcolor: 'rgba(22, 163, 74, 0.08)', color: '#16A34A', border: '1px solid rgba(22, 163, 74, 0.25)', fontWeight: 600 }}
              />
              {preview.duplicate_count > 0 && (
                <Chip
                  icon={<AlertTriangle size={14} />}
                  label={`${preview.duplicate_count} Duplicates (Auto-Skipped)`}
                  sx={{ bgcolor: 'rgba(217, 119, 6, 0.08)', color: '#D97706', border: '1px solid rgba(217, 119, 6, 0.25)', fontWeight: 600 }}
                />
              )}
              {preview.invalid_count > 0 && (
                <Chip
                  icon={<XCircle size={14} />}
                  label={`${preview.invalid_count} Syntax Errors`}
                  sx={{ bgcolor: 'rgba(220, 38, 38, 0.08)', color: '#DC2626', border: '1px solid rgba(220, 38, 38, 0.25)', fontWeight: 600 }}
                />
              )}
              {preview.truncated_count > 0 && (
                <Chip
                  label={`${preview.truncated_count} Exceeded 50 Limit (Omitted)`}
                  sx={{ bgcolor: '#F1F5F9', color: '#64748B', border: '1px solid #DCE4EE' }}
                />
              )}
            </Box>

            {triaging && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="body2" sx={{ color: '#0891B2', fontWeight: 600, mb: 1 }}>
                  Running concurrent bounded queries (Worker Pool: 4 workers)...
                </Typography>
                <LinearProgress sx={{ height: 6, borderRadius: 3, bgcolor: '#E2E8F0', '& .MuiLinearProgress-bar': { bgcolor: '#0891B2' } }} />
              </Box>
            )}

            {/* Preview Table */}
            <TableContainer sx={{ maxHeight: 340, border: '1px solid #DCE4EE', borderRadius: 2 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow sx={{ bgcolor: '#F8FAFC' }}>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>ROW</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>ORIGINAL VALUE</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>NORMALIZED</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>TYPE</TableCell>
                    <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>PRE-FLIGHT STATUS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {preview.items.slice(0, 30).map((it, idx) => (
                    <TableRow key={idx} hover sx={{ '&:hover': { bgcolor: '#F8FAFC' } }}>
                      <TableCell sx={{ color: '#64748B', fontSize: '0.75rem' }}>#{it.row_number}</TableCell>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#172B4D' }}>{it.original}</TableCell>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", color: '#64748B' }}>{it.normalized}</TableCell>
                      <TableCell>
                        <Chip size="small" label={it.type.toUpperCase()} sx={{ fontSize: '0.65rem', bgcolor: '#F1F5F9', border: '1px solid #DCE4EE' }} />
                      </TableCell>
                      <TableCell>
                        {it.is_valid && !it.is_duplicate && !it.is_exceeded && (
                          <Chip size="small" label="Ready" sx={{ bgcolor: 'rgba(22, 163, 74, 0.08)', color: '#16A34A', border: '1px solid rgba(22, 163, 74, 0.25)', fontWeight: 600 }} />
                        )}
                        {it.is_duplicate && (
                          <Chip size="small" label="Duplicate" sx={{ bgcolor: 'rgba(217, 119, 6, 0.08)', color: '#D97706', border: '1px solid rgba(217, 119, 6, 0.25)', fontWeight: 600 }} />
                        )}
                        {!it.is_valid && (
                          <Tooltip title={it.error || 'Invalid syntax'}>
                            <Chip size="small" label="Invalid Syntax" sx={{ bgcolor: 'rgba(220, 38, 38, 0.08)', color: '#DC2626', border: '1px solid rgba(220, 38, 38, 0.25)', fontWeight: 600 }} />
                          </Tooltip>
                        )}
                        {it.is_exceeded && (
                          <Chip size="small" label="Limit Exceeded (>50)" sx={{ bgcolor: '#F1F5F9', color: '#64748B', border: '1px solid #DCE4EE' }} />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* Batch Results View */}
      {results && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {/* Summary KPIs */}
          <Grid container spacing={2.5}>
            <Grid item xs={12} sm={6} md={3}>
              <StatCard
                title="Total Processed"
                value={results.completed + results.invalid}
                subtitle="Indicators in batch"
                accentColor="#0891B2"
              />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <StatCard
                title="Actionable Threats"
                value={results.high_critical_count}
                subtitle="High / Critical detections"
                accentColor="#DC2626"
              />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <StatCard
                title="Clean / Low Risk"
                value={results.clean_count}
                subtitle="No active threat signals"
                accentColor="#16A34A"
              />
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <StatCard
                title="Validation Failures"
                value={results.invalid}
                subtitle="Malformed indicator strings"
                accentColor="#D97706"
              />
            </Grid>
          </Grid>

          {/* Results Table Card */}
          <Card sx={{ bgcolor: '#FFFFFF', border: '1px solid #DCE4EE', boxShadow: '0 1px 3px rgba(15, 23, 42, 0.04)', borderRadius: 2.5 }}>
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2, mb: 2.5 }}>
                <Box>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: '#172B4D' }}>
                    Triage Results Matrix ({filteredResults.length} items)
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#64748B' }}>
                    Every valid indicator has been evaluated and archived to the persistent database.
                  </Typography>
                </Box>

                <Box sx={{ display: 'flex', gap: 1.5 }}>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<Download size={15} />}
                    onClick={handleExportCSV}
                    sx={{
                      borderColor: '#0891B2',
                      color: '#0891B2',
                      '&:hover': { bgcolor: 'rgba(8, 145, 178, 0.06)' },
                    }}
                  >
                    Export Enriched CSV
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<RefreshCw size={15} />}
                    onClick={() => {
                      setResults(null);
                      setPreview(null);
                      setFile(null);
                    }}
                    sx={{
                      borderColor: '#DCE4EE',
                      color: '#172B4D',
                      '&:hover': { borderColor: '#0891B2', color: '#0891B2' },
                    }}
                  >
                    New Batch
                  </Button>
                </Box>
              </Box>

              {/* Filter Pills */}
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <Chip
                  size="small"
                  label={`All (${results.results.length})`}
                  onClick={() => setFilterSeverity('all')}
                  sx={{
                    bgcolor: filterSeverity === 'all' ? 'rgba(8, 145, 178, 0.12)' : '#F1F5F9',
                    color: filterSeverity === 'all' ? '#0891B2' : '#64748B',
                    border: filterSeverity === 'all' ? '1px solid rgba(8, 145, 178, 0.3)' : '1px solid #DCE4EE',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                />
                <Chip
                  size="small"
                  label={`Threats (${results.high_critical_count})`}
                  onClick={() => setFilterSeverity('threats')}
                  sx={{
                    bgcolor: filterSeverity === 'threats' ? 'rgba(220, 38, 38, 0.12)' : '#F1F5F9',
                    color: filterSeverity === 'threats' ? '#DC2626' : '#64748B',
                    border: filterSeverity === 'threats' ? '1px solid rgba(220, 38, 38, 0.3)' : '1px solid #DCE4EE',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                />
                <Chip
                  size="small"
                  label={`Clean (${results.clean_count})`}
                  onClick={() => setFilterSeverity('clean')}
                  sx={{
                    bgcolor: filterSeverity === 'clean' ? 'rgba(22, 163, 74, 0.12)' : '#F1F5F9',
                    color: filterSeverity === 'clean' ? '#16A34A' : '#64748B',
                    border: filterSeverity === 'clean' ? '1px solid rgba(22, 163, 74, 0.3)' : '1px solid #DCE4EE',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                />
              </Box>

              {/* Results Table */}
              <TableContainer sx={{ border: '1px solid #DCE4EE', borderRadius: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: '#F8FAFC' }}>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>INDICATOR</TableCell>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>TYPE</TableCell>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>SCORE</TableCell>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>SEVERITY</TableCell>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>FEEDS</TableCell>
                      <TableCell sx={{ color: '#64748B', fontWeight: 600 }}>VERDICT SUMMARY</TableCell>
                      <TableCell align="right" sx={{ color: '#64748B', fontWeight: 600 }}>ACTION</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {filteredResults.map((r, idx) => (
                      <TableRow key={idx} hover sx={{ '&:hover': { bgcolor: '#F8FAFC' } }}>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#172B4D' }}>
                          {r.normalized_indicator}
                        </TableCell>
                        <TableCell>
                          <Chip size="small" label={r.indicator_type.toUpperCase()} sx={{ fontSize: '0.68rem', bgcolor: '#F1F5F9', border: '1px solid #DCE4EE' }} />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: '#172B4D' }}>
                            {r.risk_score} / 100
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={r.severity} size="small" />
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 0.6 }}>
                            <Chip
                              size="small"
                              label={r.vt_status === 'rate_limited' ? 'VT: 429 Quota' : `VT: ${r.vt_detections}`}
                              sx={{
                                bgcolor: r.vt_status === 'rate_limited'
                                  ? 'rgba(234, 88, 12, 0.08)'
                                  : r.vt_detections > 0
                                  ? 'rgba(220, 38, 38, 0.08)'
                                  : '#F1F5F9',
                                color: r.vt_status === 'rate_limited'
                                  ? '#EA580C'
                                  : r.vt_detections > 0
                                  ? '#DC2626'
                                  : '#64748B',
                                border: '1px solid #DCE4EE',
                                fontSize: '0.68rem',
                                fontWeight: 600,
                              }}
                            />
                            <Chip
                              size="small"
                              label={r.otx_status === 'rate_limited' ? 'OTX: 429 Quota' : `OTX: ${r.otx_pulse_count}`}
                              sx={{
                                bgcolor: r.otx_status === 'rate_limited'
                                  ? 'rgba(234, 88, 12, 0.08)'
                                  : r.otx_pulse_count > 0
                                  ? 'rgba(79, 70, 229, 0.08)'
                                  : '#F1F5F9',
                                color: r.otx_status === 'rate_limited'
                                  ? '#EA580C'
                                  : r.otx_pulse_count > 0
                                  ? '#4F46E5'
                                  : '#64748B',
                                border: '1px solid #DCE4EE',
                                fontSize: '0.68rem',
                                fontWeight: 600,
                              }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: '#172B4D', fontSize: '0.8rem', maxWidth: 300 }}>
                          {r.verdict_summary}
                        </TableCell>
                        <TableCell align="right">
                          {r.id ? (
                            <Button
                              size="small"
                              variant="outlined"
                              startIcon={<Eye size={13} />}
                              onClick={() => navigate(`/investigation/${r.id}`)}
                              sx={{
                                fontSize: '0.75rem',
                                borderColor: '#0891B2',
                                color: '#0891B2',
                                '&:hover': { bgcolor: 'rgba(8, 145, 178, 0.06)' },
                              }}
                            >
                              Details
                            </Button>
                          ) : (
                            <Typography variant="caption" sx={{ color: '#DC2626', fontWeight: 600 }}>
                              Invalid
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Box>
      )}
    </Box>
  );
}
