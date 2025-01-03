import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
  CircularProgress,
  IconButton,
  Tooltip,
  Grid,
  TextField,
  InputAdornment,
  Modal,
  Card,
  CardContent,
  CardHeader,
  Divider
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ArrowUpward as ArrowUpwardIcon,
  ArrowDownward as ArrowDownwardIcon,
  Search as SearchIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import config from '../config';
import axios from 'axios';

function Detections() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [filters, setFilters] = useState({
    timestamp: '',
    rule_name: '',
    severity: '',
    log_source: '',
    details: ''
  });
  const [selectedDetection, setSelectedDetection] = useState(null);

  // Modal styles
  const modalStyle = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: '80%',
    maxWidth: '800px',
    maxHeight: '90vh',
    overflow: 'auto',
    bgcolor: '#1a1a1a',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    boxShadow: 24,
    p: 0,
    color: '#fff'
  };

  // Handle sorting
  const handleSort = (key) => {
    setSortConfig((prevSort) => ({
      key,
      direction: prevSort.key === key && prevSort.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  // Handle filtering
  const handleFilterChange = (column, value) => {
    setFilters(prev => ({
      ...prev,
      [column]: value
    }));
  };

  const fetchDetections = async () => {
    try {
      setLoading(true);
      // Get alerts from the API's logs endpoint with alert_id filter
      const response = await axios.get(`${config.apiUrl}/api/logs`, {
        params: {
          has_alert: true,
          page: 1,
          page_size: 100
        }
      });

      if (response.data && response.data.logs) {
        const alerts = response.data.logs.map(log => ({
          rule_id: log.alert_id,
          rule_name: log.alert ? log.alert.rule_name : 'Unknown Rule',
          timestamp: log.timestamp,
          log_source: log.source,
          matched_log: {
            ...log,
            message: log.message,
            metadata: log.log_metadata
          },
          severity: log.alert ? log.alert.severity : 'medium'
        }));

        setDetections(alerts);
        setError(null);
      }
    } catch (err) {
      console.error('Error fetching detections:', err);
      setError('Failed to fetch detections. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetections();
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(fetchDetections, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleRefresh = () => {
    fetchDetections();
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'error';
      case 'medium':
        return 'warning';
      case 'low':
        return 'info';
      default:
        return 'default';
    }
  };

  const formatDetails = (matchedLog) => {
    try {
      // Extract relevant information from matched_log
      const {
        source,
        timestamp,
        level,
        ...details
      } = matchedLog;

      // Return formatted details
      return JSON.stringify(details, null, 2);
    } catch (err) {
      console.error('Error formatting details:', err);
      return JSON.stringify(matchedLog);
    }
  };

  // Filter detections
  const filteredDetections = detections.filter(detection => {
    return Object.entries(filters).every(([key, value]) => {
      if (!value) return true;
      
      const searchValue = value.toLowerCase();
      switch (key) {
        case 'timestamp':
          return new Date(detection.timestamp)
            .toLocaleString()
            .toLowerCase()
            .includes(searchValue);
        case 'rule_name':
          return detection.rule_name.toLowerCase().includes(searchValue);
        case 'severity':
          return detection.severity.toLowerCase().includes(searchValue);
        case 'log_source':
          return detection.log_source.toLowerCase().includes(searchValue);
        case 'details':
          return formatDetails(detection.matched_log).toLowerCase().includes(searchValue);
        default:
          return true;
      }
    });
  });

  // Sort detections
  const sortedDetections = [...filteredDetections].sort((a, b) => {
    const { key, direction } = sortConfig;
    let comparison = 0;

    switch (key) {
      case 'timestamp':
        comparison = new Date(a.timestamp) - new Date(b.timestamp);
        break;
      case 'rule_name':
        comparison = a.rule_name.localeCompare(b.rule_name);
        break;
      case 'severity':
        comparison = a.severity.localeCompare(b.severity);
        break;
      case 'log_source':
        comparison = a.log_source.localeCompare(b.log_source);
        break;
      case 'details':
        comparison = formatDetails(a.matched_log).localeCompare(formatDetails(b.matched_log));
        break;
      default:
        comparison = 0;
    }

    return direction === 'asc' ? comparison : -comparison;
  });

  // Handle row click
  const handleRowClick = (detection) => {
    setSelectedDetection(detection);
  };

  // Handle modal close
  const handleModalClose = () => {
    setSelectedDetection(null);
  };

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Grid container spacing={2} alignItems="center" sx={{ mb: 3 }}>
        <Grid item xs>
          <Typography variant="h4" sx={{ color: '#fff' }}>
            Detections
          </Typography>
        </Grid>
        <Grid item>
          <Tooltip title="Refresh detections">
            <IconButton 
              onClick={handleRefresh} 
              sx={{ 
                color: '#4d9fff',
                '&:hover': {
                  backgroundColor: 'rgba(77, 159, 255, 0.1)',
                }
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Grid>
      </Grid>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
          <CircularProgress sx={{ color: '#4d9fff' }} />
        </Box>
      ) : (
        <TableContainer 
          component={Paper} 
          sx={{ 
            backgroundColor: '#1a1a1a',
            boxShadow: 'none',
            border: '1px solid rgba(255, 255, 255, 0.1)',
          }}
        >
          <Table>
            <TableHead>
              <TableRow>
                {[
                  { id: 'timestamp', label: 'Timestamp' },
                  { id: 'rule_name', label: 'Rule Name' },
                  { id: 'severity', label: 'Severity' },
                  { id: 'log_source', label: 'Source' },
                  { id: 'details', label: 'Details' }
                ].map((column) => (
                  <TableCell
                    key={column.id}
                    onClick={() => handleSort(column.id)}
                    sx={{
                      color: 'rgba(255, 255, 255, 0.7)',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                      cursor: 'pointer',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 255, 255, 0.05)'
                      }
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {column.label}
                      {sortConfig.key === column.id && (
                        <Box component="span" sx={{ ml: 1 }}>
                          {sortConfig.direction === 'asc' ? (
                            <ArrowUpwardIcon sx={{ fontSize: 16 }} />
                          ) : (
                            <ArrowDownwardIcon sx={{ fontSize: 16 }} />
                          )}
                        </Box>
                      )}
                    </Box>
                  </TableCell>
                ))}
              </TableRow>
              <TableRow>
                {[
                  'timestamp',
                  'rule_name',
                  'severity',
                  'log_source',
                  'details'
                ].map((column) => (
                  <TableCell
                    key={column}
                    sx={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                      padding: '8px'
                    }}
                  >
                    <TextField
                      size="small"
                      placeholder={`Filter ${column.replace('_', ' ')}...`}
                      value={filters[column]}
                      onChange={(e) => handleFilterChange(column, e.target.value)}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <SearchIcon sx={{ color: 'rgba(255, 255, 255, 0.3)' }} />
                          </InputAdornment>
                        ),
                        sx: {
                          color: '#fff',
                          '& .MuiOutlinedInput-notchedOutline': {
                            borderColor: 'rgba(255, 255, 255, 0.1)'
                          },
                          '&:hover .MuiOutlinedInput-notchedOutline': {
                            borderColor: 'rgba(255, 255, 255, 0.3)'
                          },
                          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                            borderColor: '#4d9fff'
                          }
                        }
                      }}
                      sx={{
                        width: '100%',
                        '& .MuiInputBase-input': {
                          color: '#fff'
                        }
                      }}
                    />
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {sortedDetections.length === 0 ? (
                <TableRow>
                  <TableCell 
                    colSpan={5} 
                    align="center"
                    sx={{ 
                      color: 'rgba(255, 255, 255, 0.5)',
                      borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                    }}
                  >
                    No detections found
                  </TableCell>
                </TableRow>
              ) : (
                sortedDetections.map((detection) => (
                  <TableRow 
                    key={`${detection.rule_id}-${detection.timestamp}`}
                    onClick={() => handleRowClick(detection)}
                    sx={{ 
                      cursor: 'pointer',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 255, 255, 0.05)'
                      }
                    }}
                  >
                    <TableCell 
                      sx={{ 
                        color: '#fff',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      {new Date(detection.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        color: '#fff',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      {detection.rule_name}
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      <Chip 
                        label={detection.severity}
                        color={getSeverityColor(detection.severity)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        color: '#fff',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      {detection.log_source}
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        maxWidth: '400px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        color: '#fff',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      {formatDetails(detection.matched_log)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Details Modal */}
      <Modal
        open={selectedDetection !== null}
        onClose={handleModalClose}
        aria-labelledby="detection-details-modal"
      >
        <Card sx={modalStyle}>
          {selectedDetection && (
            <>
              <CardHeader
                title={
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6" component="div">
                      Detection Details
                    </Typography>
                    <IconButton onClick={handleModalClose} sx={{ color: '#fff' }}>
                      <CloseIcon />
                    </IconButton>
                  </Box>
                }
                sx={{
                  borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                  backgroundColor: '#2a2a2a'
                }}
              />
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Rule Name
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {selectedDetection.rule_name}
                    </Typography>
                    <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Timestamp
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {new Date(selectedDetection.timestamp).toLocaleString()}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Severity
                    </Typography>
                    <Chip 
                      label={selectedDetection.severity}
                      color={getSeverityColor(selectedDetection.severity)}
                      size="small"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Source
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {selectedDetection.log_source}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Matched Log Details
                    </Typography>
                    <Paper 
                      sx={{ 
                        p: 2, 
                        mt: 1, 
                        backgroundColor: '#2a2a2a',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: 1
                      }}
                    >
                      <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                        {formatDetails(selectedDetection.matched_log)}
                      </pre>
                    </Paper>
                  </Grid>
                </Grid>
              </CardContent>
            </>
          )}
        </Card>
      </Modal>
    </Box>
  );
}

export default Detections;