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
  InputAdornment
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ArrowUpward as ArrowUpwardIcon,
  ArrowDownward as ArrowDownwardIcon,
  Search as SearchIcon
} from '@mui/icons-material';
import config from '../config';

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
      const response = await fetch(`${config.detectionUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          source: 'detections_page',
          message: 'Checking for alerts',
          level: 'INFO',
          timestamp: new Date().toISOString()
        })
      });

      if (!response.ok) {
        throw new Error('Failed to fetch detections');
      }

      const data = await response.json();
      
      // Get alerts from the response
      const alerts = data.alerts || [];
      
      // Sort alerts by timestamp in descending order
      const sortedAlerts = alerts.sort((a, b) => 
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );

      setDetections(sortedAlerts);
      setError(null);
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
                  <TableRow key={`${detection.rule_id}-${detection.timestamp}`}>
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
    </Box>
  );
}

export default Detections;