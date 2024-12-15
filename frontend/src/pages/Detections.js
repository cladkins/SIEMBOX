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
  Grid
} from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import config from '../config';

function Detections() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
                <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  Timestamp
                </TableCell>
                <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  Rule Name
                </TableCell>
                <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  Severity
                </TableCell>
                <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  Source
                </TableCell>
                <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  Details
                </TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detections.length === 0 ? (
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
                detections.map((detection) => (
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