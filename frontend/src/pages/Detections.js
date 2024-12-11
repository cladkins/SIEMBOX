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

function Detections() {
  const [detections, setDetections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDetections = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8080/api/detections');
      if (!response.ok) {
        throw new Error('Failed to fetch detections');
      }
      const data = await response.json();
      setDetections(data);
      setError(null);
    } catch (err) {
      setError(err.message);
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
          <Typography variant="h4">
            Detections
          </Typography>
        </Grid>
        <Grid item>
          <Tooltip title="Refresh detections">
            <IconButton onClick={handleRefresh} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Grid>
      </Grid>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
          <CircularProgress />
        </Box>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Rule Name</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detections.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    No detections found
                  </TableCell>
                </TableRow>
              ) : (
                detections.map((detection) => (
                  <TableRow key={detection.id}>
                    <TableCell>{new Date(detection.timestamp).toLocaleString()}</TableCell>
                    <TableCell>{detection.rule_name}</TableCell>
                    <TableCell>
                      <Chip 
                        label={detection.severity}
                        color={getSeverityColor(detection.severity)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>{detection.log_source}</TableCell>
                    <TableCell 
                      sx={{ 
                        maxWidth: '400px',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap'
                      }}
                    >
                      {JSON.stringify(detection.matched_log)}
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
