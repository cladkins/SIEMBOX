import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  CircularProgress,
  Alert,
  LinearProgress,
  useTheme
} from '@mui/material';
import { styled } from '@mui/material/styles';
import axios from 'axios';
import config from '../config';

// Styled components
const MetricPaper = styled(Paper)(({ theme }) => ({
  padding: theme.spacing(3),
  backgroundColor: '#1E1E1E',
  color: '#fff',
  height: '100%',
  position: 'relative',
  overflow: 'hidden',
  '&::after': {
    content: '""',
    position: 'absolute',
    bottom: 0,
    left: 0,
    right: 0,
    height: '3px',
    background: 'linear-gradient(90deg, #00C853 0%, #2196F3 100%)'
  }
}));

const MetricValue = styled(Typography)({
  fontSize: '2.5rem',
  fontWeight: 500,
  marginBottom: '8px'
});

const MetricLabel = styled(Typography)({
  fontSize: '0.875rem',
  color: '#9E9E9E',
  textTransform: 'uppercase',
  letterSpacing: '0.1em'
});

const ProgressLabel = styled(Box)({
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: '4px'
});

const defaultStats = {
  collector: {
    total_logs: 0,
    logs_per_minute: 0,
    status: 'degraded'
  },
  detection: {
    alerts_last_24h: 0,
    enabled_rules: 0,
    total_rules: 0,
    system_metrics: {
      cpu_usage: 0,
      memory_usage: 0
    },
    status: 'degraded'
  }
};

function Dashboard() {
  const [stats, setStats] = useState(defaultStats);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const theme = useTheme();

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${config.apiUrl}/api/services/stats`);
      setStats(response.data);
      setError(null);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      setError('Failed to fetch service statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Alert severity="error" sx={{ backgroundColor: '#472a2a', color: '#fff' }}>
          {error}
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      {/* Alerts/Detections Section */}
      <Grid container spacing={4}>
        <Grid item xs={12}>
          <MetricPaper elevation={3}>
            <Box sx={{ mb: 3 }}>
              <MetricLabel>Security Alerts (Last 24h)</MetricLabel>
              <MetricValue sx={{ color: stats.detection.alerts_last_24h > 0 ? '#FF5252' : '#4CAF50' }}>
                {formatNumber(stats.detection.alerts_last_24h)}
              </MetricValue>
            </Box>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box>
                  <MetricLabel>Active Rules</MetricLabel>
                  <Typography variant="h6" sx={{ color: '#2196F3' }}>
                    {stats.detection.enabled_rules} / {stats.detection.total_rules}
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box>
                  <MetricLabel>Detection Status</MetricLabel>
                  <Typography variant="h6" sx={{ 
                    color: stats.detection.status === 'operational' ? '#4CAF50' : '#FF5252'
                  }}>
                    {stats.detection.status.toUpperCase()}
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </MetricPaper>
        </Grid>

        {/* System Health Section */}
        <Grid item xs={12} md={6}>
          <MetricPaper elevation={3}>
            <Box sx={{ mb: 3 }}>
              <MetricLabel>System Health</MetricLabel>
            </Box>
            <Box sx={{ mb: 4 }}>
              <ProgressLabel>
                <Typography variant="body2">CPU Usage</Typography>
                <Typography variant="body2">{stats.detection.system_metrics.cpu_usage}%</Typography>
              </ProgressLabel>
              <LinearProgress
                variant="determinate"
                value={stats.detection.system_metrics.cpu_usage}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: stats.detection.system_metrics.cpu_usage > 80 ? '#FF5252' : '#4CAF50'
                  }
                }}
              />
            </Box>
            <Box>
              <ProgressLabel>
                <Typography variant="body2">Memory Usage</Typography>
                <Typography variant="body2">{stats.detection.system_metrics.memory_usage}%</Typography>
              </ProgressLabel>
              <LinearProgress
                variant="determinate"
                value={stats.detection.system_metrics.memory_usage}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  backgroundColor: 'rgba(255, 255, 255, 0.1)',
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: stats.detection.system_metrics.memory_usage > 80 ? '#FF5252' : '#4CAF50'
                  }
                }}
              />
            </Box>
          </MetricPaper>
        </Grid>

        {/* Log Collection Status Section */}
        <Grid item xs={12} md={6}>
          <MetricPaper elevation={3}>
            <Box sx={{ mb: 3 }}>
              <MetricLabel>Log Collection</MetricLabel>
              <MetricValue>{formatNumber(stats.collector.logs_per_minute)}</MetricValue>
              <Typography variant="body2" sx={{ color: '#9E9E9E' }}>
                Logs per minute
              </Typography>
            </Box>
            <Box>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <MetricLabel>Total Logs</MetricLabel>
                  <Typography variant="h6">
                    {formatNumber(stats.collector.total_logs)}
                  </Typography>
                </Grid>
                <Grid item xs={6}>
                  <MetricLabel>Status</MetricLabel>
                  <Typography variant="h6" sx={{ 
                    color: stats.collector.status === 'operational' ? '#4CAF50' : '#FF5252'
                  }}>
                    {stats.collector.status.toUpperCase()}
                  </Typography>
                </Grid>
              </Grid>
            </Box>
          </MetricPaper>
        </Grid>
      </Grid>
    </Container>
  );
}

export default Dashboard;