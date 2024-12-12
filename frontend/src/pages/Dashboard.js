import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Alert,
  CircularProgress,
  LinearProgress,
  Chip,
  Stack,
  Divider
} from '@mui/material';
import { styled } from '@mui/material/styles';
import StorageIcon from '@mui/icons-material/Storage';
import SecurityIcon from '@mui/icons-material/Security';
import LanguageIcon from '@mui/icons-material/Language';
import HealthAndSafetyIcon from '@mui/icons-material/HealthAndSafety';
import axios from 'axios';
import config from '../config';

const DashboardCard = styled(Card)(({ theme }) => ({
  height: '100%',
  backgroundColor: '#1a1a1a',
  color: '#fff',
  position: 'relative',
  overflow: 'visible',
  '&::before': {
    content: '""',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: '4px',
    background: 'linear-gradient(90deg, #4d9fff 0%, #9f4dff 100%)',
  }
}));

const StatChip = styled(Chip)(({ status }) => ({
  backgroundColor: status === 'success' ? '#1a472a' : 
                  status === 'warning' ? '#472a1a' : 
                  status === 'error' ? '#472a2a' : '#2a2a2a',
  color: status === 'success' ? '#4caf50' : 
         status === 'warning' ? '#ff9800' : 
         status === 'error' ? '#f44336' : '#fff',
  border: 'none',
  height: '24px'
}));

const ProgressIndicator = styled(LinearProgress)(({ value }) => ({
  height: 4,
  borderRadius: 2,
  backgroundColor: '#2d2d2d',
  '& .MuiLinearProgress-bar': {
    backgroundColor: value < 50 ? '#4caf50' : 
                    value < 80 ? '#ff9800' : '#f44336'
  }
}));

const defaultStats = {
  logCollection: {
    totalLogs: 0,
    logsPerMinute: 0,
    activeConnections: 0,
    lastLogReceived: null,
    status: 'degraded'
  },
  detectionEngine: {
    enabledRules: 0,
    totalRules: 0,
    alertsLast24h: 0,
    processingRate: 0,
    status: 'degraded'
  },
  ipIntelligence: {
    lookupCount: 0,
    cacheHitRate: 0,
    threatDetections: 0,
    apiQuotaRemaining: 0,
    status: 'degraded'
  },
  systemHealth: {
    cpuUsage: 0,
    memoryUsage: 0,
    diskUsage: 0,
    serviceUptime: 0,
    status: 'degraded'
  }
};

function Dashboard() {
  const [stats, setStats] = useState(defaultStats);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      const requests = [
        axios.get(`${config.apiUrl}/api/collector/stats`).catch(error => ({ error, type: 'collector' })),
        axios.get(`${config.apiUrl}/api/detection/stats`).catch(error => ({ error, type: 'detection' })),
        axios.get(`${config.apiUrl}/api/iplookup/stats`).catch(error => ({ error, type: 'iplookup' })),
        axios.get(`${config.apiUrl}/api/system/health`).catch(error => ({ error, type: 'health' }))
      ];

      const [logStatsResp, detectionStatsResp, ipStatsResp, healthStatsResp] = await Promise.all(requests);

      const newStats = { ...defaultStats };

      // Process collector stats
      if (!logStatsResp.error) {
        newStats.logCollection = {
          totalLogs: logStatsResp.data.total_logs,
          logsPerMinute: logStatsResp.data.logs_per_minute,
          activeConnections: logStatsResp.data.active_connections,
          lastLogReceived: logStatsResp.data.last_log_received,
          status: logStatsResp.data.status
        };
      }

      // Process detection stats
      if (!detectionStatsResp.error) {
        newStats.detectionEngine = {
          enabledRules: detectionStatsResp.data.enabled_rules,
          totalRules: detectionStatsResp.data.total_rules,
          alertsLast24h: detectionStatsResp.data.alerts_last_24h,
          processingRate: detectionStatsResp.data.processing_rate,
          status: detectionStatsResp.data.status
        };
      }

      // Process IP intelligence stats
      if (!ipStatsResp.error) {
        newStats.ipIntelligence = {
          lookupCount: ipStatsResp.data.lookup_count,
          cacheHitRate: ipStatsResp.data.cache_hit_rate,
          threatDetections: ipStatsResp.data.threat_detections,
          apiQuotaRemaining: ipStatsResp.data.api_quota_remaining,
          status: ipStatsResp.data.status
        };
      }

      // Process system health stats
      if (!healthStatsResp.error) {
        newStats.systemHealth = {
          cpuUsage: healthStatsResp.data.system_metrics?.cpu_usage || 0,
          memoryUsage: healthStatsResp.data.system_metrics?.memory_usage || 0,
          diskUsage: healthStatsResp.data.system_metrics?.disk_usage || 0,
          serviceUptime: healthStatsResp.data.uptime || 0,
          status: healthStatsResp.data.status
        };
      }

      setStats(newStats);
      setError(null);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      setError('Failed to fetch some service statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds) => {
    const days = Math.floor(seconds / (24 * 60 * 60));
    const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
    const minutes = Math.floor((seconds % (60 * 60)) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  };

  const formatNumber = (num) => {
    return new Intl.NumberFormat().format(num);
  };

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ color: '#fff', mb: 3 }}>
        Dashboard
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          {error && (
            <Alert severity="warning" sx={{ mb: 3, backgroundColor: '#472a1a', color: '#fff' }}>
              {error}
            </Alert>
          )}
          <Alert severity="info" sx={{ mb: 3, backgroundColor: '#1a2b3c', color: '#fff' }}>
            Welcome to SIEMBox! Please configure your API keys in the Settings page to enable all features.
          </Alert>
        </Grid>

        <Grid item xs={12} md={6}>
          <DashboardCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <StorageIcon sx={{ mr: 1, color: '#4d9fff' }} />
                <Typography variant="h6">
                  Log Collection Status
                </Typography>
                <Box sx={{ flexGrow: 1 }} />
                <StatChip
                  label={stats.logCollection.status.toUpperCase()}
                  status={stats.logCollection.status === 'operational' ? 'success' : 'error'}
                  size="small"
                />
              </Box>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Logs Per Minute
                  </Typography>
                  <Typography variant="h4" sx={{ color: '#4d9fff' }}>
                    {formatNumber(stats.logCollection.logsPerMinute)}
                  </Typography>
                </Box>
                
                <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
                
                <Stack direction="row" spacing={2} justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="text.secondary">Total Logs</Typography>
                    <Typography variant="h6">{formatNumber(stats.logCollection.totalLogs)}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">Active Connections</Typography>
                    <Typography variant="h6">{stats.logCollection.activeConnections}</Typography>
                  </Box>
                </Stack>
              </Stack>
            </CardContent>
          </DashboardCard>
        </Grid>

        <Grid item xs={12} md={6}>
          <DashboardCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SecurityIcon sx={{ mr: 1, color: '#9f4dff' }} />
                <Typography variant="h6">
                  Detection Engine
                </Typography>
                <Box sx={{ flexGrow: 1 }} />
                <StatChip
                  label={stats.detectionEngine.status.toUpperCase()}
                  status={stats.detectionEngine.status === 'operational' ? 'success' : 'error'}
                  size="small"
                />
              </Box>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Alerts (Last 24h)
                  </Typography>
                  <Typography variant="h4" sx={{ color: '#9f4dff' }}>
                    {formatNumber(stats.detectionEngine.alertsLast24h)}
                  </Typography>
                </Box>
                
                <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
                
                <Stack direction="row" spacing={2} justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="text.secondary">Enabled Rules</Typography>
                    <Typography variant="h6">
                      {stats.detectionEngine.enabledRules}/{stats.detectionEngine.totalRules}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">Processing Rate</Typography>
                    <Typography variant="h6">{stats.detectionEngine.processingRate}/s</Typography>
                  </Box>
                </Stack>
              </Stack>
            </CardContent>
          </DashboardCard>
        </Grid>

        <Grid item xs={12} md={6}>
          <DashboardCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <LanguageIcon sx={{ mr: 1, color: '#4dff9f' }} />
                <Typography variant="h6">
                  IP Intelligence
                </Typography>
                <Box sx={{ flexGrow: 1 }} />
                <StatChip
                  label={stats.ipIntelligence.status.toUpperCase()}
                  status={stats.ipIntelligence.status === 'operational' ? 'success' : 'error'}
                  size="small"
                />
              </Box>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Threat Detections
                  </Typography>
                  <Typography variant="h4" sx={{ color: '#4dff9f' }}>
                    {formatNumber(stats.ipIntelligence.threatDetections)}
                  </Typography>
                </Box>
                
                <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
                
                <Stack direction="row" spacing={2} justifyContent="space-between">
                  <Box>
                    <Typography variant="body2" color="text.secondary">Cache Hit Rate</Typography>
                    <Typography variant="h6">{stats.ipIntelligence.cacheHitRate}%</Typography>
                  </Box>
                  <Box>
                    <Typography variant="body2" color="text.secondary">API Quota</Typography>
                    <Typography variant="h6">{stats.ipIntelligence.apiQuotaRemaining}</Typography>
                  </Box>
                </Stack>
              </Stack>
            </CardContent>
          </DashboardCard>
        </Grid>

        <Grid item xs={12} md={6}>
          <DashboardCard>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <HealthAndSafetyIcon sx={{ mr: 1, color: '#ff4d9f' }} />
                <Typography variant="h6">
                  System Health
                </Typography>
                <Box sx={{ flexGrow: 1 }} />
                <StatChip
                  label={stats.systemHealth.status.toUpperCase()}
                  status={stats.systemHealth.status === 'operational' ? 'success' : 'error'}
                  size="small"
                />
              </Box>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Uptime
                  </Typography>
                  <Typography variant="h4" sx={{ color: '#ff4d9f' }}>
                    {formatUptime(stats.systemHealth.serviceUptime)}
                  </Typography>
                </Box>
                
                <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)' }} />
                
                <Stack spacing={1}>
                  <Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2" color="text.secondary">CPU Usage</Typography>
                      <Typography variant="body2">{stats.systemHealth.cpuUsage}%</Typography>
                    </Box>
                    <ProgressIndicator variant="determinate" value={stats.systemHealth.cpuUsage} />
                  </Box>
                  
                  <Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2" color="text.secondary">Memory Usage</Typography>
                      <Typography variant="body2">{stats.systemHealth.memoryUsage}%</Typography>
                    </Box>
                    <ProgressIndicator variant="determinate" value={stats.systemHealth.memoryUsage} />
                  </Box>
                  
                  <Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2" color="text.secondary">Disk Usage</Typography>
                      <Typography variant="body2">{stats.systemHealth.diskUsage}%</Typography>
                    </Box>
                    <ProgressIndicator variant="determinate" value={stats.systemHealth.diskUsage} />
                  </Box>
                </Stack>
              </Stack>
            </CardContent>
          </DashboardCard>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;