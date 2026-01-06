import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Alert,
  Paper,
} from '@mui/material';
import {
  Security,
  Warning,
  Description,
  BugReport,
  Computer,
  Scanner,
  Shield,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../services/api';
import { websocketService } from '../services/websocket';
import { useAuthStore } from '../stores/authStore';
import type { DashboardStats } from '../types/api';

interface StatCardProps {
  title: string;
  value: number | undefined;
  icon: React.ReactElement;
  color: 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
  subtitle?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color, subtitle }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography color="textSecondary" gutterBottom variant="overline">
            {title}
          </Typography>
          <Typography variant="h4" component="div">
            {(value ?? 0).toLocaleString()}
          </Typography>
          {subtitle && (
            <Typography variant="body2" color="textSecondary">
              {subtitle}
            </Typography>
          )}
        </Box>
        <Box
          sx={{
            backgroundColor: `${color}.main`,
            borderRadius: '50%',
            p: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'white',
          }}
        >
          {icon}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

export const DashboardPage: React.FC = () => {
  const { token } = useAuthStore();
  const [realtimeStats, setRealtimeStats] = useState<DashboardStats | null>(null);

  const {
    data: stats,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => apiClient.getDashboardStats(),
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  // Use real-time stats if available, otherwise fall back to API data
  const currentStats = realtimeStats || stats;

  useEffect(() => {
    if (token) {
      websocketService.connect(token);

      const handleStatsUpdate = (data: DashboardStats) => {
        setRealtimeStats(data);
      };

      websocketService.onStatsUpdate(handleStatsUpdate);

      return () => {
        websocketService.offStatsUpdate(handleStatsUpdate);
      };
    }
  }, [token]);

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" action={
        <button onClick={() => refetch()}>Retry</button>
      }>
        Failed to load dashboard data: {error instanceof Error ? error.message : 'Unknown error'}
      </Alert>
    );
  }

  if (!currentStats) {
    return (
      <Alert severity="info">
        No dashboard data available
      </Alert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Security Dashboard
      </Typography>
      
      {/* Stats Cards */}
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: '1fr 1fr 1fr 1fr' },
        gap: 3,
        mb: 3
      }}>
        <StatCard
          title="Total Logs"
          value={currentStats.total_logs}
          icon={<Description />}
          color="info"
          subtitle="All time"
        />
        
        <StatCard
          title="Total Alerts"
          value={currentStats.total_alerts}
          icon={<Security />}
          color="primary"
          subtitle="All time"
        />
        
        <StatCard
          title="Open Alerts"
          value={currentStats.open_alerts}
          icon={<Warning />}
          color="warning"
          subtitle="Requires attention"
        />
        
        <StatCard
          title="Critical Alerts"
          value={currentStats.critical_alerts}
          icon={<Warning />}
          color="error"
          subtitle="High priority"
        />
      </Box>

      {/* Vulnerability Statistics */}
      {(currentStats.total_assets !== undefined || currentStats.total_vulnerabilities !== undefined) && (
        <>
          <Typography variant="h5" gutterBottom sx={{ mt: 4, mb: 2 }}>
            Vulnerability Management
          </Typography>
          
          <Box sx={{
            display: 'grid',
            gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: '1fr 1fr 1fr 1fr' },
            gap: 3,
            mb: 3
          }}>
            {currentStats.total_assets !== undefined && (
              <StatCard
                title="Total Assets"
                value={currentStats.total_assets}
                icon={<Computer />}
                color="info"
                subtitle={`${currentStats.active_assets || 0} active`}
              />
            )}
            
            {currentStats.total_vulnerabilities !== undefined && (
              <StatCard
                title="Total Vulnerabilities"
                value={currentStats.total_vulnerabilities}
                icon={<BugReport />}
                color="warning"
                subtitle={`${currentStats.open_vulnerabilities || 0} open`}
              />
            )}
            
            {currentStats.critical_vulnerabilities !== undefined && (
              <StatCard
                title="Critical Vulnerabilities"
                value={currentStats.critical_vulnerabilities}
                icon={<Shield />}
                color="error"
                subtitle="Immediate attention"
              />
            )}
            
            {currentStats.active_scans !== undefined && (
              <StatCard
                title="Active Scans"
                value={currentStats.active_scans}
                icon={<Scanner />}
                color="primary"
                subtitle={`${currentStats.recent_scans || 0} recent`}
              />
            )}
          </Box>

          {/* Vulnerability Severity Breakdown */}
          {(currentStats.high_vulnerabilities !== undefined ||
            currentStats.medium_vulnerabilities !== undefined ||
            currentStats.low_vulnerabilities !== undefined) && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Severity Breakdown
                </Typography>
                <Box sx={{
                  display: 'grid',
                  gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1fr' },
                  gap: 2,
                  mt: 2
                }}>
                  {currentStats.high_vulnerabilities !== undefined && (
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="warning.main">
                        {currentStats.high_vulnerabilities}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        High Severity
                      </Typography>
                    </Box>
                  )}
                  
                  {currentStats.medium_vulnerabilities !== undefined && (
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="info.main">
                        {currentStats.medium_vulnerabilities}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Medium Severity
                      </Typography>
                    </Box>
                  )}
                  
                  {currentStats.low_vulnerabilities !== undefined && (
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {currentStats.low_vulnerabilities}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Low Severity
                      </Typography>
                    </Box>
                  )}
                </Box>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Recent Activity and System Status */}
      <Box sx={{ 
        display: 'grid', 
        gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
        gap: 3,
        mb: 3
      }}>
        {/* Recent Activity */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Last 24 Hours
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                <Typography variant="body2" color="textSecondary">
                  New Logs
                </Typography>
                <Typography variant="h6">
                  {(currentStats.logs_last_24h ?? 0).toLocaleString()}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="body2" color="textSecondary">
                  New Alerts
                </Typography>
                <Typography variant="h6" color={(currentStats.alerts_last_24h ?? 0) > 0 ? 'error.main' : 'text.primary'}>
                  {(currentStats.alerts_last_24h ?? 0).toLocaleString()}
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>

        {/* System Status */}
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              System Status
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Box
                  sx={{
                    width: 12,
                    height: 12,
                    borderRadius: '50%',
                    backgroundColor: websocketService.isConnected ? 'success.main' : 'error.main',
                    mr: 1,
                  }}
                />
                <Typography variant="body2">
                  Real-time Connection: {websocketService.isConnected ? 'Connected' : 'Disconnected'}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Box
                  sx={{
                    width: 12,
                    height: 12,
                    borderRadius: '50%',
                    backgroundColor: 'success.main',
                    mr: 1,
                  }}
                />
                <Typography variant="body2">
                  API Status: Online
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Box>

      {/* Quick Actions */}
      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Quick Actions
        </Typography>
        <Typography variant="body2" color="textSecondary">
          Dashboard is ready. Navigate to Logs, Alerts, Detection Rules, or Vulnerabilities to start monitoring your security events.
        </Typography>
        
        {/* Show vulnerability-specific quick actions if vulnerability data is available */}
        {(currentStats.total_vulnerabilities !== undefined && currentStats.total_vulnerabilities > 0) && (
          <Box sx={{ mt: 2, p: 2, backgroundColor: 'warning.light', borderRadius: 1 }}>
            <Typography variant="body2" color="warning.dark">
              <strong>Action Required:</strong> You have {currentStats.open_vulnerabilities || 0} open vulnerabilities
              {currentStats.critical_vulnerabilities && currentStats.critical_vulnerabilities > 0 &&
                ` including ${currentStats.critical_vulnerabilities} critical issues`
              }.
              Visit the Vulnerabilities page to review and remediate.
            </Typography>
          </Box>
        )}
      </Paper>
    </Box>
  );
};