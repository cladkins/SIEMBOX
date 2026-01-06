import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  CircularProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  Analytics,
  TrendingUp,
  PieChart,
  BarChart,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';

const AnalyticsPage: React.FC = () => {
  const [timeRange, setTimeRange] = useState<string>('7d');

  const { data: analytics, isLoading } = useQuery({
    queryKey: ['analytics', timeRange],
    queryFn: async () => {
      // Mock data for now
      return {
        totalEvents: 15420,
        criticalAlerts: 23,
        resolvedIncidents: 156,
        averageResponseTime: '4.2 minutes',
        topThreats: [
          { name: 'Malware Detection', count: 45 },
          { name: 'Suspicious Login', count: 32 },
          { name: 'Data Exfiltration', count: 18 },
        ],
        eventTrends: [
          { date: '2024-01-10', events: 1200 },
          { date: '2024-01-11', events: 1350 },
          { date: '2024-01-12', events: 1100 },
          { date: '2024-01-13', events: 1450 },
          { date: '2024-01-14', events: 1300 },
        ],
      };
    },
  });

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">
          Analytics Dashboard
        </Typography>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Time Range</InputLabel>
          <Select
            value={timeRange}
            label="Time Range"
            onChange={(e) => setTimeRange(e.target.value)}
          >
            <MenuItem value="1d">Last 24 Hours</MenuItem>
            <MenuItem value="7d">Last 7 Days</MenuItem>
            <MenuItem value="30d">Last 30 Days</MenuItem>
            <MenuItem value="90d">Last 90 Days</MenuItem>
          </Select>
        </FormControl>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <Analytics sx={{ mr: 1, color: 'primary.main' }} />
                <Typography variant="h6">Total Events</Typography>
              </Box>
              <Typography variant="h4" color="primary">
                {analytics?.totalEvents?.toLocaleString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <TrendingUp sx={{ mr: 1, color: 'error.main' }} />
                <Typography variant="h6">Critical Alerts</Typography>
              </Box>
              <Typography variant="h4" color="error">
                {analytics?.criticalAlerts}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <PieChart sx={{ mr: 1, color: 'success.main' }} />
                <Typography variant="h6">Resolved</Typography>
              </Box>
              <Typography variant="h4" color="success.main">
                {analytics?.resolvedIncidents}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <BarChart sx={{ mr: 1, color: 'info.main' }} />
                <Typography variant="h6">Avg Response</Typography>
              </Box>
              <Typography variant="h4" color="info.main">
                {analytics?.averageResponseTime}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Top Threats
            </Typography>
            {analytics?.topThreats?.map((threat, index) => (
              <Box key={index} display="flex" justifyContent="space-between" mb={1}>
                <Typography variant="body2">{threat.name}</Typography>
                <Typography variant="body2" fontWeight="bold">
                  {threat.count}
                </Typography>
              </Box>
            ))}
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Event Trends
            </Typography>
            {analytics?.eventTrends?.map((trend, index) => (
              <Box key={index} display="flex" justifyContent="space-between" mb={1}>
                <Typography variant="body2">{trend.date}</Typography>
                <Typography variant="body2" fontWeight="bold">
                  {trend.events.toLocaleString()}
                </Typography>
              </Box>
            ))}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default AnalyticsPage;