import React from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Alert
} from '@mui/material';

function Dashboard() {
  return (
    <Box sx={{ flexGrow: 1 }}>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Alert severity="info" sx={{ mb: 3 }}>
            Welcome to SIEMBox! Please configure your API keys in the Settings page to enable all features.
          </Alert>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Log Collection Status
              </Typography>
              <Typography variant="body1">
                System is ready to collect logs via:
              </Typography>
              <ul>
                <li>Syslog (UDP/TCP port 514)</li>
                <li>HTTP API (port 8000)</li>
                <li>Windows Event Logs (via agent)</li>
              </ul>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Detection Engine
              </Typography>
              <Typography variant="body1">
                Features:
              </Typography>
              <ul>
                <li>Real-time log analysis</li>
                <li>SigmaHQ rules integration</li>
                <li>Automated threat detection</li>
              </ul>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                IP Intelligence
              </Typography>
              <Typography variant="body1">
                Services:
              </Typography>
              <ul>
                <li>IP Geolocation</li>
                <li>Threat Intelligence</li>
                <li>Reputation Scoring</li>
              </ul>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Health
              </Typography>
              <Typography variant="body1">
                Monitoring:
              </Typography>
              <ul>
                <li>Service Status</li>
                <li>Resource Usage</li>
                <li>Storage Capacity</li>
              </ul>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default Dashboard;
