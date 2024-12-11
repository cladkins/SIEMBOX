import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Snackbar,
  Alert,
  Grid,
  CircularProgress,
  Paper,
  Divider
} from '@mui/material';
import config from '../config';
import axios from 'axios';
import RuleList from '../components/RuleList';

function Settings() {
  const [apiKeys, setApiKeys] = useState({
    IPAPI_KEY: '',
    CROWDSEC_API_KEY: ''
  });
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'success'
  });
  const [stats, setStats] = useState({
    total: 0,
    enabled: 0,
    categories: 0
  });

  useEffect(() => {
    // Fetch current API keys and rules
    fetchApiKeys();
    fetchRules();
  }, []);

  const fetchApiKeys = async () => {
    try {
      const response = await axios.get(`${config.apiUrl}/api/settings/api-keys`);
      setApiKeys(response.data);
    } catch (error) {
      console.error('Error fetching API keys:', error);
      setSnackbar({
        open: true,
        message: 'Error fetching API keys',
        severity: 'error'
      });
    }
  };

  const fetchRules = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${config.apiUrl}/api/rules`);
      const rulesData = response.data.rules;

      // Calculate statistics
      const uniqueCategories = new Set(rulesData.map(rule => rule.category));
      setStats({
        total: rulesData.length,
        enabled: rulesData.filter(rule => rule.enabled).length,
        categories: uniqueCategories.size
      });

      setRules(rulesData);
    } catch (error) {
      console.error('Error fetching rules:', error);
      setSnackbar({
        open: true,
        message: 'Error fetching rules',
        severity: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSaveKeys = async () => {
    try {
      await axios.post(`${config.apiUrl}/api/settings/api-keys`, apiKeys);
      setSnackbar({
        open: true,
        message: 'API keys saved successfully',
        severity: 'success'
      });
    } catch (error) {
      console.error('Error saving API keys:', error);
      setSnackbar({
        open: true,
        message: 'Error saving API keys',
        severity: 'error'
      });
    }
  };

  const handleToggleRule = async (ruleId, enabled, category) => {
    try {
      await axios.post(`${config.apiUrl}/api/rules/toggle`, {
        rule_id: ruleId,
        enabled: !enabled,
        category
      });
      
      // Update local state
      const updatedRules = rules.map(rule =>
        rule.id === ruleId ? { ...rule, enabled: !enabled } : rule
      );
      setRules(updatedRules);

      // Update statistics
      setStats(prev => ({
        ...prev,
        enabled: updatedRules.filter(rule => rule.enabled).length
      }));

      setSnackbar({
        open: true,
        message: `Rule ${!enabled ? 'enabled' : 'disabled'} successfully`,
        severity: 'success'
      });
    } catch (error) {
      console.error('Error toggling rule:', error);
      setSnackbar({
        open: true,
        message: 'Error toggling rule',
        severity: 'error'
      });
    }
  };

  const handleChange = (event) => {
    const { name, value } = event.target;
    setApiKeys(prev => ({
      ...prev,
      [name]: value
    }));
  };

  return (
    <Box sx={{ maxWidth: 1200, margin: 'auto', mt: 4 }}>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>
      
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            API Keys
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="IP-API Key"
                name="IPAPI_KEY"
                value={apiKeys.IPAPI_KEY}
                onChange={handleChange}
                margin="normal"
                type="password"
                helperText="Enter your IP-API key for IP geolocation services"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="CrowdSec API Key"
                name="CROWDSEC_API_KEY"
                value={apiKeys.CROWDSEC_API_KEY}
                onChange={handleChange}
                margin="normal"
                type="password"
                helperText="Enter your CrowdSec API key for threat intelligence"
              />
            </Grid>
            <Grid item xs={12}>
              <Button
                variant="contained"
                color="primary"
                onClick={handleSaveKeys}
                sx={{ mt: 2 }}
              >
                Save API Keys
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6">
              Detection Rules
            </Typography>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Paper sx={{ px: 2, py: 1 }}>
                <Typography variant="body2" color="text.secondary">Total Rules</Typography>
                <Typography variant="h6">{stats.total}</Typography>
              </Paper>
              <Paper sx={{ px: 2, py: 1 }}>
                <Typography variant="body2" color="text.secondary">Enabled Rules</Typography>
                <Typography variant="h6">{stats.enabled}</Typography>
              </Paper>
              <Paper sx={{ px: 2, py: 1 }}>
                <Typography variant="body2" color="text.secondary">Categories</Typography>
                <Typography variant="h6">{stats.categories}</Typography>
              </Paper>
            </Box>
          </Box>

          <Divider sx={{ mb: 3 }} />

          <RuleList
            rules={rules}
            loading={loading}
            handleToggleRule={handleToggleRule}
          />
        </CardContent>
      </Card>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
      >
        <Alert
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default Settings;