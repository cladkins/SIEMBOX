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
  Stack,
  Chip,
  Paper,
  Link,
  CircularProgress
} from '@mui/material';
import { styled } from '@mui/material/styles';
import InfoIcon from '@mui/icons-material/Info';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import BlockIcon from '@mui/icons-material/Block';
import ErrorIcon from '@mui/icons-material/Error';
import config from '../config';
import axios from 'axios';
import RuleList from '../components/RuleList';

const DarkCard = styled(Card)({
  backgroundColor: '#1a1a1a',
  color: '#fff',
  boxShadow: 'none',
  '& .MuiCardContent-root': {
    padding: '24px',
  }
});

const DarkTextField = styled(TextField)({
  '& .MuiOutlinedInput-root': {
    backgroundColor: '#2d2d2d',
    '& fieldset': {
      borderColor: 'rgba(255, 255, 255, 0.1)',
    },
    '&:hover fieldset': {
      borderColor: 'rgba(255, 255, 255, 0.2)',
    },
    '&.Mui-focused fieldset': {
      borderColor: '#4d9fff',
    }
  },
  '& .MuiInputLabel-root': {
    color: 'rgba(255, 255, 255, 0.7)',
  },
  '& .MuiInputBase-input': {
    color: '#fff',
  },
});

const StatusChip = styled(Chip)({
  height: '24px',
  '&.free': {
    backgroundColor: '#4d9fff33',
    color: '#4d9fff',
    border: 'none',
    '& .MuiChip-icon': {
      color: '#4d9fff',
    }
  },
  '&.warning': {
    backgroundColor: '#ff9f4d33',
    color: '#ff9f4d',
    border: 'none',
    '& .MuiChip-icon': {
      color: '#ff9f4d',
    }
  },
});

const SaveButton = styled(Button)({
  backgroundColor: '#4d9fff',
  color: '#fff',
  textTransform: 'uppercase',
  padding: '6px 16px',
  '&:hover': {
    backgroundColor: '#3d7fcf',
  },
  '&.Mui-disabled': {
    backgroundColor: '#4d9fff88',
    color: '#ffffff88',
  }
});

const StatsCard = styled(Paper)({
  backgroundColor: '#2d2d2d',
  padding: '12px 16px',
  borderRadius: '4px',
  '& .MuiTypography-root': {
    color: '#fff',
  }
});

const FieldLabel = styled(Typography)({
  color: 'rgba(255, 255, 255, 0.7)',
  marginBottom: '8px',
  fontWeight: 400,
  fontSize: '0.875rem',
});

const ApiLink = styled(Link)({
  color: '#4d9fff',
  textDecoration: 'none',
  '&:hover': {
    textDecoration: 'underline'
  }
});

const LoadingSpinner = styled(CircularProgress)({
  color: 'inherit',
  position: 'absolute',
  left: '50%',
  marginLeft: '-12px',
});

function Settings() {
  const [apiKeys, setApiKeys] = useState({
    IPAPI_KEY: '',
    CROWDSEC_API_KEY: ''
  });
  const [apiStatus, setApiStatus] = useState({
    ipapi_mode: 'free',
    ipapi_requests_remaining: null,
    ipapi_next_reset: null,
    ipapi_queue_size: 0,
    crowdsec_mode: 'disabled',
    crowdsec_requests_remaining: null,
    crowdsec_next_reset: null,
    crowdsec_queue_size: 0,
    batch_size: 0
  });
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
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

  const fetchRules = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${config.apiUrl}/api/rules`);
      const rulesData = response.data.rules;
      setRules(rulesData);
      
      // Update stats
      const categories = new Set(rulesData.map(rule => rule.category)).size;
      setStats({
        total: rulesData.length,
        enabled: rulesData.filter(rule => rule.enabled).length,
        categories: categories
      });
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

  useEffect(() => {
    fetchApiKeys();
    fetchApiStatus();
    fetchRules();
    const interval = setInterval(fetchApiStatus, 30000);
    return () => clearInterval(interval);
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

  const fetchApiStatus = async () => {
    try {
      const response = await axios.get(`${config.apiUrl}/iplookup/api/status`);
      setApiStatus(response.data);
    } catch (error) {
      console.error('Error fetching API status:', error);
    }
  };

  const validateCrowdSecKey = async () => {
    try {
      const response = await axios.post(`${config.apiUrl}/iplookup/validate/crowdsec`);
      return response.data.valid;
    } catch (error) {
      console.error('Error validating CrowdSec key:', error);
      return false;
    }
  };

  const handleSaveKeys = async () => {
    try {
      setSaving(true);
      
      // Save API keys
      await axios.post(`${config.apiUrl}/api/settings/api-keys`, apiKeys);
      
      // Validate CrowdSec key if provided
      if (apiKeys.CROWDSEC_API_KEY) {
        const isValid = await validateCrowdSecKey();
        if (!isValid) {
          setSnackbar({
            open: true,
            message: 'CrowdSec API key is invalid',
            severity: 'error'
          });
          setSaving(false);
          return;
        }
      }
      
      setSnackbar({
        open: true,
        message: 'API keys saved successfully',
        severity: 'success'
      });
      
      // Refresh status after saving
      await fetchApiStatus();
    } catch (error) {
      console.error('Error saving API keys:', error);
      setSnackbar({
        open: true,
        message: 'Error saving API keys',
        severity: 'error'
      });
    } finally {
      setSaving(false);
    }
  };

  const handleToggleRule = async (ruleId, enabled, category) => {
    try {
      await axios.post(`${config.apiUrl}/api/rules/toggle`, {
        rule_id: ruleId,
        enabled: !enabled,
        category
      });
      
      const updatedRules = rules.map(rule =>
        rule.id === ruleId ? { ...rule, enabled: !enabled } : rule
      );
      setRules(updatedRules);

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

  const getCrowdSecStatusChip = () => {
    switch (apiStatus.crowdsec_mode) {
      case 'enabled':
        return (
          <StatusChip
            icon={<CheckCircleIcon sx={{ fontSize: 16 }} />}
            label="ENABLED"
            className="free"
            size="small"
          />
        );
      case 'invalid':
        return (
          <StatusChip
            icon={<ErrorIcon sx={{ fontSize: 16 }} />}
            label="INVALID KEY"
            className="warning"
            size="small"
          />
        );
      default:
        return (
          <StatusChip
            icon={<BlockIcon sx={{ fontSize: 16 }} />}
            label="DISABLED"
            className="warning"
            size="small"
          />
        );
    }
  };

  return (
    <Box sx={{ maxWidth: 1200, margin: '0 auto', p: 3 }}>
      <Typography variant="h5" sx={{ color: '#fff', mb: 3, fontWeight: 500 }}>
        API Keys
      </Typography>
      
      <DarkCard sx={{ mb: 4 }}>
        <CardContent>
          <Stack spacing={4}>
            <Box>
              <FieldLabel>IP-API Key</FieldLabel>
              <DarkTextField
                fullWidth
                name="IPAPI_KEY"
                value={apiKeys.IPAPI_KEY}
                onChange={handleChange}
                type="password"
                variant="outlined"
                placeholder="Enter your IP-API key"
              />
              <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.5)', mt: 1, display: 'block', fontSize: '0.75rem' }}>
                Enter your IP-API key for IP geolocation services from{' '}
                <ApiLink 
                  href="https://ip-api.com/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                >
                  ip-api.com
                </ApiLink>
                . Currently using free tier (45 requests/minute, batch processing enabled)
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                <StatusChip
                  icon={<InfoIcon sx={{ fontSize: 16 }} />}
                  label={`${apiStatus.ipapi_mode.toUpperCase()} Mode`}
                  className="free"
                  size="small"
                />
                <StatusChip
                  icon={<WarningIcon sx={{ fontSize: 16 }} />}
                  label={`${apiStatus.ipapi_requests_remaining || 0}/${apiStatus.batch_size || 45} requests remaining`}
                  className="warning"
                  size="small"
                />
                {apiStatus.ipapi_queue_size > 0 && (
                  <StatusChip
                    icon={<InfoIcon sx={{ fontSize: 16 }} />}
                    label={`${apiStatus.ipapi_queue_size} requests queued`}
                    className="warning"
                    size="small"
                  />
                )}
              </Box>
            </Box>

            <Box>
              <FieldLabel>CrowdSec API Key</FieldLabel>
              <DarkTextField
                fullWidth
                name="CROWDSEC_API_KEY"
                value={apiKeys.CROWDSEC_API_KEY}
                onChange={handleChange}
                type="password"
                variant="outlined"
                placeholder="Enter your CrowdSec API key"
              />
              <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.5)', mt: 1, display: 'block', fontSize: '0.75rem' }}>
                Enter your CrowdSec API key from{' '}
                <ApiLink 
                  href="https://www.crowdsec.net/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                >
                  crowdsec.net
                </ApiLink>
                {' '}for threat intelligence. Limited to 30 requests per day with batch processing enabled.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                {getCrowdSecStatusChip()}
                {apiStatus.crowdsec_mode === 'enabled' && (
                  <>
                    <StatusChip
                      icon={<WarningIcon sx={{ fontSize: 16 }} />}
                      label={`${apiStatus.crowdsec_requests_remaining || 0}/30 daily requests remaining`}
                      className="warning"
                      size="small"
                    />
                    {apiStatus.crowdsec_queue_size > 0 && (
                      <StatusChip
                        icon={<InfoIcon sx={{ fontSize: 16 }} />}
                        label={`${apiStatus.crowdsec_queue_size} requests queued`}
                        className="warning"
                        size="small"
                      />
                    )}
                  </>
                )}
              </Box>
            </Box>

            <Box>
              <SaveButton 
                variant="contained" 
                onClick={handleSaveKeys}
                disabled={saving}
                startIcon={saving && <LoadingSpinner size={20} />}
              >
                {saving ? 'Saving...' : 'Save API Keys'}
              </SaveButton>
            </Box>
          </Stack>
        </CardContent>
      </DarkCard>

      <Typography variant="h5" sx={{ color: '#fff', mb: 3, mt: 4, fontWeight: 500 }}>
        Detection Rules
      </Typography>

      <DarkCard>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 2, mb: 3 }}>
            <StatsCard>
              <Typography variant="body2" color="text.secondary">Total Rules</Typography>
              <Typography variant="h6">{stats.total}</Typography>
            </StatsCard>
            <StatsCard>
              <Typography variant="body2" color="text.secondary">Enabled Rules</Typography>
              <Typography variant="h6">{stats.enabled}</Typography>
            </StatsCard>
            <StatsCard>
              <Typography variant="body2" color="text.secondary">Categories</Typography>
              <Typography variant="h6">{stats.categories}</Typography>
            </StatsCard>
          </Box>

          <RuleList
            rules={rules}
            loading={loading}
            handleToggleRule={handleToggleRule}
          />
        </CardContent>
      </DarkCard>

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