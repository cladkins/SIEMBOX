import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Alert as MuiAlert,
  Tabs,
  Tab,
  Card,
  CardContent,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  MonitorHeart as HealthIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Send as TestIcon,
  ExpandMore,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Email,
  Webhook,
  Chat,
  Sms,
  Visibility,
  VisibilityOff,
} from '@mui/icons-material';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../services/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

interface NotificationSettings {
  email: {
    enabled: boolean;
    smtp_server: string;
    smtp_port: number;
    username: string;
    password: string;
    from_email: string;
    to_emails: string[];
    use_tls: boolean;
  };
  discord: {
    enabled: boolean;
    webhook_url: string;
    username: string;
  };
  webhook: {
    enabled: boolean;
    webhook_url: string;
    headers: Record<string, string>;
  };
  sms: {
    enabled: boolean;
    provider: string;
    from_number: string;
    to_numbers: string[];
  };
}

interface SystemSettings {
  log_retention_days: number;
  max_log_size_mb: number;
  auto_cleanup_enabled: boolean;
  backup_enabled: boolean;
  backup_frequency: string;
}

interface SecuritySettings {
  session_timeout_minutes: number;
  max_login_attempts: number;
  require_password_change: boolean;
  password_min_length: number;
  enable_2fa: boolean;
}

interface HealthResponse {
  status: string;
  timestamp: string;
  version?: string;
  database?: string;
}

interface SystemInfoResponse {
  status: string;
  timestamp: string;
  application: string;
  version: string;
}

interface DatabaseHealthResponse {
  status: string;
  connection: string;
  tables: string[];
  database_version: string;
  timestamp: string;
}

export const SettingsPage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [showPasswords, setShowPasswords] = useState(false);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [testType, setTestType] = useState<string>('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  // Settings state
  const [notificationSettings, setNotificationSettings] = useState<NotificationSettings>({
    email: {
      enabled: false,
      smtp_server: 'smtp.gmail.com',
      smtp_port: 587,
      username: '',
      password: '',
      from_email: '',
      to_emails: [],
      use_tls: true,
    },
    discord: {
      enabled: false,
      webhook_url: '',
      username: 'SIEM BOX',
    },
    webhook: {
      enabled: false,
      webhook_url: '',
      headers: { 'Content-Type': 'application/json' },
    },
    sms: {
      enabled: false,
      provider: 'twilio',
      from_number: '',
      to_numbers: [],
    },
  });

  const [systemSettings, setSystemSettings] = useState<SystemSettings>({
    log_retention_days: 30,
    max_log_size_mb: 1000,
    auto_cleanup_enabled: true,
    backup_enabled: false,
    backup_frequency: 'daily',
  });

  const [securitySettings, setSecuritySettings] = useState<SecuritySettings>({
    session_timeout_minutes: 30,
    max_login_attempts: 5,
    require_password_change: false,
    password_min_length: 8,
    enable_2fa: false,
  });

  // Health check query
  const {
    data: healthData,
    isLoading: healthLoading,
    refetch: refetchHealth,
  } = useQuery<HealthResponse>({
    queryKey: ['system-health'],
    queryFn: () => apiClient.healthCheck(),
    refetchInterval: 30000,
  });

  // Database health query
  const {
    data: dbHealthData,
    isLoading: dbHealthLoading,
  } = useQuery<DatabaseHealthResponse>({
    queryKey: ['database-health'],
    queryFn: () => fetch('/api/v1/health/database').then(res => res.json()),
    refetchInterval: 30000,
  });

  // System info query
  const {
    data: systemInfo,
  } = useQuery<SystemInfoResponse>({
    queryKey: ['system-info'],
    queryFn: () => fetch('/api/v1/health/live').then(res => res.json()),
    refetchInterval: 60000,
  });

  // Mutations for saving settings
  const saveNotificationMutation = useMutation({
    mutationFn: (settings: NotificationSettings) => 
      fetch('/api/v1/settings/notifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      }).then(res => res.json()),
    onSuccess: () => {
      setSnackbar({ open: true, message: 'Notification settings saved successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to save notification settings', severity: 'error' });
    },
  });

  const saveSystemMutation = useMutation({
    mutationFn: (settings: SystemSettings) => 
      fetch('/api/v1/settings/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      }).then(res => res.json()),
    onSuccess: () => {
      setSnackbar({ open: true, message: 'System settings saved successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to save system settings', severity: 'error' });
    },
  });

  const saveSecurityMutation = useMutation({
    mutationFn: (settings: SecuritySettings) => 
      fetch('/api/v1/settings/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      }).then(res => res.json()),
    onSuccess: () => {
      setSnackbar({ open: true, message: 'Security settings saved successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to save security settings', severity: 'error' });
    },
  });

  const testNotificationMutation = useMutation({
    mutationFn: (type: string) => 
      fetch(`/api/v1/settings/test-notification/${type}`, {
        method: 'POST',
      }).then(res => res.json()),
    onSuccess: () => {
      setSnackbar({ open: true, message: 'Test notification sent successfully', severity: 'success' });
      setTestDialogOpen(false);
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to send test notification', severity: 'error' });
    },
  });

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  }, []);

  const handleSaveNotifications = () => {
    saveNotificationMutation.mutate(notificationSettings);
  };

  const handleSaveSystem = () => {
    saveSystemMutation.mutate(systemSettings);
  };

  const handleSaveSecurity = () => {
    saveSecurityMutation.mutate(securitySettings);
  };

  const handleTestNotification = (type: string) => {
    setTestType(type);
    setTestDialogOpen(true);
  };

  const confirmTestNotification = () => {
    testNotificationMutation.mutate(testType);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
      case 'connected':
      case 'active':
        return <CheckCircle color="success" />;
      case 'warning':
        return <Warning color="warning" />;
      case 'unhealthy':
      case 'disconnected':
      case 'error':
        return <ErrorIcon color="error" />;
      default:
        return <InfoIcon color="info" />;
    }
  };

  const getStatusColor = (status: string): 'success' | 'warning' | 'error' | 'info' => {
    switch (status) {
      case 'healthy':
      case 'connected':
      case 'active':
        return 'success';
      case 'warning':
        return 'warning';
      case 'unhealthy':
      case 'disconnected':
      case 'error':
        return 'error';
      default:
        return 'info';
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Settings & Configuration
      </Typography>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="settings tabs">
          <Tab icon={<NotificationsIcon />} label="Notifications" />
          <Tab icon={<HealthIcon />} label="System Health" />
          <Tab icon={<StorageIcon />} label="Log Sources" />
          <Tab icon={<SecurityIcon />} label="Security" />
          <Tab icon={<InfoIcon />} label="System Info" />
        </Tabs>
      </Paper>

      {/* Notification Settings Tab */}
      <TabPanel value={tabValue} index={0}>
        <Stack spacing={3}>
          {/* Email Settings */}
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Email sx={{ mr: 1 }} />
                <Typography variant="h6">Email Notifications</Typography>
                <Box sx={{ ml: 'auto' }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notificationSettings.email.enabled}
                        onChange={(e) => setNotificationSettings(prev => ({
                          ...prev,
                          email: { ...prev.email, enabled: e.target.checked }
                        }))}
                      />
                    }
                    label="Enabled"
                  />
                </Box>
              </Box>
              
              <Stack spacing={2}>
                <TextField
                  fullWidth
                  label="SMTP Server"
                  value={notificationSettings.email.smtp_server}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    email: { ...prev.email, smtp_server: e.target.value }
                  }))}
                  disabled={!notificationSettings.email.enabled}
                />
                
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <TextField
                    sx={{ flex: 2 }}
                    label="Username"
                    value={notificationSettings.email.username}
                    onChange={(e) => setNotificationSettings(prev => ({
                      ...prev,
                      email: { ...prev.email, username: e.target.value }
                    }))}
                    disabled={!notificationSettings.email.enabled}
                  />
                  <TextField
                    sx={{ flex: 1 }}
                    label="Port"
                    type="number"
                    value={notificationSettings.email.smtp_port}
                    onChange={(e) => setNotificationSettings(prev => ({
                      ...prev,
                      email: { ...prev.email, smtp_port: parseInt(e.target.value) }
                    }))}
                    disabled={!notificationSettings.email.enabled}
                  />
                </Box>
                
                <TextField
                  fullWidth
                  label="Password"
                  type={showPasswords ? 'text' : 'password'}
                  value={notificationSettings.email.password}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    email: { ...prev.email, password: e.target.value }
                  }))}
                  disabled={!notificationSettings.email.enabled}
                  InputProps={{
                    endAdornment: (
                      <IconButton
                        onClick={() => setShowPasswords(!showPasswords)}
                        edge="end"
                      >
                        {showPasswords ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    ),
                  }}
                />
                
                <TextField
                  fullWidth
                  label="From Email"
                  value={notificationSettings.email.from_email}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    email: { ...prev.email, from_email: e.target.value }
                  }))}
                  disabled={!notificationSettings.email.enabled}
                />
                
                <TextField
                  fullWidth
                  label="To Emails (comma separated)"
                  value={notificationSettings.email.to_emails.join(', ')}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    email: { ...prev.email, to_emails: e.target.value.split(',').map(email => email.trim()) }
                  }))}
                  disabled={!notificationSettings.email.enabled}
                  placeholder="admin@example.com, security@example.com"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={notificationSettings.email.use_tls}
                      onChange={(e) => setNotificationSettings(prev => ({
                        ...prev,
                        email: { ...prev.email, use_tls: e.target.checked }
                      }))}
                      disabled={!notificationSettings.email.enabled}
                    />
                  }
                  label="Use TLS"
                />
                
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<TestIcon />}
                    onClick={() => handleTestNotification('email')}
                    disabled={!notificationSettings.email.enabled}
                  >
                    Test Email
                  </Button>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {/* Discord Settings */}
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Chat sx={{ mr: 1 }} />
                <Typography variant="h6">Discord Notifications</Typography>
                <Box sx={{ ml: 'auto' }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notificationSettings.discord.enabled}
                        onChange={(e) => setNotificationSettings(prev => ({
                          ...prev,
                          discord: { ...prev.discord, enabled: e.target.checked }
                        }))}
                      />
                    }
                    label="Enabled"
                  />
                </Box>
              </Box>
              
              <Stack spacing={2}>
                <TextField
                  fullWidth
                  label="Webhook URL"
                  value={notificationSettings.discord.webhook_url}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    discord: { ...prev.discord, webhook_url: e.target.value }
                  }))}
                  disabled={!notificationSettings.discord.enabled}
                  placeholder="https://discord.com/api/webhooks/..."
                />
                
                <TextField
                  fullWidth
                  label="Bot Username"
                  value={notificationSettings.discord.username}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    discord: { ...prev.discord, username: e.target.value }
                  }))}
                  disabled={!notificationSettings.discord.enabled}
                />
                
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<TestIcon />}
                    onClick={() => handleTestNotification('discord')}
                    disabled={!notificationSettings.discord.enabled}
                  >
                    Test Discord
                  </Button>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {/* Webhook Settings */}
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Webhook sx={{ mr: 1 }} />
                <Typography variant="h6">Webhook Notifications</Typography>
                <Box sx={{ ml: 'auto' }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notificationSettings.webhook.enabled}
                        onChange={(e) => setNotificationSettings(prev => ({
                          ...prev,
                          webhook: { ...prev.webhook, enabled: e.target.checked }
                        }))}
                      />
                    }
                    label="Enabled"
                  />
                </Box>
              </Box>
              
              <Stack spacing={2}>
                <TextField
                  fullWidth
                  label="Webhook URL"
                  value={notificationSettings.webhook.webhook_url}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    webhook: { ...prev.webhook, webhook_url: e.target.value }
                  }))}
                  disabled={!notificationSettings.webhook.enabled}
                  placeholder="https://your-webhook-endpoint.com/alerts"
                />
                
                <TextField
                  fullWidth
                  label="Custom Headers (JSON)"
                  multiline
                  rows={3}
                  value={JSON.stringify(notificationSettings.webhook.headers, null, 2)}
                  onChange={(e) => {
                    try {
                      const headers = JSON.parse(e.target.value);
                      setNotificationSettings(prev => ({
                        ...prev,
                        webhook: { ...prev.webhook, headers }
                      }));
                    } catch {
                      // Invalid JSON, keep the text for user to fix
                    }
                  }}
                  disabled={!notificationSettings.webhook.enabled}
                />
                
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<TestIcon />}
                    onClick={() => handleTestNotification('webhook')}
                    disabled={!notificationSettings.webhook.enabled}
                  >
                    Test Webhook
                  </Button>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {/* SMS Settings */}
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Sms sx={{ mr: 1 }} />
                <Typography variant="h6">SMS Notifications</Typography>
                <Box sx={{ ml: 'auto' }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={notificationSettings.sms.enabled}
                        onChange={(e) => setNotificationSettings(prev => ({
                          ...prev,
                          sms: { ...prev.sms, enabled: e.target.checked }
                        }))}
                      />
                    }
                    label="Enabled"
                  />
                </Box>
              </Box>
              
              <Stack spacing={2}>
                <FormControl fullWidth disabled={!notificationSettings.sms.enabled}>
                  <InputLabel>Provider</InputLabel>
                  <Select
                    value={notificationSettings.sms.provider}
                    label="Provider"
                    onChange={(e) => setNotificationSettings(prev => ({
                      ...prev,
                      sms: { ...prev.sms, provider: e.target.value }
                    }))}
                  >
                    <MenuItem value="twilio">Twilio</MenuItem>
                    <MenuItem value="aws_sns">AWS SNS</MenuItem>
                  </Select>
                </FormControl>
                
                <TextField
                  fullWidth
                  label="From Number"
                  value={notificationSettings.sms.from_number}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    sms: { ...prev.sms, from_number: e.target.value }
                  }))}
                  disabled={!notificationSettings.sms.enabled}
                  placeholder="+1234567890"
                />
                
                <TextField
                  fullWidth
                  label="To Numbers (comma separated)"
                  value={notificationSettings.sms.to_numbers.join(', ')}
                  onChange={(e) => setNotificationSettings(prev => ({
                    ...prev,
                    sms: { ...prev.sms, to_numbers: e.target.value.split(',').map(num => num.trim()) }
                  }))}
                  disabled={!notificationSettings.sms.enabled}
                  placeholder="+1987654321, +1555123456"
                />
                
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Button
                    variant="outlined"
                    startIcon={<TestIcon />}
                    onClick={() => handleTestNotification('sms')}
                    disabled={!notificationSettings.sms.enabled}
                  >
                    Test SMS
                  </Button>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Stack>

        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSaveNotifications}
            disabled={saveNotificationMutation.isPending}
          >
            Save Notification Settings
          </Button>
        </Box>
      </TabPanel>

      {/* System Health Tab */}
      <TabPanel value={tabValue} index={1}>
        <Stack spacing={3}>
          {/* Health Overview Cards */}
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            {/* Overall Health */}
            <Card sx={{ flex: 1, minWidth: 250 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="textSecondary" gutterBottom variant="overline">
                      System Status
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {healthLoading ? (
                        <CircularProgress size={20} />
                      ) : (
                        getStatusIcon(healthData?.status || 'unknown')
                      )}
                      <Typography variant="h6">
                        {healthData?.status?.toUpperCase() || 'UNKNOWN'}
                      </Typography>
                    </Box>
                  </Box>
                  <IconButton onClick={() => refetchHealth()}>
                    <RefreshIcon />
                  </IconButton>
                </Box>
              </CardContent>
            </Card>

            {/* Database Health */}
            <Card sx={{ flex: 1, minWidth: 250 }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom variant="overline">
                  Database
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {dbHealthLoading ? (
                    <CircularProgress size={20} />
                  ) : (
                    getStatusIcon(dbHealthData?.status || 'unknown')
                  )}
                  <Typography variant="h6">
                    {dbHealthData?.status?.toUpperCase() || 'UNKNOWN'}
                  </Typography>
                </Box>
                {dbHealthData && (
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    Tables: {dbHealthData.tables?.length || 0}
                  </Typography>
                )}
              </CardContent>
            </Card>

            {/* Version Info */}
            <Card sx={{ flex: 1, minWidth: 250 }}>
              <CardContent>
                <Typography color="textSecondary" gutterBottom variant="overline">
                  Version
                </Typography>
                <Typography variant="h6">
                  {systemInfo?.version || healthData?.version || 'Unknown'}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {systemInfo?.application || 'SIEM BOX'}
                </Typography>
              </CardContent>
            </Card>
          </Box>

          {/* Detailed Health Information */}
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Detailed System Information
              </Typography>
              
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography>Database Details</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  {dbHealthData ? (
                    <Stack spacing={1}>
                      <Typography><strong>Status:</strong> {dbHealthData.status}</Typography>
                      <Typography><strong>Connection:</strong> {dbHealthData.connection}</Typography>
                      <Typography><strong>Version:</strong> {dbHealthData.database_version}</Typography>
                      <Typography><strong>Tables:</strong></Typography>
                      <Box sx={{ ml: 2 }}>
                        {dbHealthData.tables?.map((table: string) => (
                          <Chip key={table} label={table} size="small" sx={{ mr: 1, mb: 1 }} />
                        ))}
                      </Box>
                    </Stack>
                  ) : (
                    <Typography>Loading database information...</Typography>
                  )}
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography>Service Status</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List>
                    <ListItem>
                      <ListItemText primary="API Service" />
                      <ListItemSecondaryAction>
                        <Chip 
                          label="Running" 
                          color="success" 
                          size="small"
                          icon={<CheckCircle />}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                    <ListItem>
                      <ListItemText primary="Database Service" />
                      <ListItemSecondaryAction>
                        <Chip 
                          label={dbHealthData?.status === 'healthy' ? 'Connected' : 'Disconnected'} 
                          color={getStatusColor(dbHealthData?.status || 'unknown')} 
                          size="small"
                          icon={getStatusIcon(dbHealthData?.status || 'unknown')}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                    <ListItem>
                      <ListItemText primary="Log Ingestion" />
                      <ListItemSecondaryAction>
                        <Chip 
                          label="Active" 
                          color="success" 
                          size="small"
                          icon={<CheckCircle />}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                    <ListItem>
                      <ListItemText primary="Detection Engine" />
                      <ListItemSecondaryAction>
                        <Chip 
                          label="Active" 
                          color="success" 
                          size="small"
                          icon={<CheckCircle />}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  </List>
                </AccordionDetails>
              </Accordion>
            </CardContent>
          </Card>
        </Stack>
      </TabPanel>

      {/* Log Sources Tab */}
      <TabPanel value={tabValue} index={2}>
        <Stack spacing={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Log Source Configuration
              </Typography>
              
              <Stack spacing={2}>
                <TextField
                  fullWidth
                  label="Log Retention (days)"
                  type="number"
                  value={systemSettings.log_retention_days}
                  onChange={(e) => setSystemSettings(prev => ({
                    ...prev,
                    log_retention_days: parseInt(e.target.value)
                  }))}
                />
                
                <TextField
                  fullWidth
                  label="Maximum Log Size (MB)"
                  type="number"
                  value={systemSettings.max_log_size_mb}
                  onChange={(e) => setSystemSettings(prev => ({
                    ...prev,
                    max_log_size_mb: parseInt(e.target.value)
                  }))}
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={systemSettings.auto_cleanup_enabled}
                      onChange={(e) => setSystemSettings(prev => ({
                        ...prev,
                        auto_cleanup_enabled: e.target.checked
                      }))}
                    />
                  }
                  label="Enable Automatic Cleanup"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={systemSettings.backup_enabled}
                      onChange={(e) => setSystemSettings(prev => ({
                        ...prev,
                        backup_enabled: e.target.checked
                      }))}
                    />
                  }
                  label="Enable Backup"
                />
                
                <FormControl fullWidth disabled={!systemSettings.backup_enabled}>
                  <InputLabel>Backup Frequency</InputLabel>
                  <Select
                    value={systemSettings.backup_frequency}
                    label="Backup Frequency"
                    onChange={(e) => setSystemSettings(prev => ({
                      ...prev,
                      backup_frequency: e.target.value
                    }))}
                  >
                    <MenuItem value="daily">Daily</MenuItem>
                    <MenuItem value="weekly">Weekly</MenuItem>
                    <MenuItem value="monthly">Monthly</MenuItem>
                  </Select>
                </FormControl>
              </Stack>
            </CardContent>
          </Card>
        </Stack>

        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSaveSystem}
            disabled={saveSystemMutation.isPending}
          >
            Save System Settings
          </Button>
        </Box>
      </TabPanel>

      {/* Security Tab */}
      <TabPanel value={tabValue} index={3}>
        <Stack spacing={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Authentication & Security
              </Typography>
              
              <Stack spacing={2}>
                <TextField
                  fullWidth
                  label="Session Timeout (minutes)"
                  type="number"
                  value={securitySettings.session_timeout_minutes}
                  onChange={(e) => setSecuritySettings(prev => ({
                    ...prev,
                    session_timeout_minutes: parseInt(e.target.value)
                  }))}
                />
                
                <TextField
                  fullWidth
                  label="Maximum Login Attempts"
                  type="number"
                  value={securitySettings.max_login_attempts}
                  onChange={(e) => setSecuritySettings(prev => ({
                    ...prev,
                    max_login_attempts: parseInt(e.target.value)
                  }))}
                />
                
                <TextField
                  fullWidth
                  label="Minimum Password Length"
                  type="number"
                  value={securitySettings.password_min_length}
                  onChange={(e) => setSecuritySettings(prev => ({
                    ...prev,
                    password_min_length: parseInt(e.target.value)
                  }))}
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.require_password_change}
                      onChange={(e) => setSecuritySettings(prev => ({
                        ...prev,
                        require_password_change: e.target.checked
                      }))}
                    />
                  }
                  label="Require Password Change on First Login"
                />
                
                <FormControlLabel
                  control={
                    <Switch
                      checked={securitySettings.enable_2fa}
                      onChange={(e) => setSecuritySettings(prev => ({
                        ...prev,
                        enable_2fa: e.target.checked
                      }))}
                    />
                  }
                  label="Enable Two-Factor Authentication"
                />
              </Stack>
            </CardContent>
          </Card>
        </Stack>

        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
          <Button
            variant="contained"
            startIcon={<SaveIcon />}
            onClick={handleSaveSecurity}
            disabled={saveSecurityMutation.isPending}
          >
            Save Security Settings
          </Button>
        </Box>
      </TabPanel>

      {/* System Info Tab */}
      <TabPanel value={tabValue} index={4}>
        <Stack spacing={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Information
              </Typography>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Application</Typography>
                  <Typography variant="body1">{systemInfo?.application || 'SIEM BOX'}</Typography>
                </Box>
                
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Version</Typography>
                  <Typography variant="body1">{systemInfo?.version || 'Unknown'}</Typography>
                </Box>
                
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Status</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {getStatusIcon(systemInfo?.status || 'unknown')}
                    <Typography variant="body1">{systemInfo?.status?.toUpperCase() || 'UNKNOWN'}</Typography>
                  </Box>
                </Box>
                
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Last Updated</Typography>
                  <Typography variant="body1">
                    {systemInfo?.timestamp ? new Date(systemInfo.timestamp).toLocaleString() : 'Unknown'}
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
          
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Database Information
              </Typography>
              
              <Stack spacing={2}>
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Connection Status</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {getStatusIcon(dbHealthData?.status || 'unknown')}
                    <Typography variant="body1">{dbHealthData?.connection || 'Unknown'}</Typography>
                  </Box>
                </Box>
                
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Database Version</Typography>
                  <Typography variant="body1">{dbHealthData?.database_version || 'Unknown'}</Typography>
                </Box>
                
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Tables</Typography>
                  <Box sx={{ mt: 1 }}>
                    {dbHealthData?.tables?.map((table: string) => (
                      <Chip key={table} label={table} size="small" sx={{ mr: 1, mb: 1 }} />
                    )) || <Typography variant="body2" color="text.secondary">No table information available</Typography>}
                  </Box>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Stack>
      </TabPanel>

      {/* Test Notification Dialog */}
      <Dialog open={testDialogOpen} onClose={() => setTestDialogOpen(false)}>
        <DialogTitle>Test Notification</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to send a test {testType} notification?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={confirmTestNotification}
            variant="contained"
            disabled={testNotificationMutation.isPending}
          >
            {testNotificationMutation.isPending ? 'Sending...' : 'Send Test'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
      >
        <MuiAlert
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </MuiAlert>
      </Snackbar>
    </Box>
  );
};