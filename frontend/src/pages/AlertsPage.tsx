import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Alert as MuiAlert,
  Tabs,
  Tab,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  IconButton,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Checkbox,
  Card,
  CardContent,
  Snackbar,
  Pagination,
  Stack,
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  Cancel,
  MoreVert,
  Refresh,
  Notifications,
  Info,
  Timeline,
  BugReport,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../services/api';
import { websocketService } from '../services/websocket';
import { useAuthStore } from '../stores/authStore';
import type { Alert, AlertQueryParams } from '../types/api';

const getSeverityColor = (severity: string): 'error' | 'warning' | 'info' | 'success' | 'default' => {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'warning';
    case 'medium': return 'info';
    case 'low': return 'success';
    default: return 'default';
  }
};

const getStatusColor = (status: string): 'error' | 'warning' | 'info' | 'success' | 'default' => {
  switch (status) {
    case 'open': return 'error';
    case 'investigating': return 'warning';
    case 'resolved': return 'success';
    case 'false_positive': return 'default';
    default: return 'default';
  }
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'open': return <Warning />;
    case 'investigating': return <Info />;
    case 'resolved': return <CheckCircle />;
    case 'false_positive': return <Cancel />;
    default: return <Security />;
  }
};

export const AlertsPage: React.FC = () => {
  const { token } = useAuthStore();
  const queryClient = useQueryClient();
  const [tabValue, setTabValue] = useState(0);
  const [selectedAlerts, setSelectedAlerts] = useState<string[]>([]);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [bulkActionOpen, setBulkActionOpen] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  // Filter state
  const [filters, setFilters] = useState<AlertQueryParams>({
    page: 1,
    size: 50,
  });

  // Alerts query
  const {
    data: alertsData,
    isLoading: alertsLoading,
    error: alertsError,
    refetch: refetchAlerts,
  } = useQuery({
    queryKey: ['alerts', filters],
    queryFn: () => apiClient.getAlerts(filters),
    refetchInterval: 30000,
  });

  // Alert stats query
  const {
    data: alertStats,
  } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => apiClient.getAlertStats(),
    refetchInterval: 30000,
  });

  // Alert context query for details
  const {
    data: alertContext,
    isLoading: contextLoading,
  } = useQuery({
    queryKey: ['alert-context', selectedAlert?.id],
    queryFn: () => selectedAlert ? apiClient.getAlertContext(selectedAlert.id) : null,
    enabled: !!selectedAlert,
  });

  // Mutations
  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => apiClient.acknowledgeAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
      setSnackbar({ open: true, message: 'Alert acknowledged', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to acknowledge alert', severity: 'error' });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: (id: string) => apiClient.resolveAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
      setSnackbar({ open: true, message: 'Alert resolved', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to resolve alert', severity: 'error' });
    },
  });

  const falsePositiveMutation = useMutation({
    mutationFn: (id: string) => apiClient.markAlertFalsePositive(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
      setSnackbar({ open: true, message: 'Alert marked as false positive', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to mark alert as false positive', severity: 'error' });
    },
  });

  const bulkUpdateMutation = useMutation({
    mutationFn: ({ alertIds, status }: { alertIds: string[]; status: string }) => 
      apiClient.bulkUpdateAlerts(alertIds, status),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
      setSelectedAlerts([]);
      setBulkActionOpen(false);
      setSnackbar({ 
        open: true, 
        message: `Updated ${data.updated_count} alerts`, 
        severity: 'success' 
      });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update alerts', severity: 'error' });
    },
  });

  const notificationMutation = useMutation({
    mutationFn: (alertIds: string[]) => apiClient.sendAlertNotifications(alertIds),
    onSuccess: () => {
      setSnackbar({ open: true, message: 'Notifications sent', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to send notifications', severity: 'error' });
    },
  });

  // Real-time updates
  useEffect(() => {
    if (token) {
      websocketService.connect(token);

      const handleNewAlert = (alert: Alert) => {
        queryClient.invalidateQueries({ queryKey: ['alerts'] });
        queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
        setSnackbar({ 
          open: true, 
          message: `New ${alert.severity} alert: ${alert.title}`, 
          severity: 'error' 
        });
      };

      const handleAlertUpdated = () => {
        queryClient.invalidateQueries({ queryKey: ['alerts'] });
        queryClient.invalidateQueries({ queryKey: ['alert-stats'] });
      };

      websocketService.onNewAlert(handleNewAlert);
      websocketService.onAlertUpdated(handleAlertUpdated);

      return () => {
        websocketService.offNewAlert(handleNewAlert);
        websocketService.offAlertUpdated(handleAlertUpdated);
      };
    }
  }, [token, queryClient]);

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    // Update filters based on tab
    const newFilters = { ...filters, page: 1 };
    switch (newValue) {
      case 0: // All alerts
        delete newFilters.status;
        break;
      case 1: // Open alerts
        newFilters.status = 'open';
        break;
      case 2: // Investigating
        newFilters.status = 'investigating';
        break;
      case 3: // Resolved
        newFilters.status = 'resolved';
        break;
    }
    setFilters(newFilters);
  }, [filters]);

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlerts(prev => 
      prev.includes(alertId) 
        ? prev.filter(id => id !== alertId)
        : [...prev, alertId]
    );
  };

  const handleSelectAllAlerts = () => {
    if (selectedAlerts.length === alertsData?.items.length) {
      setSelectedAlerts([]);
    } else {
      setSelectedAlerts(alertsData?.items.map(alert => alert.id) || []);
    }
  };

  const handleActionClick = (event: React.MouseEvent<HTMLElement>, alert: Alert) => {
    setAnchorEl(event.currentTarget);
    setSelectedAlert(alert);
  };

  const handleActionClose = () => {
    setAnchorEl(null);
    setSelectedAlert(null);
  };

  const handleViewDetails = () => {
    setDetailsOpen(true);
    handleActionClose();
  };

  const handlePageChange = (_event: React.ChangeEvent<unknown>, page: number) => {
    setFilters(prev => ({ ...prev, page }));
  };

  const handleBulkAction = (status: string) => {
    if (selectedAlerts.length > 0) {
      bulkUpdateMutation.mutate({ alertIds: selectedAlerts, status });
    }
  };

  const handleSendNotifications = () => {
    if (selectedAlerts.length > 0) {
      notificationMutation.mutate(selectedAlerts);
    }
  };

  if (alertsLoading && !alertsData) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (alertsError) {
    return (
      <MuiAlert severity="error" action={
        <Button onClick={() => refetchAlerts()}>Retry</Button>
      }>
        Failed to load alerts: {alertsError instanceof Error ? alertsError.message : 'Unknown error'}
      </MuiAlert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Alert Management
      </Typography>

      {/* Stats Cards */}
      {alertStats && (
        <Box sx={{ 
          display: 'grid', 
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', md: '1fr 1fr 1fr 1fr' },
          gap: 3,
          mb: 3
        }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Total Alerts
                  </Typography>
                  <Typography variant="h4">
                    {alertStats.total_alerts.toLocaleString()}
                  </Typography>
                </Box>
                <Security color="primary" />
              </Box>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Open Alerts
                  </Typography>
                  <Typography variant="h4" color="error.main">
                    {alertStats.status_distribution.open.toLocaleString()}
                  </Typography>
                </Box>
                <Warning color="error" />
              </Box>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Critical Alerts
                  </Typography>
                  <Typography variant="h4" color="error.main">
                    {alertStats.severity_distribution.critical.toLocaleString()}
                  </Typography>
                </Box>
                <BugReport color="error" />
              </Box>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Last 24h
                  </Typography>
                  <Typography variant="h4">
                    {alertStats.recent_24h.toLocaleString()}
                  </Typography>
                </Box>
                <Timeline color="info" />
              </Box>
            </CardContent>
          </Card>
        </Box>
      )}

      {/* Connection Status and Actions */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box>
          <Chip
            label={`Real-time: ${websocketService.isConnected ? 'Connected' : 'Disconnected'}`}
            color={websocketService.isConnected ? 'success' : 'error'}
            size="small"
            sx={{ mr: 1 }}
          />
          <Chip
            label={`Total: ${alertsData?.total?.toLocaleString() || 0}`}
            color="info"
            size="small"
          />
        </Box>
        <Box>
          <Button
            startIcon={<Refresh />}
            onClick={() => refetchAlerts()}
            sx={{ mr: 1 }}
          >
            Refresh
          </Button>
          {selectedAlerts.length > 0 && (
            <>
              <Button
                startIcon={<Notifications />}
                onClick={handleSendNotifications}
                sx={{ mr: 1 }}
              >
                Notify ({selectedAlerts.length})
              </Button>
              <Button
                variant="contained"
                onClick={() => setBulkActionOpen(true)}
              >
                Bulk Actions ({selectedAlerts.length})
              </Button>
            </>
          )}
        </Box>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="alert tabs">
          <Tab label="All Alerts" />
          <Tab label="Open" />
          <Tab label="Investigating" />
          <Tab label="Resolved" />
        </Tabs>
      </Paper>

      {/* Alerts Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    checked={selectedAlerts.length === alertsData?.items.length && alertsData?.items.length > 0}
                    indeterminate={selectedAlerts.length > 0 && selectedAlerts.length < (alertsData?.items.length || 0)}
                    onChange={handleSelectAllAlerts}
                  />
                </TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Category</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Triggered</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alertsData?.items?.map((alert) => (
                <TableRow key={alert.id} hover>
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={selectedAlerts.includes(alert.id)}
                      onChange={() => handleSelectAlert(alert.id)}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={alert.severity.toUpperCase()}
                      color={getSeverityColor(alert.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight="medium">
                      {alert.title}
                    </Typography>
                    {alert.description && (
                      <Typography variant="caption" color="text.secondary">
                        {alert.description.length > 100 
                          ? `${alert.description.substring(0, 100)}...` 
                          : alert.description}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{alert.category}</TableCell>
                  <TableCell>
                    <Chip
                      icon={getStatusIcon(alert.status)}
                      label={alert.status.replace('_', ' ').toUpperCase()}
                      color={getStatusColor(alert.status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(alert.triggered_at).toLocaleString()}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <IconButton
                      onClick={(e) => handleActionClick(e, alert)}
                      size="small"
                    >
                      <MoreVert />
                    </IconButton>
                  </TableCell>
                </TableRow>
              )) || (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    <Typography variant="body2" color="text.secondary">
                      No alerts found
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
        {alertsData && alertsData.pages > 1 && (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
            <Pagination
              count={alertsData.pages}
              page={alertsData.page}
              onChange={handlePageChange}
              color="primary"
            />
          </Box>
        )}
      </Paper>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleActionClose}
      >
        <MenuItem onClick={handleViewDetails}>
          <Info sx={{ mr: 1 }} /> View Details
        </MenuItem>
        {selectedAlert?.status === 'open' && (
          <MenuItem onClick={() => {
            if (selectedAlert) {
              acknowledgeMutation.mutate(selectedAlert.id);
            }
            handleActionClose();
          }}>
            <Info sx={{ mr: 1 }} /> Acknowledge
          </MenuItem>
        )}
        {selectedAlert?.status !== 'resolved' && (
          <MenuItem onClick={() => {
            if (selectedAlert) {
              resolveMutation.mutate(selectedAlert.id);
            }
            handleActionClose();
          }}>
            <CheckCircle sx={{ mr: 1 }} /> Resolve
          </MenuItem>
        )}
        <MenuItem onClick={() => {
          if (selectedAlert) {
            falsePositiveMutation.mutate(selectedAlert.id);
          }
          handleActionClose();
        }}>
          <Cancel sx={{ mr: 1 }} /> Mark False Positive
        </MenuItem>
        <MenuItem onClick={() => {
          if (selectedAlert) {
            notificationMutation.mutate([selectedAlert.id]);
          }
          handleActionClose();
        }}>
          <Notifications sx={{ mr: 1 }} /> Send Notification
        </MenuItem>
      </Menu>

      {/* Alert Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Alert Details
          {selectedAlert && (
            <Chip
              label={selectedAlert.severity.toUpperCase()}
              color={getSeverityColor(selectedAlert.severity)}
              size="small"
              sx={{ ml: 2 }}
            />
          )}
        </DialogTitle>
        <DialogContent>
          {contextLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : alertContext ? (
            <Stack spacing={3}>
              <Box>
                <Typography variant="h6" gutterBottom>Alert Information</Typography>
                <Typography><strong>Title:</strong> {alertContext.alert.title}</Typography>
                <Typography><strong>Description:</strong> {alertContext.alert.description}</Typography>
                <Typography><strong>Category:</strong> {alertContext.alert.category}</Typography>
                <Typography><strong>Status:</strong> {alertContext.alert.status}</Typography>
                <Typography><strong>Triggered:</strong> {new Date(alertContext.alert.triggered_at).toLocaleString()}</Typography>
                {alertContext.alert.resolved_at && (
                  <Typography><strong>Resolved:</strong> {new Date(alertContext.alert.resolved_at).toLocaleString()}</Typography>
                )}
              </Box>

              {alertContext.parsed_log && (
                <Box>
                  <Typography variant="h6" gutterBottom>Related Log</Typography>
                  <Typography><strong>Source IP:</strong> {alertContext.parsed_log.source_ip}</Typography>
                  <Typography><strong>Message:</strong> {alertContext.parsed_log.message}</Typography>
                  <Typography><strong>Timestamp:</strong> {new Date(alertContext.parsed_log.timestamp).toLocaleString()}</Typography>
                </Box>
              )}

              {alertContext.detection_rule && (
                <Box>
                  <Typography variant="h6" gutterBottom>Detection Rule</Typography>
                  <Typography><strong>Name:</strong> {alertContext.detection_rule.name}</Typography>
                  <Typography><strong>Description:</strong> {alertContext.detection_rule.description}</Typography>
                </Box>
              )}

              {alertContext.related_alerts.length > 0 && (
                <Box>
                  <Typography variant="h6" gutterBottom>Related Alerts ({alertContext.related_alerts.length})</Typography>
                  {alertContext.related_alerts.slice(0, 5).map((relatedAlert) => (
                    <Typography key={relatedAlert.id} variant="body2">
                      • {relatedAlert.title} ({relatedAlert.severity})
                    </Typography>
                  ))}
                </Box>
              )}
            </Stack>
          ) : (
            <Typography>No details available</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Bulk Actions Dialog */}
      <Dialog
        open={bulkActionOpen}
        onClose={() => setBulkActionOpen(false)}
      >
        <DialogTitle>Bulk Actions ({selectedAlerts.length} alerts)</DialogTitle>
        <DialogContent>
          <Typography gutterBottom>
            Select an action to apply to all selected alerts:
          </Typography>
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Button
              variant="outlined"
              onClick={() => handleBulkAction('investigating')}
              startIcon={<Info />}
            >
              Mark as Investigating
            </Button>
            <Button
              variant="outlined"
              onClick={() => handleBulkAction('resolved')}
              startIcon={<CheckCircle />}
            >
              Mark as Resolved
            </Button>
            <Button
              variant="outlined"
              onClick={() => handleBulkAction('false_positive')}
              startIcon={<Cancel />}
            >
              Mark as False Positive
            </Button>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBulkActionOpen(false)}>Cancel</Button>
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