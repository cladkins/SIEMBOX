import React, { useState, useCallback } from 'react';
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
  Card,
  CardContent,
  Snackbar,
  Switch,
  FormControlLabel,
  TextField,
  Select,
  FormControl,
  InputLabel,
  Stack,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
} from '@mui/material';
import {
  Security,
  Warning,
  CheckCircle,
  Cancel,
  MoreVert,
  Refresh,
  Add,
  Edit,
  Delete,
  PlayArrow,
  Stop,
  ExpandMore,
  Code,
  Timeline,
  BugReport,
  Shield,
  Visibility,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../services/api';
import type { DetectionRule, CreateDetectionRuleRequest } from '../types/api';

const getSeverityColor = (severity: string): 'error' | 'warning' | 'info' | 'success' | 'default' => {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'warning';
    case 'medium': return 'info';
    case 'low': return 'success';
    default: return 'default';
  }
};

const getRuleTypeIcon = (ruleType: string) => {
  switch (ruleType) {
    case 'threshold': return <Timeline />;
    case 'pattern': return <Code />;
    case 'correlation': return <Security />;
    case 'anomaly': return <BugReport />;
    default: return <Shield />;
  }
};

const getRuleTypeColor = (ruleType: string): 'primary' | 'secondary' | 'success' | 'warning' => {
  switch (ruleType) {
    case 'threshold': return 'primary';
    case 'pattern': return 'secondary';
    case 'correlation': return 'success';
    case 'anomaly': return 'warning';
    default: return 'primary';
  }
};

export const RulesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [tabValue, setTabValue] = useState(0);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  // Filter state
  const [filters, setFilters] = useState({
    enabled_only: false,
    category: '',
    severity: '',
  });

  // Form state for create/edit
  const [formData, setFormData] = useState<Partial<CreateDetectionRuleRequest>>({
    name: '',
    description: '',
    rule_type: 'threshold',
    severity: 'medium',
    category: '',
    conditions: {},
    is_enabled: true,
  });

  // Rules query
  const {
    data: rules,
    isLoading: rulesLoading,
    error: rulesError,
    refetch: refetchRules,
  } = useQuery({
    queryKey: ['detection-rules', filters],
    queryFn: () => apiClient.getDetectionRules(filters),
    refetchInterval: 30000,
  });

  // Stats query
  const {
    data: stats,
  } = useQuery({
    queryKey: ['detection-stats'],
    queryFn: () => apiClient.getDetectionStats(),
    refetchInterval: 30000,
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: (rule: CreateDetectionRuleRequest) => apiClient.createDetectionRule(rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setCreateOpen(false);
      resetForm();
      setSnackbar({ open: true, message: 'Rule created successfully', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to create rule: ${error.message}`, severity: 'error' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<CreateDetectionRuleRequest> }) => 
      apiClient.updateDetectionRule(id, rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setEditOpen(false);
      resetForm();
      setSnackbar({ open: true, message: 'Rule updated successfully', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to update rule: ${error.message}`, severity: 'error' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteDetectionRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setDeleteOpen(false);
      setSnackbar({ open: true, message: 'Rule deleted successfully', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to delete rule: ${error.message}`, severity: 'error' });
    },
  });

  const enableMutation = useMutation({
    mutationFn: (id: string) => apiClient.enableDetectionRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setSnackbar({ open: true, message: 'Rule enabled', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to enable rule: ${error.message}`, severity: 'error' });
    },
  });

  const disableMutation = useMutation({
    mutationFn: (id: string) => apiClient.disableDetectionRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setSnackbar({ open: true, message: 'Rule disabled', severity: 'success' });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to disable rule: ${error.message}`, severity: 'error' });
    },
  });

  const initializeDefaultsMutation = useMutation({
    mutationFn: () => apiClient.initializeDefaultRules(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['detection-rules'] });
      queryClient.invalidateQueries({ queryKey: ['detection-stats'] });
      setSnackbar({ 
        open: true, 
        message: `Initialized ${data.created_count} default rules`, 
        severity: 'success' 
      });
    },
    onError: (error: Error) => {
      setSnackbar({ open: true, message: `Failed to initialize rules: ${error.message}`, severity: 'error' });
    },
  });

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    const newFilters = { ...filters };
    switch (newValue) {
      case 0: // All rules
        newFilters.enabled_only = false;
        break;
      case 1: // Enabled rules
        newFilters.enabled_only = true;
        break;
      case 2: // Disabled rules
        // We'll filter this in the component since the API doesn't have disabled_only
        newFilters.enabled_only = false;
        break;
    }
    setFilters(newFilters);
  }, [filters]);

  const handleActionClick = (event: React.MouseEvent<HTMLElement>, rule: DetectionRule) => {
    setAnchorEl(event.currentTarget);
    setSelectedRule(rule);
  };

  const handleActionClose = () => {
    setAnchorEl(null);
    setSelectedRule(null);
  };

  const handleViewDetails = () => {
    setDetailsOpen(true);
    handleActionClose();
  };

  const handleEdit = () => {
    if (selectedRule) {
      setFormData({
        name: selectedRule.name,
        description: selectedRule.description,
        rule_type: selectedRule.rule_type,
        severity: selectedRule.severity,
        category: selectedRule.category,
        conditions: selectedRule.conditions,
        is_enabled: selectedRule.is_enabled,
      });
      setEditOpen(true);
    }
    handleActionClose();
  };

  const handleDelete = () => {
    setDeleteOpen(true);
    handleActionClose();
  };

  const handleToggleEnabled = (rule: DetectionRule) => {
    if (rule.is_enabled) {
      disableMutation.mutate(rule.id);
    } else {
      enableMutation.mutate(rule.id);
    }
    handleActionClose();
  };

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      rule_type: 'threshold',
      severity: 'medium',
      category: '',
      conditions: {},
      is_enabled: true,
    });
  };

  const handleCreateSubmit = () => {
    if (formData.name && formData.rule_type && formData.severity && formData.category) {
      createMutation.mutate(formData as CreateDetectionRuleRequest);
    }
  };

  const handleEditSubmit = () => {
    if (selectedRule && formData.name && formData.rule_type && formData.severity && formData.category) {
      updateMutation.mutate({ 
        id: selectedRule.id, 
        rule: formData as CreateDetectionRuleRequest 
      });
    }
  };

  const handleDeleteConfirm = () => {
    if (selectedRule) {
      deleteMutation.mutate(selectedRule.id);
    }
  };

  const filteredRules = rules?.filter(rule => {
    if (tabValue === 2) { // Disabled rules tab
      return !rule.is_enabled;
    }
    return true;
  }) || [];

  if (rulesLoading && !rules) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 400 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (rulesError) {
    return (
      <MuiAlert severity="error" action={
        <Button onClick={() => refetchRules()}>Retry</Button>
      }>
        Failed to load detection rules: {rulesError instanceof Error ? rulesError.message : 'Unknown error'}
      </MuiAlert>
    );
  }

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Detection Rules Management
      </Typography>

      {/* Stats Cards */}
      {stats && (
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
                    Total Rules
                  </Typography>
                  <Typography variant="h4">
                    {stats.rules.total}
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
                    Enabled Rules
                  </Typography>
                  <Typography variant="h4" color="success.main">
                    {stats.rules.enabled}
                  </Typography>
                </Box>
                <CheckCircle color="success" />
              </Box>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Total Alerts
                  </Typography>
                  <Typography variant="h4">
                    {stats.alerts.total}
                  </Typography>
                </Box>
                <Warning color="warning" />
              </Box>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography color="textSecondary" gutterBottom variant="overline">
                    Recent 24h
                  </Typography>
                  <Typography variant="h4">
                    {stats.alerts.recent_24h}
                  </Typography>
                </Box>
                <Timeline color="info" />
              </Box>
            </CardContent>
          </Card>
        </Box>
      )}

      {/* Actions */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box>
          <Chip
            label={`Total: ${filteredRules.length} rules`}
            color="info"
            size="small"
          />
        </Box>
        <Box>
          <Button
            startIcon={<Refresh />}
            onClick={() => refetchRules()}
            sx={{ mr: 1 }}
          >
            Refresh
          </Button>
          <Button
            startIcon={<Add />}
            variant="outlined"
            onClick={() => setCreateOpen(true)}
            sx={{ mr: 1 }}
          >
            Create Rule
          </Button>
          <Button
            startIcon={<Security />}
            variant="contained"
            onClick={() => initializeDefaultsMutation.mutate()}
            disabled={initializeDefaultsMutation.isPending}
          >
            Initialize Defaults
          </Button>
        </Box>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="rule tabs">
          <Tab label="All Rules" />
          <Tab label="Enabled" />
          <Tab label="Disabled" />
        </Tabs>
      </Paper>

      {/* Rules Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Status</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Category</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredRules.map((rule) => (
                <TableRow key={rule.id} hover>
                  <TableCell>
                    <Chip
                      icon={rule.is_enabled ? <CheckCircle /> : <Cancel />}
                      label={rule.is_enabled ? 'Enabled' : 'Disabled'}
                      color={rule.is_enabled ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight="medium">
                      {rule.name}
                    </Typography>
                    {rule.description && (
                      <Typography variant="caption" color="text.secondary">
                        {rule.description.length > 100 
                          ? `${rule.description.substring(0, 100)}...` 
                          : rule.description}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      icon={getRuleTypeIcon(rule.rule_type)}
                      label={rule.rule_type.toUpperCase()}
                      color={getRuleTypeColor(rule.rule_type)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{rule.category}</TableCell>
                  <TableCell>
                    <Chip
                      label={rule.severity.toUpperCase()}
                      color={getSeverityColor(rule.severity)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {new Date(rule.created_at).toLocaleDateString()}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <IconButton
                      onClick={(e) => handleActionClick(e, rule)}
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
                      No rules found
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleActionClose}
      >
        <MenuItem onClick={handleViewDetails}>
          <Visibility sx={{ mr: 1 }} /> View Details
        </MenuItem>
        <MenuItem onClick={handleEdit}>
          <Edit sx={{ mr: 1 }} /> Edit Rule
        </MenuItem>
        <MenuItem onClick={() => handleToggleEnabled(selectedRule!)}>
          {selectedRule?.is_enabled ? (
            <>
              <Stop sx={{ mr: 1 }} /> Disable Rule
            </>
          ) : (
            <>
              <PlayArrow sx={{ mr: 1 }} /> Enable Rule
            </>
          )}
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleDelete} sx={{ color: 'error.main' }}>
          <Delete sx={{ mr: 1 }} /> Delete Rule
        </MenuItem>
      </Menu>

      {/* Rule Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Rule Details
          {selectedRule && (
            <Chip
              label={selectedRule.severity.toUpperCase()}
              color={getSeverityColor(selectedRule.severity)}
              size="small"
              sx={{ ml: 2 }}
            />
          )}
        </DialogTitle>
        <DialogContent>
          {selectedRule && (
            <Stack spacing={3}>
              <Box>
                <Typography variant="h6" gutterBottom>Basic Information</Typography>
                <Typography><strong>Name:</strong> {selectedRule.name}</Typography>
                <Typography><strong>Description:</strong> {selectedRule.description}</Typography>
                <Typography><strong>Type:</strong> {selectedRule.rule_type}</Typography>
                <Typography><strong>Category:</strong> {selectedRule.category}</Typography>
                <Typography><strong>Severity:</strong> {selectedRule.severity}</Typography>
                <Typography><strong>Status:</strong> {selectedRule.is_enabled ? 'Enabled' : 'Disabled'}</Typography>
                <Typography><strong>Created:</strong> {new Date(selectedRule.created_at).toLocaleString()}</Typography>
                <Typography><strong>Updated:</strong> {new Date(selectedRule.updated_at).toLocaleString()}</Typography>
              </Box>

              <Box>
                <Typography variant="h6" gutterBottom>Rule Configuration</Typography>
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMore />}>
                    <Typography>Conditions</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <pre style={{ 
                      backgroundColor: '#f5f5f5', 
                      padding: '16px', 
                      borderRadius: '4px',
                      overflow: 'auto',
                      fontSize: '12px'
                    }}>
                      {JSON.stringify(selectedRule.conditions, null, 2)}
                    </pre>
                  </AccordionDetails>
                </Accordion>
              </Box>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Create Rule Dialog */}
      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create Detection Rule</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              fullWidth
              label="Rule Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
            <TextField
              fullWidth
              label="Description"
              multiline
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
            <Stack direction="row" spacing={2}>
              <FormControl fullWidth>
                <InputLabel>Rule Type</InputLabel>
                <Select
                  value={formData.rule_type}
                  label="Rule Type"
                  onChange={(e) => setFormData({ ...formData, rule_type: e.target.value as 'threshold' | 'pattern' | 'correlation' | 'anomaly' })}
                >
                  <MenuItem value="threshold">Threshold</MenuItem>
                  <MenuItem value="pattern">Pattern</MenuItem>
                  <MenuItem value="correlation">Correlation</MenuItem>
                  <MenuItem value="anomaly">Anomaly</MenuItem>
                </Select>
              </FormControl>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={formData.severity}
                  label="Severity"
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value as 'low' | 'medium' | 'high' | 'critical' })}
                >
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
            </Stack>
            <TextField
              fullWidth
              label="Category"
              value={formData.category}
              onChange={(e) => setFormData({ ...formData, category: e.target.value })}
              required
              placeholder="e.g., brute_force, web_attack, malware"
            />
            <TextField
              fullWidth
              label="Conditions (JSON)"
              multiline
              rows={8}
              value={JSON.stringify(formData.conditions, null, 2)}
              onChange={(e) => {
                try {
                  const conditions = JSON.parse(e.target.value);
                  setFormData({ ...formData, conditions });
                } catch {
                  // Invalid JSON, keep the text for user to fix
                }
              }}
              placeholder='{"log_type": "authentication", "field_conditions": {"action": "Failed"}}'
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.is_enabled}
                  onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                />
              }
              label="Enable Rule"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleCreateSubmit}
            variant="contained"
            disabled={createMutation.isPending}
          >
            Create Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Rule Dialog */}
      <Dialog
        open={editOpen}
        onClose={() => setEditOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Edit Detection Rule</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              fullWidth
              label="Rule Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
            <TextField
              fullWidth
              label="Description"
              multiline
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
            <Stack direction="row" spacing={2}>
              <FormControl fullWidth>
                <InputLabel>Rule Type</InputLabel>
                <Select
                  value={formData.rule_type}
                  label="Rule Type"
                  onChange={(e) => setFormData({ ...formData, rule_type: e.target.value as 'threshold' | 'pattern' | 'correlation' | 'anomaly' })}
                >
                  <MenuItem value="threshold">Threshold</MenuItem>
                  <MenuItem value="pattern">Pattern</MenuItem>
                  <MenuItem value="correlation">Correlation</MenuItem>
                  <MenuItem value="anomaly">Anomaly</MenuItem>
                </Select>
              </FormControl>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={formData.severity}
                  label="Severity"
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value as 'low' | 'medium' | 'high' | 'critical' })}
                >
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
            </Stack>
            <TextField
              fullWidth
              label="Category"
              value={formData.category}
              onChange={(e) => setFormData({ ...formData, category: e.target.value })}
              required
            />
            <TextField
              fullWidth
              label="Conditions (JSON)"
              multiline
              rows={8}
              value={JSON.stringify(formData.conditions, null, 2)}
              onChange={(e) => {
                try {
                  const conditions = JSON.parse(e.target.value);
                  setFormData({ ...formData, conditions });
                } catch {
                  // Invalid JSON, keep the text for user to fix
                }
              }}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={formData.is_enabled}
                  onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                />
              }
              label="Enable Rule"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleEditSubmit}
            variant="contained"
            disabled={updateMutation.isPending}
          >
            Update Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
      >
        <DialogTitle>Delete Detection Rule</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the rule "{selectedRule?.name}"? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)}>Cancel</Button>
          <Button 
            onClick={handleDeleteConfirm}
            color="error"
            variant="contained"
            disabled={deleteMutation.isPending}
          >
            Delete
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