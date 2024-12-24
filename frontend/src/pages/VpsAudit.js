import React, { useState, useEffect } from 'react';

import {
  Box,
  Button,
  Typography,
  Paper,
  Grid,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Alert,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as RunIcon,
  History as HistoryIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import axios from 'axios';
import config from '../config';

// Auth type enum to match backend
const AuthType = {
    PASSWORD: "password",
    KEY: "key"
};

const AuditResultView = ({ audit }) => {
  return (
    <Box sx={{ mt: 2, mb: 2 }}>
      {audit.timestamp && (
        <Typography variant="subtitle2" color="textSecondary" gutterBottom>
          {new Date(audit.timestamp).toLocaleString()}
        </Typography>
      )}
      
      {/* System Information */}
      {audit.results && audit.results.system_info && (
        <Paper sx={{ p: 2, mb: 2 }} variant="outlined">
          <Typography variant="h6" gutterBottom>System Information</Typography>
          <Grid container spacing={2}>
            {Object.entries(audit.results.system_info).map(([key, value]) => (
              <Grid item xs={12} key={key}>
                <Typography variant="body2">
                  <strong>{key.charAt(0).toUpperCase() + key.slice(1)}:</strong> {value}
                </Typography>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}
      
      {/* Security Issues */}
      {audit.results && audit.results.security_issues && audit.results.security_issues.length > 0 && (
        <Paper sx={{ p: 2, mb: 2, bgcolor: '#ffebee' }} variant="outlined">
          <Typography variant="h6" color="error" gutterBottom>
            Security Issues
          </Typography>
          {audit.results.security_issues.map((issue, i) => (
            <Typography key={i} variant="body2" color="error" gutterBottom>
              • {issue}
            </Typography>
          ))}
        </Paper>
      )}
      
      {/* Warnings */}
      {audit.results && audit.results.warnings && audit.results.warnings.length > 0 && (
        <Paper sx={{ p: 2, mb: 2, bgcolor: '#fff3e0' }} variant="outlined">
          <Typography variant="h6" color="warning.dark" gutterBottom>
            Warnings
          </Typography>
          {audit.results.warnings.map((warning, i) => (
            <Typography key={i} variant="body2" color="warning.dark" gutterBottom>
              • {warning}
            </Typography>
          ))}
        </Paper>
      )}
      
      {/* Raw Output Toggle */}
      <Box sx={{ mt: 2 }}>
        <Button
          size="small"
          onClick={() => {
            const elem = document.getElementById(`raw-output-${audit.id || 'latest'}`);
            if (elem) {
              elem.style.display = elem.style.display === 'none' ? 'block' : 'none';
            }
          }}
        >
          Toggle Raw Output
        </Button>
        <Box
          id={`raw-output-${audit.id || 'latest'}`}
          sx={{ mt: 1, display: 'none' }}
        >
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem' }}>
            {audit.results && audit.results.raw_output}
          </pre>
        </Box>
      </Box>
    </Box>
  );
};

const VpsAudit = () => {
  const [error, setError] = useState('');
  const [servers, setServers] = useState([]);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedServer, setSelectedServer] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    ip_address: '',
    ssh_username: '',
    auth_type: AuthType.PASSWORD,
    sshPassword: '',
    ssh_key_path: '',
    ssh_key_passphrase: '',
  });

  const [auditResults, setAuditResults] = useState(null);
  const [showAuditResults, setShowAuditResults] = useState(false);

  useEffect(() => {
    fetchServers();
  }, []);

  const fetchServers = async () => {
    try {
      const response = await axios.get(`${config.vpsAuditUrl}/servers`);
      setServers(response.data || []);
      setError('');
    } catch (err) {
      console.error('Error fetching servers:', err);
      setError('Failed to connect to server');
    }
  };

  const handleOpenDialog = (server = null) => {
    if (server) {
      setFormData({
        name: server.name,
        ip_address: server.ip_address,
        ssh_username: server.ssh_username,
        auth_type: server.auth_type,
        sshPassword: server.sshPassword,
        ssh_private_key: '',
        ssh_key_passphrase: '',
      });
      setSelectedServer(server);
    } else {
      setFormData({
        name: '',
        ip_address: '',
        ssh_username: '',
        auth_type: AuthType.PASSWORD,
        sshPassword: '',
        ssh_private_key: '',
        ssh_key_passphrase: '',
      });
      setSelectedServer(null);
    }
    setOpenDialog(true);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setError('');
  };

  const handleSubmit = async () => {
    try {
      if (!formData.name || !formData.ip_address || !formData.ssh_username) {
        setError('Please fill in all required fields');
        return;
      }

      if (formData.auth_type === AuthType.PASSWORD && !formData.sshPassword) {
        setError('Password is required for password authentication');
        return;
      }
      if (formData.auth_type === AuthType.KEY && !formData.ssh_private_key) {
        setError('Private key is required for key authentication');
        return;
      }

      let requestData = {
        name: formData.name,
        ip_address: formData.ip_address,
        ssh_username: formData.ssh_username,
        sshPassword: formData.sshPassword,
        ssh_key_path: formData.ssh_private_key,
      };
      if (selectedServer) {
        requestData = { ...requestData, id: selectedServer.id };
      }
      await axios.post(`${config.vpsAuditUrl}/servers`, requestData);
      fetchServers();
      handleCloseDialog();
    } catch (err) {
      console.error('Error saving server:', err);
      setError(err.response?.data?.detail || 'Failed to save server');
    }
  };

  const handleDelete = async (serverId) => {
    if (window.confirm('Are you sure you want to delete this server?')) {
      try {
        await axios.delete(`${config.vpsAuditUrl}/servers/${serverId}`);
        fetchServers();
      } catch (err) {
        console.error('Error deleting server:', err);
        setError('Failed to delete server');
      }
    }
  };

  const handleRunAudit = async (serverId) => {
    try {
      const response = await axios.post(
        `${config.vpsAuditUrl}/servers/${serverId}/audit`
      );
      setAuditResults(response.data);
      setShowAuditResults(true);
      setError('');
    } catch (err) {
      console.error('Error running audit:', err);
      
      const errorDetail = err.response?.data?.detail || {};
      const errorMessage = typeof errorDetail === 'object' ?
        errorDetail.error :
        errorDetail || 'Failed to run audit';
      
      switch (err.response?.status) {
        case 401:
          setError(`Authentication failed: ${errorMessage}`);
          break;
        case 400:
          setError(`Configuration error: ${errorMessage}`);
          break;
        case 503:
          setError(`Connection failed: ${errorMessage}`);
          break;
        case 404:
          setError(`Server not found: ${errorMessage}`);
          break;
        default:
          setError(`Audit failed: ${errorMessage}`);
      }
    }
  };

  const handleViewHistory = async (serverId) => {
    try {
      const response = await axios.get(
        `${config.vpsAuditUrl}/servers/${serverId}/audits`
      );
      setAuditResults(response.data);
      setShowAuditResults(true);
    } catch (err) {
      console.error('Error fetching audit history:', err);
      setError('Failed to fetch audit history');
    }
  };

  return (
    <Box p={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">VPS Audit</Typography>
        <Button
          variant="contained"
          color="primary"
          startIcon={<AddIcon />}
          onClick={() => handleOpenDialog()}
        >
          Add Server
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {servers.map((server) => (
          <Grid item xs={12} md={6} lg={4} key={server.id}>
            <Paper sx={{ p: 2 }}>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="h6">{server.name}</Typography>
                <Box>
                  <IconButton onClick={() => handleOpenDialog(server)} size="small">
                    <EditIcon />
                  </IconButton>
                  <IconButton onClick={() => handleDelete(server.id)} size="small">
                    <DeleteIcon />
                  </IconButton>
                </Box>
              </Box>
              <Typography variant="body2" color="textSecondary">
                IP: {server.ip_address}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Username: {server.ssh_username}
              </Typography>
              <Typography variant="body2" color="textSecondary">
                Auth Type: {server.auth_type}
              </Typography>
              <Box mt={2} display="flex" justifyContent="space-between">
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<RunIcon />}
                  onClick={() => handleRunAudit(server.id)}
                  size="small"
                >
                  Run Audit
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<HistoryIcon />}
                  onClick={() => handleViewHistory(server.id)}
                  size="small"
                >
                  History
                </Button>
              </Box>
            </Paper>
          </Grid>
        ))}
      </Grid>

      <Dialog open={openDialog} onClose={handleCloseDialog} maxWidth="sm" fullWidth>
        <DialogTitle>
          {selectedServer ? 'Edit Server' : 'Add Server'}
        </DialogTitle>
        <DialogContent>
          <Box mt={2}>
            <TextField
              fullWidth
              label="Server Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              margin="normal"
              required
            />
            <TextField
              fullWidth
              label="IP Address"
              value={formData.ip_address}
              onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
              margin="normal"
              required
            />
            <TextField
              fullWidth
              label="SSH Username"
              value={formData.ssh_username}
              onChange={(e) => setFormData({ ...formData, ssh_username: e.target.value })}
              margin="normal"
              required
            />
            <FormControl component="fieldset" margin="normal">
              <FormLabel component="legend">Authentication Type</FormLabel>
              <RadioGroup
                value={formData.auth_type}
                onChange={(e) => setFormData({ ...formData, auth_type: e.target.value })}
              >
                <FormControlLabel value={AuthType.PASSWORD} control={<Radio />} label="Password" />
                <FormControlLabel value={AuthType.KEY} control={<Radio />} label="SSH Key" />
              </RadioGroup>
            </FormControl>
            {formData.auth_type === AuthType.PASSWORD ? (
              <TextField
                fullWidth
                type="password"
                label="SSH Password"
                value={formData.sshPassword}
                onChange={(e) => setFormData({ ...formData, sshPassword: e.target.value })}
                margin="normal"
                required
              />
            ) : (
              <>
                <TextField
                  fullWidth
                  multiline
                  rows={4}
                  label="SSH Private Key"
                  value={formData.ssh_private_key}
                  onChange={(e) =>
                    setFormData({ ...formData, ssh_private_key: e.target.value })
                  }
                  margin="normal"
                  required
                />
                <TextField
                  fullWidth
                  type="password"
                  label="Key Passphrase (Optional)"
                  value={formData.ssh_key_passphrase}
                  onChange={(e) =>
                    setFormData({ ...formData, ssh_key_passphrase: e.target.value })
                  }
                  margin="normal"
                />
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>Cancel</Button>
          <Button onClick={handleSubmit} variant="contained" color="primary">
            Save
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={showAuditResults}
        onClose={() => setShowAuditResults(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Audit Results</DialogTitle>
        <DialogContent>
          {Array.isArray(auditResults) ? (
            // History view - multiple results
            auditResults.map((audit, index) => (
              <AuditResultView key={index} audit={audit} />
            ))
          ) : (
            // Single audit result
            auditResults && <AuditResultView audit={auditResults} />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAuditResults(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default VpsAudit;