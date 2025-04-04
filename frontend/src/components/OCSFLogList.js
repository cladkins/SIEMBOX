import React, { useState, useEffect } from 'react';
import { 
  Table, TableBody, TableCell, TableContainer, TableHead, 
  TableRow, Paper, TablePagination, Chip, Typography,
  Box, CircularProgress, TextField, Button, Grid,
  FormControl, InputLabel, Select, MenuItem
} from '@mui/material';
import { format } from 'date-fns';
import axios from 'axios';
import config from '../config';

const severityColors = {
  'Emergency': 'error',
  'Alert': 'error',
  'Critical': 'error',
  'Error': 'error',
  'Warning': 'warning',
  'Notice': 'info',
  'Informational': 'info',
  'Debug': 'default'
};

const OCSFLogList = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [totalLogs, setTotalLogs] = useState(0);
  const [filters, setFilters] = useState({
    startTime: '',
    endTime: '',
    category: '',
    severity: ''
  });

  const fetchLogs = async () => {
    setLoading(true);
    try {
      // Build query parameters
      const params = new URLSearchParams();
      params.append('page', page + 1); // API uses 1-based indexing
      params.append('page_size', rowsPerPage);
      
      if (filters.startTime) {
        params.append('start_time', new Date(filters.startTime).toISOString());
      }
      
      if (filters.endTime) {
        params.append('end_time', new Date(filters.endTime).toISOString());
      }
      
      if (filters.category) {
        params.append('category', filters.category);
      }
      
      if (filters.severity) {
        params.append('severity', filters.severity);
      }
      
      const response = await axios.get(`${config.API_URL}/api/ocsf-logs?${params.toString()}`);
      setLogs(response.data.logs);
      setTotalLogs(response.data.total);
    } catch (error) {
      console.error('Error fetching OCSF logs:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, rowsPerPage]);

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleFilterChange = (event) => {
    const { name, value } = event.target;
    setFilters(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const applyFilters = () => {
    setPage(0);
    fetchLogs();
  };

  const resetFilters = () => {
    setFilters({
      startTime: '',
      endTime: '',
      category: '',
      severity: ''
    });
    setPage(0);
    fetchLogs();
  };

  const formatTime = (timeStr) => {
    if (!timeStr) return 'N/A';
    try {
      return format(new Date(timeStr), 'yyyy-MM-dd HH:mm:ss');
    } catch (e) {
      return timeStr;
    }
  };

  const renderEndpointInfo = (endpoint) => {
    if (!endpoint) return 'N/A';
    
    let info = [];
    if (endpoint.hostname) info.push(`Host: ${endpoint.hostname}`);
    if (endpoint.ip) info.push(`IP: ${endpoint.ip}`);
    if (endpoint.port) info.push(`Port: ${endpoint.port}`);
    
    return info.join(', ') || 'N/A';
  };

  return (
    <div>
      <Typography variant="h5" gutterBottom>
        OCSF Logs
      </Typography>
      
      {/* Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} sm={6} md={3}>
            <TextField
              label="Start Time"
              type="datetime-local"
              name="startTime"
              value={filters.startTime}
              onChange={handleFilterChange}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <TextField
              label="End Time"
              type="datetime-local"
              name="endTime"
              value={filters.endTime}
              onChange={handleFilterChange}
              InputLabelProps={{ shrink: true }}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth>
              <InputLabel>Category</InputLabel>
              <Select
                name="category"
                value={filters.category}
                onChange={handleFilterChange}
                label="Category"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="System">System</MenuItem>
                <MenuItem value="Identity & Access Management">Identity & Access</MenuItem>
                <MenuItem value="Network">Network</MenuItem>
                <MenuItem value="Other">Other</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={6} md={2}>
            <FormControl fullWidth>
              <InputLabel>Severity</InputLabel>
              <Select
                name="severity"
                value={filters.severity}
                onChange={handleFilterChange}
                label="Severity"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="Emergency">Emergency</MenuItem>
                <MenuItem value="Alert">Alert</MenuItem>
                <MenuItem value="Critical">Critical</MenuItem>
                <MenuItem value="Error">Error</MenuItem>
                <MenuItem value="Warning">Warning</MenuItem>
                <MenuItem value="Notice">Notice</MenuItem>
                <MenuItem value="Informational">Informational</MenuItem>
                <MenuItem value="Debug">Debug</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2}>
            <Box display="flex" gap={1}>
              <Button variant="contained" onClick={applyFilters} fullWidth>
                Apply
              </Button>
              <Button variant="outlined" onClick={resetFilters} fullWidth>
                Reset
              </Button>
            </Box>
          </Grid>
        </Grid>
      </Paper>
      
      {loading ? (
        <Box display="flex" justifyContent="center" p={3}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table sx={{ minWidth: 650 }} aria-label="OCSF logs table">
              <TableHead>
                <TableRow>
                  <TableCell>Time</TableCell>
                  <TableCell>Category</TableCell>
                  <TableCell>Activity</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Message</TableCell>
                  <TableCell>Source</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      No logs found
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell>{formatTime(log.time)}</TableCell>
                      <TableCell>{log.category_name || 'N/A'}</TableCell>
                      <TableCell>{log.activity_name || 'N/A'}</TableCell>
                      <TableCell>
                        <Chip 
                          label={log.severity || 'Unknown'} 
                          color={severityColors[log.severity] || 'default'} 
                          size="small" 
                        />
                      </TableCell>
                      <TableCell>{log.message}</TableCell>
                      <TableCell>{renderEndpointInfo(log.src_endpoint)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50]}
            component="div"
            count={totalLogs}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </>
      )}
    </div>
  );
};

export default OCSFLogList;