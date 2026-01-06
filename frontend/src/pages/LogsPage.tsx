import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  CircularProgress,
  Alert,
  Tabs,
  Tab,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../services/api';
import { websocketService } from '../services/websocket';
import { useAuthStore } from '../stores/authStore';
import type { ParsedLog, LogQueryParams } from '../types/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => (
  <div
    role="tabpanel"
    hidden={value !== index}
    id={`log-tabpanel-${index}`}
    aria-labelledby={`log-tab-${index}`}
    {...other}
  >
    {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
  </div>
);

export const LogsPage: React.FC = () => {
  const { token } = useAuthStore();
  const [tabValue, setTabValue] = useState(0);
  
  // Filter state
  const [filters] = useState<LogQueryParams>({
    page: 1,
    size: 50,
  });

  // Parsed logs query
  const {
    data: parsedLogsData,
    isLoading: parsedLogsLoading,
    error: parsedLogsError,
    refetch: refetchParsedLogs,
  } = useQuery({
    queryKey: ['logs', 'parsed', filters],
    queryFn: () => apiClient.getLogs(filters),
    refetchInterval: 30000, // Refetch every 30 seconds
    enabled: tabValue === 0,
  });

  // Raw logs query
  const {
    data: rawLogsData,
    isLoading: rawLogsLoading,
    error: rawLogsError,
    refetch: refetchRawLogs,
  } = useQuery({
    queryKey: ['logs', 'raw', filters],
    queryFn: () => apiClient.getRawLogs(filters),
    refetchInterval: 30000,
    enabled: tabValue === 1,
  });

  // Handle real-time log updates
  React.useEffect(() => {
    if (token) {
      websocketService.connect(token);

      const handleNewLog = (log: ParsedLog) => {
        // Invalidate queries to refresh data
        console.log('New log received:', log);
        refetchParsedLogs();
        if (tabValue === 1) {
          refetchRawLogs();
        }
      };

      websocketService.onNewLog(handleNewLog);

      return () => {
        websocketService.offNewLog(handleNewLog);
      };
    }
  }, [token, refetchParsedLogs]);

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  }, []);

  const currentData = tabValue === 0 ? parsedLogsData : rawLogsData;
  const currentLoading = tabValue === 0 ? parsedLogsLoading : rawLogsLoading;
  const currentError = tabValue === 0 ? parsedLogsError : rawLogsError;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Log Management
      </Typography>

      {/* Connection Status */}
      <Box sx={{ mb: 2 }}>
        <Chip
          label={`Real-time: ${websocketService.isConnected ? 'Connected' : 'Disconnected'}`}
          color={websocketService.isConnected ? 'success' : 'error'}
          size="small"
          sx={{ mr: 1 }}
        />
        <Chip
          label={`Total Logs: ${currentData?.total?.toLocaleString() || 0}`}
          color="info"
          size="small"
        />
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="log tabs">
          <Tab label="Parsed Logs" id="log-tab-0" aria-controls="log-tabpanel-0" />
          <Tab label="Raw Logs" id="log-tab-1" aria-controls="log-tabpanel-1" />
        </Tabs>
      </Paper>

      {/* Error Display */}
      {currentError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load logs: {currentError instanceof Error ? currentError.message : 'Unknown error'}
        </Alert>
      )}

      {/* Loading Display */}
      {currentLoading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
          <CircularProgress />
        </Box>
      )}

      {/* Parsed Logs Tab */}
      <TabPanel value={tabValue} index={0}>
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Log Level</TableCell>
                  <TableCell>Message</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {parsedLogsData?.items?.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>{new Date(log.timestamp).toLocaleString()}</TableCell>
                    <TableCell>{log.source_ip}</TableCell>
                    <TableCell>
                      <Chip 
                        label={log.log_level || 'INFO'} 
                        size="small"
                        color={log.log_level === 'ERROR' ? 'error' : log.log_level === 'WARN' ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>{log.message}</TableCell>
                  </TableRow>
                )) || (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No parsed logs found
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </TabPanel>

      {/* Raw Logs Tab */}
      <TabPanel value={tabValue} index={1}>
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Timestamp</TableCell>
                  <TableCell>Source IP</TableCell>
                  <TableCell>Source Type</TableCell>
                  <TableCell>Raw Message</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rawLogsData?.items?.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>{new Date(log.timestamp).toLocaleString()}</TableCell>
                    <TableCell>{log.source_ip}</TableCell>
                    <TableCell>{log.source_type}</TableCell>
                    <TableCell>
                      <Typography 
                        variant="body2" 
                        sx={{ 
                          fontFamily: 'monospace',
                          maxWidth: 400,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }}
                      >
                        {log.raw_message}
                      </Typography>
                    </TableCell>
                  </TableRow>
                )) || (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No raw logs found
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </TabPanel>
    </Box>
  );
};