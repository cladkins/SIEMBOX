import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  IconButton,
  Tooltip,
  Alert,
  CircularProgress,
  Grid,
  Pagination,
  Stack,
  InputAdornment,
  Modal,
  Card,
  CardContent,
  CardHeader,
  Divider
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ArrowUpward as ArrowUpwardIcon,
  ArrowDownward as ArrowDownwardIcon,
  Search as SearchIcon,
  Close as CloseIcon
} from '@mui/icons-material';
import config from '../config';

function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize] = useState(50);
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  const [selectedLog, setSelectedLog] = useState(null);
  const [filters, setFilters] = useState({
    timestamp: '',
    source: '',
    type: '',
    message: ''
  });

  // Modal styles
  const modalStyle = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    width: '80%',
    maxWidth: '800px',
    maxHeight: '90vh',
    overflow: 'auto',
    bgcolor: '#1a1a1a',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    boxShadow: 24,
    p: 0,
    color: '#fff'
  };

  const handleRowClick = (log) => {
    setSelectedLog(log);
  };

  const handleModalClose = () => {
    setSelectedLog(null);
  };

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${config.apiUrl}/api/logs?page=${page}&page_size=${pageSize}`);
      if (!response.ok) {
        throw new Error('Failed to fetch logs');
      }
      const data = await response.json();
      setLogs(data.logs);
      setTotalPages(data.total_pages);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(fetchLogs, 30000);
    return () => clearInterval(interval);
  }, [page, pageSize]); // Refetch when page or pageSize changes

  const handleRefresh = () => {
    fetchLogs();
  };

  const handlePageChange = (event, newPage) => {
    setPage(newPage);
  };

  // Handle sorting
  const handleSort = (key) => {
    setSortConfig((prevSort) => ({
      key,
      direction: prevSort.key === key && prevSort.direction === 'asc' ? 'desc' : 'asc'
    }));
  };

  // Handle filtering
  const handleFilterChange = (column, value) => {
    setFilters(prev => ({
      ...prev,
      [column]: value
    }));
  };

  // Filter logs
  const filteredLogs = logs.filter(log => {
    return Object.entries(filters).every(([key, value]) => {
      if (!value) return true;
      
      const searchValue = value.toLowerCase();
      switch (key) {
        case 'timestamp':
          return new Date(log.timestamp)
            .toLocaleString()
            .toLowerCase()
            .includes(searchValue);
        case 'source':
          return log.source.toLowerCase().includes(searchValue);
        case 'type':
          return log.type.toLowerCase().includes(searchValue);
        case 'message':
          return log.message.toLowerCase().includes(searchValue);
        default:
          return true;
      }
    });
  });

  // Sort logs
  const sortedLogs = [...filteredLogs].sort((a, b) => {
    const { key, direction } = sortConfig;
    let comparison = 0;

    switch (key) {
      case 'timestamp':
        comparison = new Date(a.timestamp) - new Date(b.timestamp);
        break;
      case 'source':
        comparison = a.source.localeCompare(b.source);
        break;
      case 'type':
        comparison = a.type.localeCompare(b.type);
        break;
      case 'message':
        comparison = a.message.localeCompare(b.message);
        break;
      default:
        comparison = 0;
    }

    return direction === 'asc' ? comparison : -comparison;
  });

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Grid container spacing={2} alignItems="center" sx={{ mb: 3 }}>
        <Grid item xs>
          <Typography variant="h4" sx={{ color: '#fff' }}>
            System Logs
          </Typography>
        </Grid>
        <Grid item>
          <Tooltip title="Refresh logs">
            <IconButton 
              onClick={handleRefresh} 
              sx={{ 
                color: '#4d9fff',
                '&:hover': {
                  backgroundColor: 'rgba(77, 159, 255, 0.1)',
                }
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Grid>
      </Grid>

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
          <CircularProgress sx={{ color: '#4d9fff' }} />
        </Box>
      ) : (
        <Stack spacing={2}>
          <TableContainer 
            component={Paper} 
            sx={{ 
              backgroundColor: '#1a1a1a',
              boxShadow: 'none',
              border: '1px solid rgba(255, 255, 255, 0.1)',
            }}
          >
            <Table>
              <TableHead>
                <TableRow>
                  {[
                    { id: 'timestamp', label: 'Timestamp' },
                    { id: 'source', label: 'Source' },
                    { id: 'type', label: 'Type' },
                    { id: 'message', label: 'Message' }
                  ].map((column) => (
                    <TableCell
                      key={column.id}
                      onClick={() => handleSort(column.id)}
                      sx={{
                        color: 'rgba(255, 255, 255, 0.7)',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                        cursor: 'pointer',
                        '&:hover': {
                          backgroundColor: 'rgba(255, 255, 255, 0.05)'
                        }
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        {column.label}
                        {sortConfig.key === column.id && (
                          <Box component="span" sx={{ ml: 1 }}>
                            {sortConfig.direction === 'asc' ? (
                              <ArrowUpwardIcon sx={{ fontSize: 16 }} />
                            ) : (
                              <ArrowDownwardIcon sx={{ fontSize: 16 }} />
                            )}
                          </Box>
                        )}
                      </Box>
                    </TableCell>
                  ))}
                </TableRow>
                <TableRow>
                  {[
                    'timestamp',
                    'source',
                    'type',
                    'message'
                  ].map((column) => (
                    <TableCell
                      key={column}
                      sx={{
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                        padding: '8px'
                      }}
                    >
                      <TextField
                        size="small"
                        placeholder={`Filter ${column}...`}
                        value={filters[column]}
                        onChange={(e) => handleFilterChange(column, e.target.value)}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SearchIcon sx={{ color: 'rgba(255, 255, 255, 0.3)' }} />
                            </InputAdornment>
                          ),
                          sx: {
                            color: '#fff',
                            '& .MuiOutlinedInput-notchedOutline': {
                              borderColor: 'rgba(255, 255, 255, 0.1)'
                            },
                            '&:hover .MuiOutlinedInput-notchedOutline': {
                              borderColor: 'rgba(255, 255, 255, 0.3)'
                            },
                            '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                              borderColor: '#4d9fff'
                            }
                          }
                        }}
                        sx={{
                          width: '100%',
                          '& .MuiInputBase-input': {
                            color: '#fff'
                          }
                        }}
                      />
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {sortedLogs.length === 0 ? (
                  <TableRow>
                    <TableCell 
                      colSpan={4} 
                      align="center"
                      sx={{ 
                        color: 'rgba(255, 255, 255, 0.5)',
                        borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                      }}
                    >
                      No logs found
                    </TableCell>
                  </TableRow>
                ) : (
                  sortedLogs.map((log) => (
                   <TableRow
                     key={log.id}
                     onClick={() => handleRowClick(log)}
                     sx={{
                       cursor: 'pointer',
                       '&:hover': {
                         backgroundColor: 'rgba(255, 255, 255, 0.05)'
                       }
                     }}
                   >
                     <TableCell
                       sx={{
                         color: '#fff',
                         borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                       }}
                     >
                       {new Date(log.timestamp).toLocaleString()}
                     </TableCell>
                     <TableCell
                       sx={{
                         color: '#fff',
                         borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                       }}
                     >
                       {log.source}
                     </TableCell>
                     <TableCell
                       sx={{
                         color: '#fff',
                         borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                       }}
                     >
                       {log.level}
                     </TableCell>
                     <TableCell
                       sx={{
                         maxWidth: '400px',
                         overflow: 'hidden',
                         textOverflow: 'ellipsis',
                         whiteSpace: 'nowrap',
                         color: '#fff',
                         borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
                       }}
                     >
                       {log.message}
                     </TableCell>
                   </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <Pagination
              count={totalPages}
              page={page}
              onChange={handlePageChange}
              color="primary"
              sx={{
                '& .MuiPaginationItem-root': {
                  color: '#fff',
                  '&.Mui-selected': {
                    backgroundColor: '#4d9fff',
                  },
                  '&:hover': {
                    backgroundColor: 'rgba(77, 159, 255, 0.2)',
                  },
                },
              }}
            />
          </Box>
        </Stack>
      )}

      {/* Log Details Modal */}
      <Modal
        open={selectedLog !== null}
        onClose={handleModalClose}
        aria-labelledby="log-details-modal"
      >
        <Card sx={modalStyle}>
          {selectedLog && (
            <>
              <CardHeader
                title={
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h6" component="div">
                      Log Details
                    </Typography>
                    <IconButton onClick={handleModalClose} sx={{ color: '#fff' }}>
                      <CloseIcon />
                    </IconButton>
                  </Box>
                }
                sx={{
                  borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
                  backgroundColor: '#2a2a2a'
                }}
              />
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Timestamp
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {new Date(selectedLog.timestamp).toLocaleString()}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Source
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {selectedLog.source}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Level
                    </Typography>
                    <Typography variant="body1" sx={{ mb: 2 }}>
                      {selectedLog.level}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                    <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                      Message
                    </Typography>
                    <Paper
                      sx={{
                        p: 2,
                        mt: 1,
                        backgroundColor: '#2a2a2a',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        borderRadius: 1
                      }}
                    >
                      <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                        {selectedLog.message}
                      </Typography>
                    </Paper>
                  </Grid>
                  {selectedLog.metadata && Object.keys(selectedLog.metadata).length > 0 && (
                    <Grid item xs={12}>
                      <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.1)', my: 2 }} />
                      <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
                        Additional Details
                      </Typography>
                      <Paper
                        sx={{
                          p: 2,
                          mt: 1,
                          backgroundColor: '#2a2a2a',
                          border: '1px solid rgba(255, 255, 255, 0.1)',
                          borderRadius: 1
                        }}
                      >
                        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                          {JSON.stringify(selectedLog.metadata, null, 2)}
                        </pre>
                      </Paper>
                    </Grid>
                  )}
                </Grid>
              </CardContent>
            </>
          )}
        </Card>
      </Modal>
    </Box>
  );
}

export default Logs;