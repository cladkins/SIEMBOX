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
  Stack
} from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import config from '../config';

function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize] = useState(50);

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

  const filteredLogs = logs.filter(log => 
    JSON.stringify(log).toLowerCase().includes(filter.toLowerCase())
  );

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
          <TextField
            label="Filter logs"
            variant="outlined"
            size="small"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            sx={{
              mr: 2,
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
            }}
          />
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
                  <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                    Timestamp
                  </TableCell>
                  <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                    Source
                  </TableCell>
                  <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                    Type
                  </TableCell>
                  <TableCell sx={{ color: 'rgba(255, 255, 255, 0.7)', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                    Message
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredLogs.length === 0 ? (
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
                  filteredLogs.map((log) => (
                    <TableRow key={log.id}>
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
                        {log.type}
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
    </Box>
  );
}

export default Logs;