import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  CircularProgress,
} from '@mui/material';
import {
  Assessment,
  Download,
  DateRange,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';

const ReportsPage: React.FC = () => {
  const [selectedReport, setSelectedReport] = useState<string>('');

  const { data: reports, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: async () => {
      // Mock data for now
      return [
        { id: '1', name: 'Security Summary', type: 'security', lastGenerated: '2024-01-15' },
        { id: '2', name: 'Vulnerability Report', type: 'vulnerability', lastGenerated: '2024-01-14' },
        { id: '3', name: 'Compliance Report', type: 'compliance', lastGenerated: '2024-01-13' },
      ];
    },
  });

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Reports
      </Typography>
      
      <Grid container spacing={3}>
        {reports?.map((report) => (
          <Grid item xs={12} md={6} lg={4} key={report.id}>
            <Card>
              <CardContent>
                <Box display="flex" alignItems="center" mb={2}>
                  <Assessment sx={{ mr: 1 }} />
                  <Typography variant="h6">{report.name}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Type: {report.type}
                </Typography>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Last Generated: {report.lastGenerated}
                </Typography>
                <Box mt={2}>
                  <Button
                    variant="contained"
                    startIcon={<Download />}
                    size="small"
                    onClick={() => setSelectedReport(report.id)}
                  >
                    Download
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Paper sx={{ mt: 3, p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Generate New Report
        </Typography>
        <Button
          variant="outlined"
          startIcon={<DateRange />}
          onClick={() => console.log('Generate report')}
        >
          Schedule Report
        </Button>
      </Paper>
    </Box>
  );
};

export default ReportsPage;