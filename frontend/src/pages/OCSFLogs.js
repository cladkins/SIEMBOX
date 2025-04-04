import React from 'react';
import { Container, Typography, Box, Paper } from '@mui/material';
import OCSFLogList from '../components/OCSFLogList';

const OCSFLogs = () => {
  return (
    <Container maxWidth="xl">
      <Box sx={{ mt: 4, mb: 4 }}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h4" gutterBottom>
            OCSF Logs
          </Typography>
          <Typography variant="body1" paragraph>
            View and analyze logs in Open Cybersecurity Schema Framework (OCSF) format. 
            OCSF provides a standardized schema for security events, enhancing interoperability 
            with other security tools and platforms.
          </Typography>
        </Paper>
      </Box>
      
      <OCSFLogList />
    </Container>
  );
};

export default OCSFLogs;