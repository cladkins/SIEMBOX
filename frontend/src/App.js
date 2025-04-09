import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Navbar from './components/Navbar';
import Settings from './pages/Settings';
import Detections from './pages/Detections';
// Logs page removed in favor of OCSF Logs
import OCSFLogs from './pages/OCSFLogs';
import VpsAudit from './pages/VpsAudit';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    secondary: {
      main: '#f48fb1',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex' }}>
          <Navbar />
          <Box component="main" sx={{ flexGrow: 1, p: 3, mt: 8 }}>
            <Routes>
              <Route path="/" element={<Navigate to="/detections" replace />} />
              <Route path="/detections" element={<Detections />} />
              <Route path="/logs" element={<OCSFLogs />} />
              <Route path="/ocsf-logs" element={<OCSFLogs />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/vps-audit" element={<VpsAudit />} />
            </Routes>
          </Box>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;