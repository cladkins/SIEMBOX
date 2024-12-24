const config = {
  apiUrl: process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8080`,
  detectionUrl: process.env.REACT_APP_DETECTION_URL || `http://${window.location.hostname}:8001`,
  ipLookupUrl: process.env.REACT_APP_IPLOOKUP_URL || `http://${window.location.hostname}:8002`,
  vpsAuditUrl: process.env.REACT_APP_VPS_AUDIT_URL || `http://${window.location.hostname}:8004`
};

export default config;