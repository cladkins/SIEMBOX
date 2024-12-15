const config = {
  apiUrl: process.env.REACT_APP_API_URL || `http://${window.location.hostname}:8080`,
  detectionUrl: process.env.REACT_APP_DETECTION_URL || `http://${window.location.hostname}:8001`
};

export default config;