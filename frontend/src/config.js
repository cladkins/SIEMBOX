const getApiUrl = () => {
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Get the current hostname (either localhost or IP address)
  const hostname = window.location.hostname;
  return `http://${hostname}:8080`;
};

const config = {
  apiUrl: getApiUrl()
};

export default config;