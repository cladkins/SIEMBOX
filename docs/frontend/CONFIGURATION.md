# SIEM BOX - Frontend User Configuration Guide

This guide covers how to configure and customize the SIEM BOX frontend interface for end users, including deployment settings, theming, and basic customization options.

## Table of Contents

1. [Overview](#overview)
2. [Basic Configuration](#basic-configuration)
3. [Environment Settings](#environment-settings)
4. [Theming and Customization](#theming-and-customization)
5. [Performance Settings](#performance-settings)
6. [Security Configuration](#security-configuration)
7. [Troubleshooting](#troubleshooting)

## Overview

The SIEM BOX frontend provides a modern, responsive interface for security monitoring and log analysis. This guide focuses on configuration options available to end users and system administrators.

### Key Features
- **Modern Interface**: React-based web application with Material-UI components
- **Real-time Updates**: Live log streaming and alert notifications
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark/Light Themes**: Customizable appearance options
- **Multi-language Support**: Configurable language settings

## Basic Configuration

### Accessing the Interface

By default, the SIEM BOX frontend is available at:
- **URL**: http://localhost:3000
- **Username**: `admin`
- **Password**: `admin123`

⚠️ **Important**: Change the default credentials immediately in production environments.

### Default Settings

The frontend comes pre-configured with sensible defaults:
- **Theme**: Light mode (dark mode available)
- **Language**: English
- **Session Timeout**: 30 minutes
- **Auto-refresh**: Enabled for dashboards and logs

## Environment Settings

### Basic Environment Configuration

For most users, the default configuration works out of the box. However, you can customize certain settings by modifying environment variables.

#### Common Settings

| Setting | Default | Description |
|---------|---------|-------------|
| **Application Title** | `SIEM BOX` | Displayed in browser title and header |
| **Theme** | `light` | Default UI theme (light/dark) |
| **Language** | `en` | Default interface language |
| **Session Timeout** | `1800` | Session timeout in seconds (30 minutes) |

#### Production Environment

For production deployments, ensure these settings are configured:

```bash
# Application Settings
VITE_APP_TITLE=SIEM BOX
VITE_APP_ENVIRONMENT=production

# API Configuration (adjust to your setup)
VITE_API_BASE_URL=https://api.siembox.yourdomain.com
VITE_WS_BASE_URL=wss://api.siembox.yourdomain.com

# Security Settings
VITE_SESSION_TIMEOUT=1800
VITE_ENABLE_CSP=true

# Performance Settings
VITE_ENABLE_SERVICE_WORKER=true
```

## Theming and Customization

### Theme Selection

Users can switch between light and dark themes:

1. **Via User Interface**:
   - Click the theme toggle button in the top navigation
   - Changes are saved automatically to user preferences

2. **Default Theme Setting**:
   - Set `VITE_DEFAULT_THEME=dark` for dark mode by default
   - Set `VITE_DEFAULT_THEME=light` for light mode by default

### Color Customization

The interface uses a consistent color scheme for security events:

- **Low Severity**: Green (#4caf50)
- **Medium Severity**: Orange (#ff9800)
- **High Severity**: Red (#ff5722)
- **Critical Severity**: Dark Red (#f44336)

### Logo and Branding

To customize the application branding:

1. **Application Title**: Set `VITE_APP_TITLE` environment variable
2. **Custom Logo**: Replace `/public/favicon.svg` with your organization's logo
3. **Favicon**: Replace `/public/favicon.png` with your custom favicon

## Performance Settings

### Auto-refresh Configuration

The interface automatically refreshes data at regular intervals:

- **Dashboard**: Every 30 seconds
- **Logs Page**: Every 10 seconds (when viewing recent logs)
- **Alerts Page**: Every 15 seconds

### Browser Performance

For optimal performance:

- **Recommended Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Memory Usage**: Approximately 50-100MB for typical usage
- **Network**: Minimal bandwidth usage with efficient data loading

### Large Dataset Handling

When working with large log volumes:

- **Pagination**: Logs are automatically paginated (100 entries per page)
- **Filtering**: Use date ranges and filters to limit data loading
- **Search**: Indexed search provides fast results even with large datasets

## Security Configuration

### Session Management

- **Automatic Logout**: Sessions expire after 30 minutes of inactivity
- **Secure Cookies**: Authentication tokens are stored securely
- **HTTPS Enforcement**: Always use HTTPS in production environments

### Content Security Policy

The frontend implements security headers to protect against common attacks:

- **XSS Protection**: Prevents cross-site scripting attacks
- **Content Type Validation**: Ensures proper content type handling
- **Frame Protection**: Prevents clickjacking attacks

### Access Control

- **Role-based Access**: Different user roles have appropriate permissions
- **API Authentication**: All API calls require valid authentication tokens
- **Audit Logging**: User actions are logged for security monitoring

## Troubleshooting

### Common Issues

#### 1. Interface Won't Load
**Symptoms**: Blank page or loading errors
**Solutions**:
- Check that the backend service is running
- Verify the API URL configuration
- Clear browser cache and cookies
- Check browser console for error messages

#### 2. Login Problems
**Symptoms**: Cannot authenticate or frequent logouts
**Solutions**:
- Verify default credentials (admin/admin123)
- Check session timeout settings
- Ensure system time is synchronized
- Review backend authentication logs

#### 3. Data Not Loading
**Symptoms**: Empty dashboards or missing logs
**Solutions**:
- Verify log ingestion is working
- Check API connectivity
- Review date range filters
- Confirm user permissions

#### 4. Performance Issues
**Symptoms**: Slow loading or unresponsive interface
**Solutions**:
- Reduce date range for log queries
- Clear browser cache
- Check network connectivity
- Monitor system resource usage

### Browser Compatibility

#### Supported Browsers
- **Chrome**: Version 90 and later
- **Firefox**: Version 88 and later
- **Safari**: Version 14 and later
- **Edge**: Version 90 and later

#### Unsupported Browsers
- Internet Explorer (all versions)
- Chrome versions below 90
- Firefox versions below 88

### Getting Help

For additional support:

1. **Configuration Issues**: Review this guide and the [Docker Deployment Guide](../DOCKER_DEPLOYMENT.md)
2. **Technical Problems**: Check the [Troubleshooting Guide](../TROUBLESHOOTING.md)
3. **Advanced Configuration**: See the [Developer Documentation](../../project_docs/README.md)

### Log Collection for Support

If you need to report issues, collect these logs:

1. **Browser Console**: Press F12 and check the Console tab for errors
2. **Network Tab**: Monitor failed API requests in the Network tab
3. **Application Logs**: Check Docker container logs for the frontend service

```bash
# View frontend container logs
docker-compose logs frontend

# View all service logs
docker-compose logs
```

---

**Last Updated**: January 7, 2025  
**Documentation Version**: 2.0  
**Target Audience**: End Users, System Administrators

For advanced development and build configuration, see [Frontend Development Guide](../../project_docs/frontend/DEVELOPMENT.md).