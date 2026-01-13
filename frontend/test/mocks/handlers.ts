/**
 * Mock Service Worker (MSW) Handlers
 * Defines mock API responses for testing
 */

import { http, HttpResponse } from 'msw';

const API_BASE = '/api';

export const handlers = [
  // Authentication endpoints
  http.post(`${API_BASE}/auth/login`, async ({ request }) => {
    const body = await request.json() as { username: string; password: string };

    if (body.username === 'admin' && body.password === 'changeme') {
      return HttpResponse.json({
        token: 'mock-jwt-token-12345',
        user: {
          id: 1,
          username: 'admin',
          email: 'admin@siembox.local',
          role: 'Admin',
        },
      });
    }

    return HttpResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  }),

  http.post(`${API_BASE}/auth/logout`, () => {
    return HttpResponse.json({ message: 'Logged out successfully' });
  }),

  http.get(`${API_BASE}/auth/me`, ({ request }) => {
    const authHeader = request.headers.get('Authorization');

    if (authHeader && authHeader.startsWith('Bearer ')) {
      return HttpResponse.json({
        id: 1,
        username: 'admin',
        email: 'admin@siembox.local',
        role: 'Admin',
      });
    }

    return HttpResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }),

  // Logs endpoints
  http.get(`${API_BASE}/logs`, ({ request }) => {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '20');

    return HttpResponse.json({
      logs: [
        {
          id: 1,
          raw_message: 'Test log message 1',
          parsed_data: { level: 'info', message: 'Test log 1' },
          timestamp: '2025-01-13T10:00:00Z',
          source_ip: '192.168.1.100',
          hostname: 'webserver',
          app_name: 'nginx',
        },
        {
          id: 2,
          raw_message: 'Test log message 2',
          parsed_data: { level: 'error', message: 'Test log 2' },
          timestamp: '2025-01-13T10:01:00Z',
          source_ip: '192.168.1.101',
          hostname: 'appserver',
          app_name: 'app',
        },
      ],
      total: 100,
      page,
      limit,
      totalPages: Math.ceil(100 / limit),
    });
  }),

  // Alerts endpoints
  http.get(`${API_BASE}/alerts`, ({ request }) => {
    const url = new URL(request.url);
    const severity = url.searchParams.get('severity');

    return HttpResponse.json({
      alerts: [
        {
          id: 1,
          rule_name: 'Failed Login Attempts',
          severity: 'high',
          message: 'Multiple failed login attempts detected',
          count: 5,
          acknowledged: false,
          created_at: '2025-01-13T10:00:00Z',
        },
        {
          id: 2,
          rule_name: 'Unusual Traffic Pattern',
          severity: 'medium',
          message: 'Unusual traffic detected from IP',
          count: 1,
          acknowledged: true,
          created_at: '2025-01-13T09:30:00Z',
        },
      ],
      total: 2,
    });
  }),

  http.post(`${API_BASE}/alerts/:id/acknowledge`, ({ params }) => {
    return HttpResponse.json({
      id: parseInt(params.id as string),
      acknowledged: true,
      acknowledged_at: new Date().toISOString(),
    });
  }),

  // Parsers endpoints
  http.get(`${API_BASE}/parsers`, () => {
    return HttpResponse.json({
      parsers: [
        {
          id: 1,
          name: 'NGINX Access',
          type: 'regex',
          pattern: '.*',
          enabled: true,
          priority: 10,
        },
        {
          id: 2,
          name: 'JSON Parser',
          type: 'json',
          pattern: null,
          enabled: true,
          priority: 20,
        },
      ],
      total: 2,
    });
  }),

  http.post(`${API_BASE}/parsers`, async ({ request }) => {
    const body = await request.json() as any;

    return HttpResponse.json(
      {
        id: 3,
        ...body,
        created_at: new Date().toISOString(),
      },
      { status: 201 }
    );
  }),

  // Rules endpoints
  http.get(`${API_BASE}/rules`, () => {
    return HttpResponse.json({
      rules: [
        {
          id: 1,
          name: 'Failed SSH Login',
          enabled: true,
          severity: 'high',
          conditions: { field: 'message', operator: 'contains', value: 'Failed password' },
          threshold: 5,
          time_window: 300,
        },
      ],
      total: 1,
    });
  }),

  // Dashboard/stats endpoints
  http.get(`${API_BASE}/stats/summary`, () => {
    return HttpResponse.json({
      totalLogs: 15234,
      activeAlerts: 8,
      parsersEnabled: 15,
      rulesEnabled: 42,
    });
  }),
];
