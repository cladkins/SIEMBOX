/**
 * RawLog Factory for Testing
 * Creates test raw log data using Fishery
 */

import { Factory } from 'fishery';
import { RawLog } from '../../../src/models/RawLog';

export const rawLogFactory = Factory.define<RawLog>(({ sequence }) => ({
  id: sequence,
  timestamp: new Date(),
  raw_message: `Test log message ${sequence}`,
  source_ip: '192.168.1.100',
  facility: 16, // Local use 0
  severity: 6, // Informational
  hostname: 'testserver',
  app_name: 'testapp',
  shipper_id: 'test1234',
  created_at: new Date(),
}));

export const nginxLogFactory = rawLogFactory.params({
  raw_message: '[13/Jan/2025:10:00:00 +0000] 192.168.1.50 - - GET /api/logs 200 1234',
  app_name: 'nginx',
  facility: 23, // Local use 7
  hostname: 'webserver',
});

export const sshLogFactory = rawLogFactory.params({
  raw_message: 'Failed password for invalid user admin from 192.168.1.50 port 22 ssh2',
  app_name: 'sshd',
  facility: 10, // Auth/security
  severity: 5, // Notice
  hostname: 'authserver',
});

export const systemLogFactory = rawLogFactory.params({
  raw_message: 'systemd[1]: Started session 123 for user admin',
  app_name: 'systemd',
  facility: 3, // System daemons
  severity: 6, // Informational
});

export const errorLogFactory = rawLogFactory.params({
  raw_message: 'ERROR: Database connection failed - connection timeout',
  severity: 3, // Error
});
