/**
 * Parser Factory for Testing
 * Creates test parser data using Fishery
 */

import { Factory } from 'fishery';
import { Parser } from '../../../src/models/Parser';

export const parserFactory = Factory.define<Parser>(({ sequence }) => ({
  id: sequence,
  name: `Parser ${sequence}`,
  description: `Test parser description ${sequence}`,
  enabled: true,
  priority: sequence * 10,
  parser_type: 'regex',
  pattern: '.*',
  field_mappings: {
    message: 'message',
    timestamp: 'timestamp',
  },
  test_samples: [
    { input: 'test log message', expected: { message: 'test log message' } },
  ],
  event_type: 'generic',
  created_at: new Date(),
  updated_at: new Date(),
}));

export const regexParserFactory = parserFactory.params({
  parser_type: 'regex',
  pattern: '^\\[(?<timestamp>[^\\]]+)\\] (?<level>\\w+): (?<message>.*)$',
  field_mappings: {
    timestamp: 'timestamp',
    level: 'level',
    message: 'message',
  },
});

export const grokParserFactory = parserFactory.params({
  parser_type: 'grok',
  pattern: '%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:message}',
});

export const jsonParserFactory = parserFactory.params({
  parser_type: 'json',
  pattern: '',
  field_mappings: {},
});

export const nginxParserFactory = parserFactory.params({
  name: 'NGINX Access Log',
  parser_type: 'regex',
  pattern: '^(?<remote_addr>[\\d.]+) - (?<remote_user>\\S+) \\[(?<time_local>[^\\]]+)\\] "(?<request>[^"]*)" (?<status>\\d+) (?<body_bytes_sent>\\d+)',
  field_mappings: {
    remote_addr: 'client_ip',
    remote_user: 'user',
    time_local: 'timestamp',
    request: 'http_request',
    status: 'http_status',
    body_bytes_sent: 'bytes_sent',
  },
  event_type: 'web_access',
});
