/**
 * Nuclei Scanner Tests
 *
 * Unit tests for the Nuclei vulnerability scanner service.
 * Tests command argument building, result processing, and scan management.
 */

import { NucleiScanner, ScanOptions } from '../../../src/services/scanner/nucleiScanner';
import {
  NucleiResult,
  NucleiSeverity,
  ProcessedNucleiVulnerability,
} from '../../../src/types/nucleiTypes';

// Mock dependencies
jest.mock('../../../src/config/database', () => ({
  query: jest.fn(),
  connect: jest.fn(() => ({
    query: jest.fn(),
    release: jest.fn(),
  })),
}));

jest.mock('../../../src/services/audit/auditService', () => ({
  AuditService: {
    log: jest.fn(),
  },
}));

// Access private methods for testing
// We need to test buildNucleiArgs and processNucleiResult
// Since they're private, we'll test them via a testing helper

/**
 * Helper to access private static methods for testing
 */
function getPrivateMethod<T>(obj: any, method: string): T {
  return obj[method] as T;
}

describe('NucleiScanner', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('buildNucleiArgs', () => {
    // Get reference to private method
    const buildNucleiArgs = getPrivateMethod<(options: ScanOptions) => string[]>(
      NucleiScanner,
      'buildNucleiArgs'
    );

    it('should build basic args with target', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: {},
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-target');
      expect(args).toContain('http://example.com');
      expect(args).toContain('-jsonl');
      expect(args).toContain('-silent');
      expect(args).toContain('-update-templates');
    });

    it('should include all templates when all=true', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: { all: true },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-tags');
      expect(args).toContain('all');
    });

    it('should include specific templates', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: {
          templates: ['cves/2021/CVE-2021-44228.yaml', 'cves/2022/CVE-2022-1234.yaml'],
        },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-t');
      expect(args).toContain('cves/2021/CVE-2021-44228.yaml');
      expect(args).toContain('cves/2022/CVE-2022-1234.yaml');
    });

    it('should include tags filter', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: {
          tags: ['rce', 'sqli', 'xss'],
        },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-tags');
      expect(args).toContain('rce,sqli,xss');
    });

    it('should include CVE templates when cves=true', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: { cves: true },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-t');
      expect(args).toContain('cves/');
    });

    it('should include severity filter', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: {
          severities: ['critical', 'high'] as NucleiSeverity[],
        },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-severity');
      expect(args).toContain('critical,high');
    });

    it('should include exclusions', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: {
          cves: true,
          exclude: ['cves/2020/CVE-2020-5902.yaml'],
          excludeTags: ['dos', 'fuzz'],
        },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-exclude');
      expect(args).toContain('cves/2020/CVE-2020-5902.yaml');
      expect(args).toContain('-exclude-tags');
      expect(args).toContain('dos,fuzz');
    });

    it('should include rate limiting', () => {
      const options: ScanOptions = {
        target: 'http://example.com',
        templateSelection: { cves: true },
        userId: 1,
        rateLimit: 50,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-rate-limit');
      expect(args).toContain('50');
    });

    it('should handle IP address target', () => {
      const options: ScanOptions = {
        target: '192.168.1.100',
        templateSelection: { cves: true },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-target');
      expect(args).toContain('192.168.1.100');
    });

    it('should handle target with port', () => {
      const options: ScanOptions = {
        target: 'https://example.com:8443',
        templateSelection: { cves: true },
        userId: 1,
      };

      const args = buildNucleiArgs(options);

      expect(args).toContain('-target');
      expect(args).toContain('https://example.com:8443');
    });
  });

  describe('processNucleiResult', () => {
    // Get reference to private method
    const processNucleiResult = getPrivateMethod<
      (result: NucleiResult, target: string) => ProcessedNucleiVulnerability
    >(NucleiScanner, 'processNucleiResult');

    it('should process basic Nuclei result', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'CVE-2021-44228',
        info: {
          name: 'Log4j RCE (CVE-2021-44228)',
          severity: 'critical' as NucleiSeverity,
          'cve-id': 'CVE-2021-44228',
          'cvss-score': 10.0,
          description: 'Remote code execution vulnerability in Log4j',
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/api/vulnerable',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cveId).toBe('CVE-2021-44228');
      expect(processed.title).toBe('Log4j RCE (CVE-2021-44228)');
      expect(processed.severity).toBe('critical');
      expect(processed.cvssScore).toBe(10.0);
      expect(processed.target).toBe('http://example.com');
      expect(processed.matchedAt).toBe('http://example.com/api/vulnerable');
      expect(processed.templateId).toBe('CVE-2021-44228');
    });

    it('should extract CVE from template ID if not in info', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'CVE-2022-22963',
        info: {
          name: 'Spring Cloud RCE',
          severity: 'critical' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/functionRouter',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cveId).toBe('CVE-2022-22963');
    });

    it('should extract CVE from classification', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'spring-rce',
        info: {
          name: 'Spring RCE',
          severity: 'critical' as NucleiSeverity,
          classification: {
            'cve-id': ['CVE-2022-22963', 'CVE-2022-22965'],
            'cvss-score': 9.8,
            'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          },
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/vulnerable',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cveId).toBe('CVE-2022-22963');
      expect(processed.cvssScore).toBe(9.8);
      expect(processed.cvssVector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });

    it('should handle non-CVE vulnerabilities', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'nginx-version-detect',
        info: {
          name: 'Nginx Version Detection',
          severity: 'info' as NucleiSeverity,
          description: 'Detected Nginx version',
          tags: ['tech', 'nginx'],
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/',
        'extracted-results': ['nginx/1.18.0'],
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cveId).toBeUndefined();
      expect(processed.title).toBe('Nginx Version Detection');
      expect(processed.severity).toBe('info');
      expect(processed.evidence).toBe('nginx/1.18.0');
    });

    it('should handle references as array', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'CVE-2021-26855',
        info: {
          name: 'Exchange Server SSRF',
          severity: 'critical' as NucleiSeverity,
          reference: [
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-26855',
          ],
        },
        type: 'http',
        host: 'http://exchange.example.com',
        'matched-at': 'http://exchange.example.com/owa',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://exchange.example.com');

      expect(processed.references).toHaveLength(2);
      expect(processed.references).toContain(
        'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855'
      );
    });

    it('should handle references as string', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'CVE-2021-44228',
        info: {
          name: 'Log4Shell',
          severity: 'critical' as NucleiSeverity,
          reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/api',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.references).toHaveLength(1);
      expect(processed.references?.[0]).toBe('https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
    });

    it('should handle CWE ID as string', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'sqli-test',
        info: {
          name: 'SQL Injection',
          severity: 'high' as NucleiSeverity,
          'cwe-id': 'CWE-89',
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/search?q=test',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cweId).toBe('CWE-89');
    });

    it('should handle CWE ID as array', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'xss-test',
        info: {
          name: 'Cross-Site Scripting',
          severity: 'medium' as NucleiSeverity,
          'cwe-id': ['CWE-79', 'CWE-80'],
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/page?input=test',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.cweId).toBe('CWE-79');
    });

    it('should include remediation guidance', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'CVE-2021-44228',
        info: {
          name: 'Log4Shell',
          severity: 'critical' as NucleiSeverity,
          remediation: 'Upgrade Log4j to version 2.17.0 or later',
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/api',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.remediation).toBe('Upgrade Log4j to version 2.17.0 or later');
    });

    it('should use matcher-name as evidence fallback', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'nginx-version',
        info: {
          name: 'Nginx Version',
          severity: 'info' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/',
        'matcher-name': 'nginx-1.x',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.evidence).toBe('nginx-1.x');
    });

    it('should include raw result in processed output', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'test-template',
        info: {
          name: 'Test',
          severity: 'low' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/test',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.rawResult).toBe(nucleiResult);
    });
  });

  describe('Severity Levels', () => {
    const processNucleiResult = getPrivateMethod<
      (result: NucleiResult, target: string) => ProcessedNucleiVulnerability
    >(NucleiScanner, 'processNucleiResult');

    const severities: NucleiSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

    severities.forEach((severity) => {
      it(`should correctly process ${severity} severity`, () => {
        const nucleiResult: NucleiResult = {
          'template-id': `test-${severity}`,
          info: {
            name: `Test ${severity}`,
            severity,
          },
          type: 'http',
          host: 'http://example.com',
          'matched-at': 'http://example.com/test',
          timestamp: '2025-01-14T12:00:00Z',
        };

        const processed = processNucleiResult(nucleiResult, 'http://example.com');

        expect(processed.severity).toBe(severity);
      });
    });
  });

  describe('Edge Cases', () => {
    const processNucleiResult = getPrivateMethod<
      (result: NucleiResult, target: string) => ProcessedNucleiVulnerability
    >(NucleiScanner, 'processNucleiResult');

    it('should handle missing optional fields', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'minimal-template',
        info: {
          name: 'Minimal Test',
          severity: 'info' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/test',
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.title).toBe('Minimal Test');
      expect(processed.severity).toBe('info');
      expect(processed.cveId).toBeUndefined();
      expect(processed.cvssScore).toBeUndefined();
      expect(processed.cvssVector).toBeUndefined();
      expect(processed.cweId).toBeUndefined();
      expect(processed.description).toBeUndefined();
      expect(processed.remediation).toBeUndefined();
      expect(processed.references).toEqual([]);
    });

    it('should handle empty extracted-results', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'test-template',
        info: {
          name: 'Test',
          severity: 'info' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/test',
        'extracted-results': [],
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.evidence).toBe('');
    });

    it('should handle multiple extracted results', () => {
      const nucleiResult: NucleiResult = {
        'template-id': 'version-detect',
        info: {
          name: 'Version Detection',
          severity: 'info' as NucleiSeverity,
        },
        type: 'http',
        host: 'http://example.com',
        'matched-at': 'http://example.com/',
        'extracted-results': ['nginx/1.18.0', 'OpenSSL/1.1.1k', 'PHP/7.4.3'],
        timestamp: '2025-01-14T12:00:00Z',
      };

      const processed = processNucleiResult(nucleiResult, 'http://example.com');

      expect(processed.evidence).toBe('nginx/1.18.0, OpenSSL/1.1.1k, PHP/7.4.3');
    });
  });
});

describe('NucleiScanner Public Methods', () => {
  describe('getScanStatus', () => {
    const pool = require('../../../src/config/database');

    it('should return scan status from database', async () => {
      const mockScan = {
        id: 1,
        scan_type: 'vulnerability',
        target: 'http://example.com',
        status: 'completed',
        started_at: new Date(),
        completed_at: new Date(),
        vulnerabilities_found: 5,
      };

      pool.query.mockResolvedValueOnce({ rows: [mockScan] });

      const result = await NucleiScanner.getScanStatus(1);

      expect(result).toEqual(mockScan);
      expect(pool.query).toHaveBeenCalledWith(expect.any(String), [1]);
    });

    it('should return null for non-existent scan', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });

      const result = await NucleiScanner.getScanStatus(999);

      expect(result).toBeNull();
    });
  });

  describe('getRecentScans', () => {
    const pool = require('../../../src/config/database');

    it('should return recent scans with default limit', async () => {
      const mockScans = [
        { id: 1, target: 'http://example1.com', status: 'completed' },
        { id: 2, target: 'http://example2.com', status: 'running' },
      ];

      pool.query.mockResolvedValueOnce({ rows: mockScans });

      const result = await NucleiScanner.getRecentScans();

      expect(result).toEqual(mockScans);
      expect(pool.query).toHaveBeenCalledWith(expect.any(String), [20]);
    });

    it('should return recent scans with custom limit', async () => {
      const mockScans = [{ id: 1, target: 'http://example.com', status: 'completed' }];

      pool.query.mockResolvedValueOnce({ rows: mockScans });

      const result = await NucleiScanner.getRecentScans(10);

      expect(result).toEqual(mockScans);
      expect(pool.query).toHaveBeenCalledWith(expect.any(String), [10]);
    });
  });

  describe('cancelScan', () => {
    it('should return false for non-active scan', async () => {
      const result = await NucleiScanner.cancelScan(999);

      expect(result).toBe(false);
    });
  });
});
