# Asset Discovery Type Definitions

Comprehensive TypeScript type definitions for the SIEMBox Asset Discovery system. These types provide compile-time safety, IDE autocomplete, and prevent runtime errors.

## Overview

This directory contains type-safe definitions for:

- **Assets**: Discovered network devices and their metadata
- **Scans**: NMAP and vulnerability scan operations
- **Services**: Network services running on assets
- **Vulnerabilities**: Security issues found on assets
- **API Responses**: Consistent API response envelopes
- **Scanner Interface**: Extensible scanner architecture

## File Structure

```
/types
├── index.ts              # Central export point for all types
├── apiTypes.ts           # API response envelopes and helpers
├── nmapTypes.ts          # NMAP-specific types
├── serviceTypes.ts       # Generic scanner interfaces
└── README.md             # This file

/models
├── Asset.ts              # Asset and service type definitions
└── Scan.ts               # Scan and credential type definitions

/utils
└── typeGuards.ts         # Runtime type validation functions
```

## Usage Examples

### Importing Types

```typescript
// Import from central index (recommended)
import { Asset, AssetType, CreateAssetInput } from '../types';

// Or import from specific files
import { Asset } from '../models/Asset';
import { NmapScanResult } from '../types/nmapTypes';
```

### Creating Type-Safe Assets

```typescript
import { CreateAssetInput, AssetType, AssetCriticality, AssetStatus, DiscoveryMethod } from '../types';

const newAsset: CreateAssetInput = {
  ip_address: '192.168.1.100',
  hostname: 'webserver01',
  asset_type: AssetType.SERVER,
  criticality: AssetCriticality.HIGH,
  status: AssetStatus.ACTIVE,
  discovery_method: DiscoveryMethod.NMAP,
  last_seen: new Date(),
  metadata: {
    nmap_scan_id: 123,
    environment: 'production',
    owner: 'IT Operations'
  }
};
```

### Type-Safe API Responses

```typescript
import { successResponse, paginatedResponse, ApiResponse, PaginatedResponse } from '../types';

// Simple success response
const response: ApiResponse<Asset> = successResponse(asset, 'Asset created successfully');

// Paginated response
const paginatedAssets: ApiResponse<PaginatedResponse<Asset>> = paginatedResponse(
  assets,
  totalCount,
  limit,
  offset
);
```

### Runtime Validation with Type Guards

```typescript
import { isValidIPAddress, isAssetType, assertValid, ValidationError } from '../utils/typeGuards';

// Validate IP address
if (!isValidIPAddress(ip)) {
  throw new Error('Invalid IP address');
}

// Validate enum value
if (!isAssetType(type)) {
  throw new Error('Invalid asset type');
}

// Assert with automatic error throwing
try {
  assertValid(ip, isValidIPAddress, 'Invalid IP address', 'ip_address');
} catch (error) {
  if (error instanceof ValidationError) {
    console.error(`Validation failed for ${error.field}: ${error.message}`);
  }
}
```

### Implementing a Scanner

```typescript
import { Scanner, ScanResult, ScanType, DiscoveredAsset } from '../types';
import { NmapScanConfig, NmapScanResult } from '../types/nmapTypes';

class NmapScanner implements Scanner<NmapScanConfig, NmapScanResult> {
  getScannerName(): string {
    return 'nmap';
  }

  getSupportedScanTypes(): ScanType[] {
    return [ScanType.ASSET_DISCOVERY, ScanType.PORT_SCAN, ScanType.SERVICE_DETECTION];
  }

  async scan(config: NmapScanConfig): Promise<ScanResult<NmapScanResult>> {
    // Implementation here
  }

  validateConfig(config: NmapScanConfig): boolean {
    return config.targets.length > 0 && config.flags.length > 0;
  }

  async isAvailable(): Promise<boolean> {
    // Check if NMAP is installed
  }

  async getVersion(): Promise<string> {
    // Get NMAP version
  }
}
```

### Filtering and Querying Assets

```typescript
import { AssetFilters, AssetStatus, AssetCriticality } from '../types';

const filters: AssetFilters = {
  status: AssetStatus.ACTIVE,
  criticality: AssetCriticality.HIGH,
  search: '192.168.1',
  tags: ['production', 'web'],
  limit: 50,
  offset: 0,
  sort_by: 'criticality',
  sort_order: 'desc'
};

const assets = await assetService.getAssets(filters);
```

## Key Design Principles

### 1. Strict Type Safety

All types use strict TypeScript settings:

- Enums instead of string literals for finite sets
- Explicit `null` types (e.g., `string | null`)
- No `any` types
- Required vs optional fields clearly defined

### 2. Database Alignment

Types match the database schema exactly:

- `id`, `created_at`, `updated_at` are always `number` and `Date`
- Nullable database columns use `| null` union types
- JSONB columns use structured interfaces with `[key: string]: unknown` for flexibility

### 3. Input/Output Types

Separate types for different operations:

- **Create**: Omits auto-generated fields (`id`, `created_at`, etc.)
- **Update**: All fields optional except `id`
- **With Relations**: Extended interfaces for joined data

### 4. API Consistency

All API responses use the `ApiResponse<T>` envelope:

```typescript
{
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp?: string;
}
```

### 5. Extensibility

Generic interfaces support future scanners:

- `Scanner<TConfig, TResult>` - Abstract scanner interface
- `EventEmittingScanner` - Real-time scan updates
- `ScanResultProcessor` - Pluggable result handling

## Enum Reference

### AssetType

```typescript
enum AssetType {
  SERVER = 'server',
  WORKSTATION = 'workstation',
  NETWORK = 'network',
  IOT = 'iot',
  MOBILE = 'mobile',
  UNKNOWN = 'unknown'
}
```

### AssetCriticality

```typescript
enum AssetCriticality {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}
```

### AssetStatus

```typescript
enum AssetStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  OFFLINE = 'offline'
}
```

### DiscoveryMethod

```typescript
enum DiscoveryMethod {
  NMAP = 'nmap',
  LOG_CORRELATION = 'log_correlation',
  MANUAL = 'manual'
}
```

### ScanType

```typescript
enum ScanType {
  ASSET_DISCOVERY = 'asset_discovery',
  VULNERABILITY = 'vulnerability',
  PORT_SCAN = 'port_scan',
  SERVICE_DETECTION = 'service_detection',
  OS_DETECTION = 'os_detection'
}
```

### ScanStatus

```typescript
enum ScanStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  TIMEOUT = 'timeout'
}
```

### NmapScanMode

```typescript
enum NmapScanMode {
  PING = 'ping',           // -sn
  PORT = 'port',           // -sS, -sT
  SERVICE = 'service',     // -sV
  OS = 'os',               // -O
  AGGRESSIVE = 'aggressive', // -A
  QUICK = 'quick'          // -F
}
```

## Type Guard Reference

### IP Address Validation

```typescript
isValidIPv4Address(ip: string): boolean
isValidIPv6Address(ip: string): boolean
isValidIPAddress(ip: string): boolean
isValidCIDR(cidr: string): boolean
isValidMACAddress(mac: string): boolean
```

### Port Validation

```typescript
isValidPort(port: number): boolean
isValidPortRange(portRange: string): boolean
```

### Target Validation

```typescript
isValidHostname(hostname: string): boolean
isValidScanTarget(target: string): boolean
isValidScanTargets(targets: string): boolean
```

### Enum Validation

```typescript
isAssetType(value: unknown): value is AssetType
isAssetCriticality(value: unknown): value is AssetCriticality
isAssetStatus(value: unknown): value is AssetStatus
isDiscoveryMethod(value: unknown): value is DiscoveryMethod
isScanType(value: unknown): value is ScanType
isScanStatus(value: unknown): value is ScanStatus
```

### Generic Validators

```typescript
isNotNull<T>(value: T | null | undefined): value is T
isNonEmptyString(value: unknown, minLength?: number): value is string
isPositiveInteger(value: unknown): value is number
isNonNegativeInteger(value: unknown): value is number
isArrayOf<T>(value: unknown, guard: (item: unknown) => item is T): value is T[]
isValidDate(value: unknown): value is Date
```

## Integration with Database

### Asset Model Example

```typescript
import { query } from '../config/database';
import { Asset, CreateAssetInput, AssetFilters } from '../types';

export class AssetModel {
  static async create(input: CreateAssetInput): Promise<Asset> {
    const result = await query(
      `INSERT INTO assets (ip_address, hostname, asset_type, criticality, status, discovery_method, last_seen)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [input.ip_address, input.hostname, input.asset_type, input.criticality, input.status, input.discovery_method, input.last_seen]
    );
    return result.rows[0] as Asset;
  }

  static async findById(id: number): Promise<Asset | null> {
    const result = await query('SELECT * FROM assets WHERE id = $1', [id]);
    return result.rows[0] as Asset || null;
  }

  static async findAll(filters: AssetFilters): Promise<Asset[]> {
    // Build dynamic query with filters
    // Return type-safe results
  }
}
```

## Testing with Types

```typescript
import { describe, it, expect } from 'vitest';
import { isValidIPAddress, isAssetType, AssetType } from '../types';

describe('Type Guards', () => {
  it('should validate IPv4 addresses', () => {
    expect(isValidIPAddress('192.168.1.1')).toBe(true);
    expect(isValidIPAddress('256.1.1.1')).toBe(false);
  });

  it('should validate asset types', () => {
    expect(isAssetType('server')).toBe(true);
    expect(isAssetType('invalid')).toBe(false);
    expect(isAssetType(AssetType.SERVER)).toBe(true);
  });
});
```

## Best Practices

1. **Always use enums for finite value sets**
   - Prevents typos and enables autocomplete
   - Example: `AssetType.SERVER` instead of `'server'`

2. **Use type guards for user input validation**
   - Never trust incoming data
   - Validate before database operations

3. **Leverage TypeScript utility types**
   - `Omit<T, K>` for excluding fields
   - `Partial<T>` for optional updates
   - `Pick<T, K>` for selecting specific fields

4. **Document complex types with JSDoc**
   - Improves IDE tooltips
   - Explains business logic

5. **Use strict null checks**
   - Always handle `null` and `undefined` explicitly
   - Use `| null` for nullable fields

6. **Create separate input/output types**
   - Database results vs API responses may differ
   - Clear separation of concerns

7. **Use generic types for reusability**
   - `Scanner<TConfig, TResult>` works for any scanner
   - `ApiResponse<T>` wraps any data type

## Migration Notes

When adding new fields to existing types:

1. Update the interface in `models/Asset.ts` or `models/Scan.ts`
2. Update database migration in `backend/migrations/001_initial_schema.sql`
3. Update any affected API endpoints
4. Update type guards if validation is needed
5. Update tests to cover new fields

## Future Extensions

The type system is designed to support:

- **New Scanner Types**: Nuclei, OpenVAS, custom scanners
- **New Asset Types**: Cloud resources, containers, serverless functions
- **Custom Metadata**: Extensible JSONB fields with type safety
- **Compliance Frameworks**: NIST, CIS, ISO 27001 mappings
- **Integration Hooks**: SOAR, ticketing systems, notification channels

## Questions?

For questions about these types or suggestions for improvements, contact the backend-architect or open a discussion in the project repository.
