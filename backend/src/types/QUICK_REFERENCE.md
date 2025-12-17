# Asset Discovery Types - Quick Reference

Quick reference for common type operations. For full documentation, see [README.md](./README.md).

## Quick Imports

```typescript
// Everything you need
import {
  // Asset types
  Asset, AssetType, AssetCriticality, AssetStatus, CreateAssetInput,
  // Scan types
  VulnerabilityScan, ScanType, ScanStatus, CreateScanInput,
  // API types
  ApiResponse, successResponse, errorResponse, paginatedResponse,
  // NMAP types
  NmapScanResult, NmapHost, NmapScanConfig,
  // Type guards
  isValidIPAddress, isAssetType, assertValid
} from '../types';
```

## Common Patterns

### Creating an Asset

```typescript
import { CreateAssetInput, AssetType, AssetCriticality, AssetStatus, DiscoveryMethod } from '../types';

const input: CreateAssetInput = {
  ip_address: '192.168.1.100',
  hostname: 'webserver01',
  asset_type: AssetType.SERVER,
  criticality: AssetCriticality.HIGH,
  status: AssetStatus.ACTIVE,
  discovery_method: DiscoveryMethod.NMAP,
  last_seen: new Date()
};
```

### Updating an Asset

```typescript
import { UpdateAssetInput, AssetStatus } from '../types';

const update: UpdateAssetInput = {
  status: AssetStatus.OFFLINE,
  last_seen: new Date()
};
```

### Creating a Scan

```typescript
import { CreateScanInput, ScanType, NmapScanMode } from '../types';

const scanInput: CreateScanInput = {
  scan_type: ScanType.ASSET_DISCOVERY,
  target: '192.168.1.0/24',
  initiated_by: userId,
  scan_options: {
    scan_mode: NmapScanMode.SERVICE,
    timing: 'T4',
    ports: '1-1000'
  }
};
```

### API Success Response

```typescript
import { successResponse, Asset } from '../types';

const response = successResponse<Asset>(asset, 'Asset created successfully');
// Returns: { success: true, data: asset, message: '...', timestamp: '...' }
```

### API Error Response

```typescript
import { errorResponse, ApiErrorCode } from '../types';

const response = errorResponse('Asset not found', ApiErrorCode.NOT_FOUND);
// Returns: { success: false, error: '...', timestamp: '...' }
```

### Paginated Response

```typescript
import { paginatedResponse, Asset } from '../types';

const response = paginatedResponse<Asset>(assets, totalCount, limit, offset);
// Returns: { success: true, data: { items, total, limit, offset, hasMore, page, totalPages }, timestamp }
```

### Validating Input

```typescript
import { isValidIPAddress, isAssetType, AssetType } from '../utils/typeGuards';

if (!isValidIPAddress(ip)) {
  throw new Error('Invalid IP address');
}

if (!isAssetType(type)) {
  throw new Error('Invalid asset type');
}
```

### Asserting Validity (throws on failure)

```typescript
import { assertValid, isValidIPAddress, ValidationError } from '../utils/typeGuards';

try {
  assertValid(ip, isValidIPAddress, 'Invalid IP address', 'ip_address');
} catch (error) {
  if (error instanceof ValidationError) {
    console.error(`Field ${error.field}: ${error.message}`);
  }
}
```

### Filtering Assets

```typescript
import { AssetFilters, AssetStatus, AssetCriticality } from '../types';

const filters: AssetFilters = {
  status: AssetStatus.ACTIVE,
  criticality: AssetCriticality.HIGH,
  search: '192.168',
  limit: 50,
  offset: 0,
  sort_by: 'criticality',
  sort_order: 'desc'
};
```

### Filtering Scans

```typescript
import { ScanFilters, ScanStatus } from '../types';

const filters: ScanFilters = {
  status: ScanStatus.COMPLETED,
  date_from: new Date('2025-01-01'),
  date_to: new Date(),
  limit: 20,
  offset: 0
};
```

## Enum Values

### AssetType
`SERVER`, `WORKSTATION`, `NETWORK`, `IOT`, `MOBILE`, `UNKNOWN`

### AssetCriticality
`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### AssetStatus
`ACTIVE`, `INACTIVE`, `OFFLINE`

### DiscoveryMethod
`NMAP`, `LOG_CORRELATION`, `MANUAL`

### ScanType
`ASSET_DISCOVERY`, `VULNERABILITY`, `PORT_SCAN`, `SERVICE_DETECTION`, `OS_DETECTION`

### ScanStatus
`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `TIMEOUT`

### NmapScanMode
`PING`, `PORT`, `SERVICE`, `OS`, `AGGRESSIVE`, `QUICK`

### NmapTiming
`'T0'`, `'T1'`, `'T2'`, `'T3'`, `'T4'`, `'T5'`

## Common Validators

```typescript
// IP addresses
isValidIPv4Address('192.168.1.1')      // true
isValidIPv6Address('::1')              // true
isValidIPAddress('192.168.1.1')        // true (IPv4 or IPv6)
isValidCIDR('192.168.1.0/24')          // true
isValidMACAddress('00:11:22:33:44:55') // true

// Ports
isValidPort(80)                        // true
isValidPort(70000)                     // false
isValidPortRange('80,443,8080-8090')   // true

// Targets
isValidHostname('example.com')         // true
isValidScanTarget('192.168.1.1')       // true
isValidScanTargets('192.168.1.1, 192.168.1.0/24') // true

// Enums
isAssetType(AssetType.SERVER)          // true
isAssetType('invalid')                 // false
isScanStatus(ScanStatus.COMPLETED)     // true

// Generic
isNotNull(value)                       // type guard for non-null
isNonEmptyString(value, 3)             // min length 3
isPositiveInteger(42)                  // true
isArrayOf(arr, isValidIPAddress)       // validate array elements
```

## Type Guards in Practice

### Route Handler Example

```typescript
import { Request, Response } from 'express';
import {
  CreateAssetInput,
  successResponse,
  errorResponse,
  ApiErrorCode,
  isValidIPAddress,
  isAssetType,
  ValidationError
} from '../types';

async function createAsset(req: Request, res: Response) {
  try {
    const input = req.body as CreateAssetInput;

    // Validate
    if (!isValidIPAddress(input.ip_address)) {
      return res.status(400).json(
        errorResponse('Invalid IP address', ApiErrorCode.VALIDATION_ERROR)
      );
    }

    if (!isAssetType(input.asset_type)) {
      return res.status(400).json(
        errorResponse('Invalid asset type', ApiErrorCode.VALIDATION_ERROR)
      );
    }

    // Create asset
    const asset = await AssetModel.create(input);

    // Return success
    return res.status(201).json(
      successResponse(asset, 'Asset created successfully')
    );

  } catch (error) {
    if (error instanceof ValidationError) {
      return res.status(400).json(
        errorResponse(error.message, ApiErrorCode.VALIDATION_ERROR)
      );
    }

    return res.status(500).json(
      errorResponse('Internal server error', ApiErrorCode.INTERNAL_ERROR)
    );
  }
}
```

### Database Model Example

```typescript
import { query } from '../config/database';
import { Asset, CreateAssetInput, AssetFilters } from '../types';

export class AssetModel {
  static async create(input: CreateAssetInput): Promise<Asset> {
    const result = await query(
      `INSERT INTO assets (ip_address, hostname, asset_type, criticality, status, discovery_method, last_seen)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        input.ip_address,
        input.hostname,
        input.asset_type,
        input.criticality,
        input.status,
        input.discovery_method,
        input.last_seen
      ]
    );
    return result.rows[0] as Asset;
  }

  static async findAll(filters: AssetFilters): Promise<Asset[]> {
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIndex = 1;

    if (filters.status) {
      conditions.push(`status = $${paramIndex++}`);
      params.push(filters.status);
    }

    if (filters.search) {
      conditions.push(`(ip_address LIKE $${paramIndex} OR hostname LIKE $${paramIndex})`);
      params.push(`%${filters.search}%`);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const orderBy = filters.sort_by || 'created_at';
    const order = filters.sort_order || 'desc';

    const result = await query(
      `SELECT * FROM assets ${whereClause}
       ORDER BY ${orderBy} ${order}
       LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      [...params, filters.limit || 50, filters.offset || 0]
    );

    return result.rows as Asset[];
  }
}
```

### Scanner Implementation Example

```typescript
import { Scanner, ScanResult, ScanType, NmapScanConfig, NmapScanResult } from '../types';

export class NmapScanner implements Scanner<NmapScanConfig, NmapScanResult> {
  getScannerName(): string {
    return 'nmap';
  }

  getSupportedScanTypes(): ScanType[] {
    return [
      ScanType.ASSET_DISCOVERY,
      ScanType.PORT_SCAN,
      ScanType.SERVICE_DETECTION,
      ScanType.OS_DETECTION
    ];
  }

  async scan(config: NmapScanConfig): Promise<ScanResult<NmapScanResult>> {
    try {
      // Execute NMAP scan
      const result = await this.executeNmap(config);

      return {
        success: true,
        data: result,
        metadata: {
          started_at: new Date(),
          command: this.buildCommand(config)
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  validateConfig(config: NmapScanConfig): boolean {
    return config.targets.length > 0 && config.flags.length > 0;
  }

  async isAvailable(): Promise<boolean> {
    // Check if NMAP is installed
    return true;
  }

  async getVersion(): Promise<string> {
    return '7.94';
  }

  private buildCommand(config: NmapScanConfig): string {
    return `nmap ${config.flags} ${config.targets.join(' ')}`;
  }

  private async executeNmap(config: NmapScanConfig): Promise<NmapScanResult> {
    // Implementation here
    throw new Error('Not implemented');
  }
}
```

## Common Mistakes to Avoid

1. **Don't use string literals for enums**
   ```typescript
   // Bad
   asset.asset_type = 'server';

   // Good
   asset.asset_type = AssetType.SERVER;
   ```

2. **Don't skip validation**
   ```typescript
   // Bad
   const asset = await AssetModel.create(req.body);

   // Good
   if (!isValidIPAddress(input.ip_address)) {
     throw new ValidationError('Invalid IP address');
   }
   const asset = await AssetModel.create(input);
   ```

3. **Don't forget to handle null**
   ```typescript
   // Bad
   console.log(asset.hostname.toUpperCase());

   // Good
   console.log(asset.hostname?.toUpperCase() ?? 'N/A');
   ```

4. **Use the correct input types**
   ```typescript
   // Bad - includes auto-generated fields
   function create(asset: Asset) { }

   // Good - omits auto-generated fields
   function create(input: CreateAssetInput) { }
   ```

5. **Always wrap API responses**
   ```typescript
   // Bad
   return res.json(assets);

   // Good
   return res.json(successResponse(assets));
   ```

## Need More Help?

- Full documentation: [README.md](./README.md)
- Type guard reference: [README.md#type-guard-reference](./README.md#type-guard-reference)
- Complete examples: [README.md#usage-examples](./README.md#usage-examples)
