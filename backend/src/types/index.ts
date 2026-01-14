/**
 * Type Definitions Index
 *
 * Central export point for all type definitions.
 * Enables clean imports: import { Asset, AssetType } from '../types'
 */

// Asset types
export {
  // Enums
  AssetType,
  AssetCriticality,
  AssetStatus,
  DiscoveryMethod,
  ServiceProtocol,
  ServiceState,
  // Interfaces
  Asset,
  AssetMetadata,
  CreateAssetInput,
  UpdateAssetInput,
  AssetService,
  CreateServiceInput,
  AssetWithServices,
  AssetWithVulnerabilities,
  AssetWithRelations,
  AssetVulnerability,
  AssetFilters,
  PaginatedAssets,
  AssetStatistics
} from '../models/Asset';

// Scan types
export {
  // Enums
  ScanType,
  ScanStatus,
  NmapScanMode,
  // Types
  NmapTiming,
  // Interfaces
  ScanOptions,
  ScanResultsSummary,
  VulnerabilityScan,
  CreateScanInput,
  UpdateScanInput,
  ScanWithUser,
  ScanWithResults,
  ScanFilters,
  PaginatedScans,
  ScanStatistics,
  ScanCredential,
  CreateCredentialInput
} from '../models/Scan';

// NMAP types
export {
  // Types
  NmapHostStatus,
  NmapPortState,
  // Interfaces
  NmapService,
  NmapPort,
  NmapOSMatch,
  NmapOSClass,
  NmapOS,
  NmapHost,
  NmapScanStats,
  NmapScanResult,
  NmapScanConfig,
  ScanResult,
  NmapOutputLine,
  NmapScanProgress,
  // Enums
  NmapErrorCode,
  // Classes
  NmapError
} from './nmapTypes';

// API types
export {
  // Interfaces
  ApiResponse,
  PaginatedResponse,
  ErrorResponse,
  ValidationError,
  ValidationErrorResponse,
  // Asset API responses
  GetAssetsResponse,
  GetAssetResponse,
  GetAssetDetailResponse,
  CreateAssetResponse,
  UpdateAssetResponse,
  DeleteAssetResponse,
  GetAssetStatisticsResponse,
  // Scan API responses
  TriggerScanResponse,
  GetScanResponse,
  GetScanDetailResponse,
  GetScansResponse,
  CancelScanResponse,
  GetScanStatisticsResponse,
  // Service API responses
  GetServicesResponse,
  // Generic CRUD responses
  ListResponse,
  GetResponse,
  CreateResponse,
  UpdateResponse,
  DeleteResponse,
  // Utility types
  ResponseData,
  PaginatedItems,
  // Enums
  ApiErrorCode,
  // Helper functions
  successResponse,
  errorResponse,
  paginatedResponse
} from './apiTypes';

// Service types
export {
  // Interfaces
  Scanner,
  ScannerRegistry,
  ScannerMetadata,
  ScannerFactory,
  ScanEvent,
  ScanEventListener,
  EventEmittingScanner,
  ConfigValidator,
  ValidationResult,
  ResultParser,
  DiscoveredAsset,
  DiscoveredService,
  DiscoveredVulnerability,
  ScanResultProcessor,
  ScannerHealthCheck,
  ScannerManager,
  // Enums
  ScanEventType
} from './serviceTypes';
