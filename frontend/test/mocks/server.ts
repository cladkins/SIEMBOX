/**
 * Mock Service Worker Server Setup
 * Configures MSW for Node.js test environment
 */

import { setupServer } from 'msw/node';
import { handlers } from './handlers';

// Setup MSW server with default handlers
export const server = setupServer(...handlers);
