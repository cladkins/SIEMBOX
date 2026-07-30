/**
 * HTTP log-push authentication for log shippers.
 *
 * A shipper's HTTP push key is separate from its syslog api_key (see
 * 029_shipper_http_push.sql). Presented as `Authorization: Bearer <key>` +
 * `X-Shipper-ID: <log_shippers.id>`. We look the shipper up by id, sha256 the
 * presented key, and constant-time compare against the stored hash. Modeled
 * directly on edrAgentAuth.ts.
 */
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { ApiError } from './errorHandler';
import { LogShipper, LogShipperModel } from '../models/LogShipper';
import { sha256hex } from '../models/EdrAgent';

declare global {
  namespace Express {
    interface Request {
      pushShipper?: LogShipper;
    }
  }
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    return false;
  }
}

export const authenticateShipperPush = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const shipperIdHeader = (req.header('X-Shipper-ID') || '').trim();
    const authHeader = req.header('authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const shipperId = parseInt(shipperIdHeader, 10);

    if (!shipperIdHeader || !token || !Number.isInteger(shipperId)) {
      throw new ApiError(401, 'Shipper authentication required (X-Shipper-ID + Bearer key)');
    }

    const shipper = await LogShipperModel.findById(shipperId);
    // Always hash the presented token so a missing shipper, a shipper with no
    // push key provisioned, and a wrong key all cost the same time and return
    // the same error (don't leak which shipper ids exist or have push enabled).
    const presented = sha256hex(token);
    if (!shipper || !shipper.http_push_key_hash || !timingSafeEqualHex(presented, shipper.http_push_key_hash)) {
      throw new ApiError(401, 'Invalid shipper credentials');
    }

    req.pushShipper = shipper;
    next();
  } catch (error) {
    next(error);
  }
};
