/**
 * EDR agent authentication.
 *
 * Every agent endpoint except enrollment requires the per-agent API key issued
 * at enroll time, presented as `Authorization: Bearer <key>` + `X-Agent-ID: <id>`.
 * We look the agent up by id, sha256 the presented key, and constant-time compare
 * against the stored hash. The plaintext key is never stored server-side.
 */
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { ApiError } from './errorHandler';
import { EdrAgent, EdrAgentModel, sha256hex } from '../models/EdrAgent';

declare global {
  namespace Express {
    interface Request {
      edrAgent?: EdrAgent;
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

export const authenticateAgent = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const agentId = (req.header('X-Agent-ID') || '').trim();
    const authHeader = req.header('authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!agentId || !token) {
      throw new ApiError(401, 'Agent authentication required (X-Agent-ID + Bearer key)');
    }

    const agent = await EdrAgentModel.findById(agentId);
    // Always hash the presented token so a missing agent and a wrong key cost the
    // same time (don't leak which agent ids exist).
    const presented = sha256hex(token);
    if (!agent || !timingSafeEqualHex(presented, agent.api_key_hash)) {
      throw new ApiError(401, 'Invalid agent credentials');
    }

    req.edrAgent = agent;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * For routes with an `:id` path param, ensure it matches the authenticated agent.
 * Use after authenticateAgent.
 */
export const requireAgentMatchesParam = (req: Request, _res: Response, next: NextFunction) => {
  if (!req.edrAgent || req.params.id !== req.edrAgent.agent_id) {
    return next(new ApiError(403, 'Agent id mismatch'));
  }
  next();
};
