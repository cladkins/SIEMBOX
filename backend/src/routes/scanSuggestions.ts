import { Router, Request, Response } from 'express';
import { hasRequiredRole, requireScanPermission, UserRole } from '../middleware/scanPermissions';
import { AuditService } from '../services/audit/auditService';
import { fetchScanCatalog } from '../services/scanSuggestions/scanCatalog';
import { addSuggestion } from '../services/scanSuggestions/addSuggestion';

// Suggested scans (catalog scans/<id>.scan.yaml; services/scanSuggestions).
// app.ts mounts this router behind `authenticate`.
//
// GET  /           the suggestions, any role (catalog content, nothing secret).
//                  ?refresh=true re-reads the catalog (operator and up; others
//                  get the cache).
// POST /:id/add    create what a suggestion describes, disabled: a scheduled
//                  scan (Scheduled Scans) or an unassigned endpoint scan policy
//                  (Endpoints). Admin or operator, the roles that create
//                  schedules and policies; refusals are written to audit_logs.
//                  Body: { timezone } (the browser's IANA zone; default UTC).
const router = Router();
const requireSuggestionAdd = requireScanPermission(UserRole.Operator, 'scan_suggestion');

router.get('/', async (req: Request, res: Response) => {
  const refresh = req.query.refresh === 'true' && hasRequiredRole(req.user?.role ?? '', UserRole.Operator);
  res.json(await fetchScanCatalog({ force: refresh }));
});

router.post('/:id/add', requireSuggestionAdd, async (req: Request, res: Response) => {
  const result = await addSuggestion(req.params.id, req.body, req.user?.id ?? null);
  await AuditService.log({
    userId: req.user?.id ?? null,
    action: 'scan_suggestion.add',
    resourceType: result.policy ? 'edr_scan_policy' : 'scheduled_scan',
    resourceId: result.policy?.id ?? result.scheduled_scan?.id,
    ipAddress: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
    responseStatus: 201,
    details: { suggestion_id: result.suggestion_id, kind: result.kind },
  });
  res.status(201).json(result);
});

export default router;
