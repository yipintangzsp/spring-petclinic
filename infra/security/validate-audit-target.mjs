import {resolveAuditTarget} from './audit-target.mjs';
resolveAuditTarget('',process.env.AUDIT_CANDIDATE_IMAGE);

if(process.env.PROMOTION_ACTION&&process.env.PROMOTION_ACTION!=='audit-only'&&!String(process.env.AUDIT_CANDIDATE_IMAGE||'').trim())throw Error('Promotion requires an explicit candidate digest');
