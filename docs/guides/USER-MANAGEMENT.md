# User Management

SIEMBox provides a comprehensive User Management interface that allows administrators to manage application users and their roles.

## Overview

The User Management feature enables administrators to:
- View all users in the system
- Create new user accounts
- Edit existing user details (email, role)
- Change user passwords
- Unlock sign-in for an account paused after failed attempts
- Delete user accounts
- Manage role-based access control

## User Roles

SIEMBox has four roles. Each one includes everything the roles before it can do:
**viewer < analyst < operator < admin**.

### Viewer
**Read-only.** A viewer can see the dashboard, logs, alerts, parsers, detection rules,
Content Packs, shippers and threat intel, but cannot create, edit or delete anything. Besides
reading, a viewer can only manage their own account (password, MFA), test a saved parser
against a sample, export or contribute a parser or rule, use "Explain this", and check a
password against known breaches through the API (`POST /api/exposure/password-check`; the
check's card in Settings → Digital Risk is admin-only).

### Analyst
**Detection content and alert triage.** Everything a viewer can do, plus:
- triage alerts (status, notes, assignee) and re-run AI triage
- use the AI Analyst and the SOC Triage page
- create, edit, enable/disable, import and delete parsers, and test unsaved patterns
- create, edit, enable/disable and delete detection rules
- install from the parser and detection catalogs (one, all, or the Recommended list)
- edit the asset inventory, run asset discovery scans and refresh vulnerability templates

### Operator
**Scanning and log collection.** Everything an analyst can do, plus:
- run and cancel vulnerability scans, download templates and mark vulnerabilities remediated
- container scans, scheduled scans, and Log Discovery scans and source triage
- manage log shippers (create, edit, delete, sources and volumes); operators see each
  shipper's syslog API key
- refresh threat feeds

### Admin
**Full access.** Everything an operator can do, plus users, every Settings area (AI, data
retention, log ingestion, notifications, detections, asset discovery, Digital Risk, system),
the Endpoints (EDR) and Admin pages, deleting alerts, the AI parser and detection builders,
Sigma import and Content Pack installs.

### Permission table

What each role can do through the UI and the API. A role that may not make a call gets `403`
from the API, and the UI hides or disables the matching control.

| Action | Viewer | Analyst | Operator | Admin |
|---|---|---|---|---|
| View the dashboard, logs, alerts, parsers, rules, catalogs, Content Packs, shippers, threat intel | yes | yes | yes | yes |
| Asset Inventory and Templates pages | no | yes | yes | yes |
| Vulnerability, container, scheduled-scan and Log Discovery pages | no | no | yes | yes |
| Own account: password, MFA | yes | yes | yes | yes |
| Test a saved parser, export or contribute a parser or rule, "Explain this" | yes | yes | yes | yes |
| Password breach check through the API (the Settings → Digital Risk card is admin-only) | yes | yes | yes | yes |
| Triage alerts (status, notes, assignee), re-run AI triage | no | yes | yes | yes |
| AI Analyst chat, SOC Triage page | no | yes | yes | yes |
| Create, edit, enable/disable, import or delete parsers; test an unsaved parser | no | yes | yes | yes |
| Create, edit, enable/disable or delete detection rules | no | yes | yes | yes |
| Install, update or refresh (re-fetch from GitHub) the parser and detection catalogs | no | yes | yes | yes |
| Asset inventory edits, asset discovery scans, vulnerability template refresh | no | yes | yes | yes |
| Vulnerability scans, template download, mark vulnerabilities remediated | no | no | yes | yes |
| Container scans, scheduled scans | no | no | yes | yes |
| Log Discovery scans; confirm, ignore and onboard discovered sources | no | no | yes | yes |
| Manage log shippers (create, edit, delete, sources, volumes); see shipper API keys | no | no | yes | yes |
| Refresh threat feeds | no | no | yes | yes |
| Delete alerts | no | no | no | yes |
| AI parser and detection builders, Sigma import, Content Pack install | no | no | no | yes |
| Users, Settings areas (other than Account), Endpoints (EDR), Admin dashboard | no | no | no | yes |
| Shipper key regeneration and HTTP push keys; Log Discovery scope, manual sources, editing a source's poll target, and poll credentials; threat feed and Digital Risk configuration | no | no | no | yes |

The pages a role can't open only hide data from the UI: every signed-in role can read assets,
vulnerabilities, scans and Digital Risk findings through the API, and no role can change them
through it without the matching write permission above.

A refused parser, rule, alert, AI Analyst, asset or scan change is also recorded in the audit
log (`audit_logs`, action `access.denied`). The full per-route list lives in
`backend/src/routes/routeInventory.test.ts`; the test suite checks it against the running API.
See [API Reference → Roles](../reference/API.md#roles) for the routes.

## Accessing User Management

1. Log in to SIEMBox as an **admin** user
2. Navigate to **Users** in the left sidebar menu
3. The Users menu is only visible to admin users

## Managing Users

### View Users

The User Management page displays a table with all users:
- **Username**: Unique user identifier
- **Email**: User's email address
- **Role**: User's permission level (Admin/Operator/Analyst/Viewer)
- **Created**: Account creation timestamp
- **Sign-in**: "Sign-in paused · 12 min" while failed sign-in attempts hold the
  account back (the tooltip says which: from one network, from new browsers on
  every network, one of their recognized browsers, MFA codes, or a network
  paused by failures for any username that they mistyped from in the last 15
  minutes), and "Password change paused" while wrong current passwords hold
  back changing their own password (signing in is not affected)
- **Actions**: Unlock (only while something is paused), Edit and Delete buttons

### Create New User

1. Click the **Add User** button (top right)
2. Fill in the required fields:
   - **Username**: 3+ characters, cannot be changed after creation
   - **Email**: Valid email address
   - **Role**: Select from Admin, Operator, Analyst, or Viewer
   - **Password**: Minimum 8 characters
   - **Confirm Password**: Must match password
3. Click **Create**

**Validation Rules**:
- Username must be at least 3 characters
- Username must be unique
- Email must be valid format
- Email must be unique
- Password must be at least 8 characters
- Passwords must match

### Edit User

1. Click the **Edit** button for a user
2. Update the desired fields:
   - **Email**: Change user's email address
   - **Role**: Change user's permission level
3. Click **Update**

**Important Notes**:
- Username cannot be changed after account creation
- Password is not changed during user edit (use Change Password instead)
- Changing a user's role takes effect immediately

### Change User Password

1. Click **Edit** on a user
2. Click **Change Password** button
3. Enter the new password (minimum 8 characters)
4. Confirm the password
5. Click **Change Password**

**Security Notes**:
- Admin users can change any user's password without knowing the current password
- It is a reset: the user is signed out everywhere at once, the browsers they
  signed in from are no longer recognized, and their sign-in pauses are cleared.
  They sign in with the new password (resetting your own signs you out too)
- Audited as `user.password_reset`

### Unlock Sign-in

Failed sign-ins pause further attempts for a while instead of locking the
account (30 seconds, doubling with each further failure; DEPLOYMENT.md,
"Sign-in protection"). A paused account shows "Sign-in paused" in the
**Sign-in** column.

1. Find out whose attempts they were: Alerts (source `siembox-auth`) and
   Settings -> **Sign-in protection** show the networks and user agents
2. Click **Unlock** on the user and confirm

This clears every sign-in counter of the account; a pause of a whole network
is cleared on Settings -> Sign-in protection. A user who mistyped from a
network someone else's failures have paused (a shared address: an office NAT,
a reverse proxy SIEMBox doesn't trust) is listed too, for 15 minutes at most:
Unlock lets them in while the network stays paused. The user can also simply wait,
or sign in from a browser they used before, which is never held back by
someone else's failed attempts. Without access to the web UI, see
TROUBLESHOOTING.md, "Locked out of SIEMBox" (the `auth-admin` command line).

### Delete User

1. Click the **Delete** button for a user
2. Confirm the deletion in the popup dialog
3. The user account is permanently removed

**Restrictions**:
- You cannot delete your own account
- The Delete button is disabled for the currently logged-in user
- Deletion is permanent and cannot be undone
- All user sessions, recognized browsers and sign-in counters are removed upon deletion

## Security Considerations

### Access Control
- Only **admin** users can access the User Management page
- Non-admin users attempting to access `/users` are redirected to the dashboard
- All user management API endpoints require admin authentication

### Password Security
- Passwords are hashed using bcrypt with salt rounds
- Passwords are 8 to 1024 characters; changing your own requires the current
  one, and the new one must differ from it
- Passwords are never displayed in the UI
- Passwords are not returned by the API
- Failed sign-ins pause further attempts (sign-in protection); see
  [Unlock Sign-in](#unlock-sign-in)

### Session Management
- When an admin changes a user's password, or users change their own, every
  session of that user ends at once and their browsers are no longer recognized
- Users should be notified out-of-band when passwords are changed

### Audit Logging
- User management actions are written to `audit_logs`: `user.created`,
  `user.updated` (with the fields changed), `user.deleted`,
  `user.password_reset` and `auth.unlock`, with the admin who did it and their
  address
- Sign-in events too: `auth.login.success`, `auth.login.failure`,
  `auth.login.paused`, `auth.logout`, `auth.password.changed`,
  `auth.mfa.enabled` / `disabled` (see SECURITY.md, "Audit Logging")

## API Endpoints

User management operations use the following REST API endpoints:

```
GET    /api/users           - List all users (admin only)
GET    /api/users/:id       - Get user details (admin only)
POST   /api/users           - Create new user (admin only)
PUT    /api/users/:id       - Update user (admin only; a password is a reset)
POST   /api/users/:id/unlock - Clear the account's sign-in pauses (admin only)
DELETE /api/users/:id       - Delete user (admin only)
```

### Example API Usage

**Create User:**
```bash
curl -X POST http://localhost:5000/api/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@company.com",
    "password": "SecurePassword123",
    "role": "analyst"
  }'
```

**Update User:**
```bash
curl -X PUT http://localhost:5000/api/users/2 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@newdomain.com",
    "role": "admin"
  }'
```

**Change Password:**
```bash
curl -X PUT http://localhost:5000/api/users/2 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "NewSecurePassword123"
  }'
```

**Delete User:**
```bash
curl -X DELETE http://localhost:5000/api/users/2 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Best Practices

### User Account Management
1. **Principle of Least Privilege**: Assign the minimum role required for each user
2. **Regular Audits**: Periodically review user accounts and remove inactive users
3. **Strong Passwords**: Enforce strong password policies in your organization
4. **Role Changes**: Document and track role changes for audit purposes
5. **Admin Accounts**: Limit the number of admin accounts to reduce attack surface

### Password Management
1. Use strong, unique passwords for each user
2. Consider implementing password rotation policies
3. Educate users on password security best practices
4. Use password managers for generating and storing passwords
5. Never share passwords between users

### Access Control
1. Create separate accounts for each user (never share accounts)
2. Remove user accounts promptly when employees leave
3. Use analyst role for most security team members
4. Use operator role for the people who run scans and manage log shippers (operators see shipper API keys)
5. Reserve admin role for system administrators only
6. Use viewer role for stakeholders who need read-only access

## Troubleshooting

### Cannot Access User Management
**Problem**: Users menu item not visible
**Solution**: Only admin users can see the Users menu. Verify your account has the admin role.

### Cannot Create User
**Problem**: "Username already exists" error
**Solution**: Usernames must be unique. Choose a different username.

**Problem**: "Email already exists" error
**Solution**: Email addresses must be unique. Use a different email or update the existing user.

### Password Not Working After Change
**Problem**: User cannot log in after password change
**Solution**:
- Verify the new password was entered correctly
- Check that password meets minimum length (8 characters)
- If the login page counts down ("Try again in ..."), earlier failed attempts
  paused sign-in: wait, or **Unlock** the user
- Have admin reset password again if needed

### Cannot Delete User
**Problem**: Delete button is disabled
**Solution**: You cannot delete your own account. Have another admin delete the account if needed.

### User Still Has Access After Role Change
**Problem**: User permissions didn't update after role change
**Solution**:
- Role changes take effect immediately for new requests
- User may need to log out and log back in
- Check browser cache/session storage
- Verify the role change was saved successfully

## Database Schema

Users are stored in the `users` table with the following structure:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'viewer',
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
);
```

## Related Documentation

- [API Documentation](../reference/API.md) - Complete API reference
- [Security Guide](../reference/SECURITY.md) - Security best practices
- [Deployment Guide](../../DEPLOYMENT.md) - Initial user setup
- [Contributing Guide](../../CONTRIBUTING.md) - Development guidelines

## Support

For issues or questions about User Management:
1. Check this documentation first
2. Review the [Troubleshooting Guide](../operations/TROUBLESHOOTING.md)
3. Search existing [GitHub Issues](https://github.com/cladkins/SIEMBOX/issues)
4. Create a new issue if your problem isn't resolved
