# User Management

SIEMBox provides a comprehensive User Management interface that allows administrators to manage application users and their roles.

## Overview

The User Management feature enables administrators to:
- View all users in the system
- Create new user accounts
- Edit existing user details (email, role)
- Change user passwords
- Delete user accounts
- Manage role-based access control

## User Roles

SIEMBox supports three user roles with different permission levels:

### Admin
**Full Access**: Complete control over all SIEMBox features
- Manage users, parsers, rules, shippers, and settings
- View and manage all logs and alerts
- Configure system-wide settings
- Delete and modify any resource

### Analyst
**Operational Access**: Manage security operations
- View and manage alerts
- Create and edit parsers
- Create and edit detection rules
- View logs and parsed data
- **Cannot**: Manage users, shippers, or system settings

### Viewer
**Read-Only Access**: Monitor security events
- View logs and parsed data
- View alerts (cannot modify)
- View parsers and rules (cannot modify)
- **Cannot**: Create, edit, or delete any resources

## Accessing User Management

1. Log in to SIEMBox as an **admin** user
2. Navigate to **Users** in the left sidebar menu
3. The Users menu is only visible to admin users

## Managing Users

### View Users

The User Management page displays a table with all users:
- **Username**: Unique user identifier
- **Email**: User's email address
- **Role**: User's permission level (Admin/Analyst/Viewer)
- **Created**: Account creation timestamp
- **Actions**: Edit and Delete buttons

### Create New User

1. Click the **Add User** button (top right)
2. Fill in the required fields:
   - **Username**: 3+ characters, cannot be changed after creation
   - **Email**: Valid email address
   - **Role**: Select from Admin, Analyst, or Viewer
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
- The user will need to log in with the new password
- This is useful for password resets

### Delete User

1. Click the **Delete** button for a user
2. Confirm the deletion in the popup dialog
3. The user account is permanently removed

**Restrictions**:
- You cannot delete your own account
- The Delete button is disabled for the currently logged-in user
- Deletion is permanent and cannot be undone
- All user sessions are invalidated upon deletion

## Security Considerations

### Access Control
- Only **admin** users can access the User Management page
- Non-admin users attempting to access `/users` are redirected to the dashboard
- All user management API endpoints require admin authentication

### Password Security
- Passwords are hashed using bcrypt with salt rounds
- Minimum password length: 8 characters
- Passwords are never displayed in the UI
- Passwords are not returned by the API

### Session Management
- When an admin changes a user's password, existing sessions remain active
- Users should be notified out-of-band when passwords are changed
- Consider logging out the user after password change for security

### Audit Logging
- All user management actions are logged in the backend
- Logs include: username, action type, timestamp, and admin who performed the action
- Review backend logs for user management audit trail

## API Endpoints

User management operations use the following REST API endpoints:

```
GET    /api/users           - List all users (admin only)
GET    /api/users/:id       - Get user details (admin only)
POST   /api/users           - Create new user (admin only)
PUT    /api/users/:id       - Update user (admin only)
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
4. Reserve admin role for system administrators only
5. Use viewer role for stakeholders who need read-only access

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
- Clear browser cache and try again
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
