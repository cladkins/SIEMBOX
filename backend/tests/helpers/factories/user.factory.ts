/**
 * User Factory for Testing
 * Creates test user data using Fishery
 */

import { Factory } from 'fishery';
import { User, UserSafe } from '../../../src/models/User';

export const userFactory = Factory.define<User>(({ sequence }) => ({
  id: sequence,
  username: `user${sequence}`,
  email: `user${sequence}@siembox.local`,
  password_hash: '$2b$10$abcdefghijklmnopqrstuvwxyz123456', // Mock bcrypt hash
  role: 'viewer',
  enabled: true,
  last_login: null,
  created_at: new Date(),
  updated_at: new Date(),
}));

export const adminUserFactory = userFactory.params({
  role: 'admin',
  username: 'admin',
  email: 'admin@siembox.local',
});

export const analystUserFactory = userFactory.params({
  role: 'analyst',
});

export const operatorUserFactory = userFactory.params({
  role: 'operator',
});

export const userSafeFactory = Factory.define<UserSafe>(({ sequence }) => ({
  id: sequence,
  username: `user${sequence}`,
  email: `user${sequence}@siembox.local`,
  role: 'viewer',
  enabled: true,
  last_login: null,
  created_at: new Date(),
  updated_at: new Date(),
}));
