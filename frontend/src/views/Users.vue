<template>
  <div class="users">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>User Management</span>
          <el-button type="primary" size="small" @click="showCreateUser">
            <el-icon><Plus /></el-icon> Add User
          </el-button>
        </div>
      </template>

      <el-table :data="users" v-loading="loading" stripe>
        <el-table-column prop="username" label="Username" min-width="150" />
        <el-table-column prop="email" label="Email" min-width="200" />
        <el-table-column label="Role" width="120">
          <template #default="{ row }">
            <el-tag :type="getRoleType(row.role)">
              {{ row.role }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Created" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="Actions" width="200" align="center" fixed="right">
          <template #default="{ row }">
            <el-button
              size="small"
              @click="editUser(row)"
            >
              Edit
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="deleteUserConfirm(row)"
              :disabled="row.id === currentUserId"
            >
              Delete
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create/Edit User Dialog -->
    <el-dialog
      v-model="userDialogVisible"
      :title="editingUser ? 'Edit User' : 'Create New User'"
      width="600px"
      @close="resetForm"
    >
      <el-form :model="userForm" :rules="formRules" ref="formRef" label-width="150px">
        <el-form-item label="Username" prop="username">
          <el-input
            v-model="userForm.username"
            placeholder="john.doe"
            :disabled="editingUser"
          />
          <el-text v-if="editingUser" size="small" type="info" style="margin-top: 5px; display: block;">
            Username cannot be changed after creation
          </el-text>
        </el-form-item>

        <el-form-item label="Email" prop="email">
          <el-input
            v-model="userForm.email"
            type="email"
            placeholder="john.doe@company.com"
          />
        </el-form-item>

        <el-form-item label="Role" prop="role">
          <el-select v-model="userForm.role" placeholder="Select role" style="width: 100%">
            <el-option label="Admin - Full access" value="admin">
              <div style="display: flex; justify-content: space-between;">
                <span style="font-weight: 500;">Admin</span>
                <el-text type="info" size="small">Full access</el-text>
              </div>
            </el-option>
            <el-option label="Analyst - Manage alerts and rules" value="analyst">
              <div style="display: flex; justify-content: space-between;">
                <span style="font-weight: 500;">Analyst</span>
                <el-text type="info" size="small">Manage alerts and rules</el-text>
              </div>
            </el-option>
            <el-option label="Viewer - Read-only access" value="viewer">
              <div style="display: flex; justify-content: space-between;">
                <span style="font-weight: 500;">Viewer</span>
                <el-text type="info" size="small">Read-only access</el-text>
              </div>
            </el-option>
          </el-select>
        </el-form-item>

        <el-form-item v-if="!editingUser" label="Password" prop="password">
          <el-input
            v-model="userForm.password"
            type="password"
            placeholder="Min 8 characters"
            show-password
          />
        </el-form-item>

        <el-form-item v-if="!editingUser" label="Confirm Password" prop="confirmPassword">
          <el-input
            v-model="userForm.confirmPassword"
            type="password"
            placeholder="Retype password"
            show-password
          />
        </el-form-item>

        <el-form-item v-if="editingUser">
          <el-button @click="showChangePassword" type="warning" size="small">
            <el-icon><Lock /></el-icon> Change Password
          </el-button>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="userDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveUser" :loading="saving">
          {{ editingUser ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- Change Password Dialog -->
    <el-dialog
      v-model="passwordDialogVisible"
      title="Change Password"
      width="500px"
      @close="resetPasswordForm"
    >
      <el-form :model="passwordForm" :rules="passwordRules" ref="passwordFormRef" label-width="160px">
        <el-form-item label="New Password" prop="newPassword">
          <el-input
            v-model="passwordForm.newPassword"
            type="password"
            placeholder="Min 8 characters"
            show-password
          />
        </el-form-item>

        <el-form-item label="Confirm Password" prop="confirmPassword">
          <el-input
            v-model="passwordForm.confirmPassword"
            type="password"
            placeholder="Retype password"
            show-password
          />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="passwordDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="changePassword" :loading="saving">
          Change Password
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus';
import { Plus, Lock } from '@element-plus/icons-vue';
import { format } from 'date-fns';

const authStore = useAuthStore();

// State
const loading = ref(false);
const saving = ref(false);
const users = ref<any[]>([]);
const userDialogVisible = ref(false);
const passwordDialogVisible = ref(false);
const editingUser = ref(false);
const currentUserId = ref<number | null>(null);
const selectedUserId = ref<number | null>(null);

const formRef = ref<FormInstance>();
const passwordFormRef = ref<FormInstance>();

const userForm = reactive({
  username: '',
  email: '',
  role: 'viewer',
  password: '',
  confirmPassword: '',
});

const passwordForm = reactive({
  newPassword: '',
  confirmPassword: '',
});

// Validation rules
const validatePasswordMatch = (_rule: any, value: any, callback: any) => {
  if (value !== userForm.password) {
    callback(new Error('Passwords do not match'));
  } else {
    callback();
  }
};

const validateNewPasswordMatch = (_rule: any, value: any, callback: any) => {
  if (value !== passwordForm.newPassword) {
    callback(new Error('Passwords do not match'));
  } else {
    callback();
  }
};

const formRules: FormRules = {
  username: [
    { required: true, message: 'Username is required', trigger: 'blur' },
    { min: 3, message: 'Username must be at least 3 characters', trigger: 'blur' },
  ],
  email: [
    { required: true, message: 'Email is required', trigger: 'blur' },
    { type: 'email', message: 'Please enter a valid email', trigger: 'blur' },
  ],
  role: [
    { required: true, message: 'Role is required', trigger: 'change' },
  ],
  password: [
    { required: true, message: 'Password is required', trigger: 'blur' },
    { min: 8, message: 'Password must be at least 8 characters', trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: 'Please confirm password', trigger: 'blur' },
    { validator: validatePasswordMatch, trigger: 'blur' },
  ],
};

const passwordRules: FormRules = {
  newPassword: [
    { required: true, message: 'Password is required', trigger: 'blur' },
    { min: 8, message: 'Password must be at least 8 characters', trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: 'Please confirm password', trigger: 'blur' },
    { validator: validateNewPasswordMatch, trigger: 'blur' },
  ],
};

// Fetch users
async function fetchUsers() {
  loading.value = true;
  try {
    const response = await api.getUsers();
    users.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch users');
  } finally {
    loading.value = false;
  }
}

// Show create dialog
function showCreateUser() {
  editingUser.value = false;
  resetForm();
  userDialogVisible.value = true;
}

// Edit user
function editUser(user: any) {
  editingUser.value = true;
  selectedUserId.value = user.id;

  userForm.username = user.username;
  userForm.email = user.email;
  userForm.role = user.role;
  userForm.password = '';
  userForm.confirmPassword = '';

  userDialogVisible.value = true;
}

// Save user (create or update)
async function saveUser() {
  if (!formRef.value) return;

  await formRef.value.validate(async (valid) => {
    if (!valid) return;

    saving.value = true;
    try {
      if (editingUser.value && selectedUserId.value) {
        // Update user (without password)
        await api.updateUser(selectedUserId.value, {
          email: userForm.email,
          role: userForm.role,
        });
        ElMessage.success('User updated successfully');
      } else {
        // Create user (with password)
        await api.createUser({
          username: userForm.username,
          email: userForm.email,
          role: userForm.role,
          password: userForm.password,
        });
        ElMessage.success('User created successfully');
      }

      userDialogVisible.value = false;
      fetchUsers();
    } catch (error: any) {
      const message = error.response?.data?.message || 'Failed to save user';
      ElMessage.error(message);
    } finally {
      saving.value = false;
    }
  });
}

// Delete user
async function deleteUserConfirm(user: any) {
  if (user.id === currentUserId.value) {
    ElMessage.warning('You cannot delete yourself');
    return;
  }

  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete user "${user.username}"? This action cannot be undone.`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteUser(user.id);
    ElMessage.success('User deleted successfully');
    fetchUsers();
  } catch (error: any) {
    if (error !== 'cancel') {
      const message = error.response?.data?.message || 'Failed to delete user';
      ElMessage.error(message);
    }
  }
}

// Show change password dialog
function showChangePassword() {
  resetPasswordForm();
  passwordDialogVisible.value = true;
}

// Change password
async function changePassword() {
  if (!passwordFormRef.value) return;

  await passwordFormRef.value.validate(async (valid) => {
    if (!valid) return;

    saving.value = true;
    try {
      await api.updateUser(selectedUserId.value!, {
        password: passwordForm.newPassword,
      });
      ElMessage.success('Password changed successfully');
      passwordDialogVisible.value = false;
    } catch (error: any) {
      const message = error.response?.data?.message || 'Failed to change password';
      ElMessage.error(message);
    } finally {
      saving.value = false;
    }
  });
}

// Reset forms
function resetForm() {
  userForm.username = '';
  userForm.email = '';
  userForm.role = 'viewer';
  userForm.password = '';
  userForm.confirmPassword = '';
  formRef.value?.clearValidate();
}

function resetPasswordForm() {
  passwordForm.newPassword = '';
  passwordForm.confirmPassword = '';
  passwordFormRef.value?.clearValidate();
}

// Helper functions
function getRoleType(role: string): string {
  const types: Record<string, string> = {
    admin: 'danger',
    analyst: 'warning',
    viewer: 'info',
  };
  return types[role] || 'info';
}

function formatDate(date: string): string {
  if (!date) return '-';
  return format(new Date(date), 'MMM dd, yyyy HH:mm');
}

// On mount
onMounted(() => {
  currentUserId.value = authStore.user?.id || null;
  fetchUsers();
});
</script>

<style scoped>
.users {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
