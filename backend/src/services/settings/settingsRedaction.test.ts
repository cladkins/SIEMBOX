/**
 * The rule that decides which system_settings values GET /api/settings returns
 * (settingsRedaction.ts). Pure: no database. The inventory below is every key
 * the backend or a migration writes to system_settings, classified as a stored
 * secret or a plain setting; new key names check that the rule fails closed.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { CredentialEncryption } from '../credentials/credentialEncryption';
import {
  READABLE_SETTING_KEYS,
  REDACTED_VALUE,
  holdsCredentialEnvelope,
  isReadableSetting,
  isSecretSettingKey,
  settingRowForAdmin,
} from './settingsRedaction';

// A throwaway key for this test process, so envelope() works whatever the environment holds.
process.env.CREDENTIAL_ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');

/** A stored key exactly as the services write it (aiService, reputationService, exposure/settings). */
function envelope(plaintext: string): string {
  return JSON.stringify(CredentialEncryption.encrypt(plaintext));
}

/** Every credential the code stores in system_settings, by writer. */
const STORED_SECRETS: Array<[key: string, writer: string]> = [
  ['ai_api_key', 'services/ai/aiService.ts saveAiConfig'],
  ['ai_chat_api_key', 'services/ai/aiService.ts saveChatAiConfig'],
  ['ai_triage_api_key', 'services/ai/aiService.ts saveTriageConfig'],
  // Where each saved AI key may be sent, encrypted with a hash of the key.
  ['ai_api_key_target', 'services/ai/aiService.ts saveAiConfig'],
  ['ai_chat_api_key_target', 'services/ai/aiService.ts saveChatAiConfig'],
  ['ai_triage_api_key_target', 'services/ai/aiService.ts saveTriageConfig'],
  ['ti_abuseipdb_key', 'services/threatintel/reputationService.ts saveProvider'],
  ['ti_otx_key', 'services/threatintel/reputationService.ts saveProvider'],
  ['exposure_hibp_key', 'services/exposure/settings.ts saveHibpProvider'],
];

/** Every plain setting the code or a migration writes, with a typical value. */
const PLAIN_SETTINGS: Array<[key: string, value: string]> = [
  ['auto_discovery_enabled', 'true'],
  ['auto_discovery_interval_minutes', '360'],
  ['stale_asset_threshold_days', '30'],
  ['retention_raw_logs_days', '30'],
  ['retention_parsed_logs_days', '90'],
  ['retention_alerts_days', '365'],
  ['retention_auto_cleanup_enabled', 'true'],
  ['syslog_host', '192.0.2.10'],
  ['syslog_port', '514'],
  ['notify_alerts_enabled', 'false'],
  ['notify_alerts_min_severity', 'high'],
  ['notify_vuln_enabled', 'false'],
  ['notify_vuln_min_severity', 'high'],
  ['notify_ingestion_enabled', 'false'],
  ['notify_ingestion_stall_minutes', '15'],
  ['ai_provider', 'anthropic'],
  ['ai_model', 'claude-sonnet-4-6'],
  ['ai_base_url', 'https://api.openai.com/v1'],
  ['ai_chat_provider', 'openai'],
  ['ai_chat_model', 'gpt-4o'],
  ['ai_chat_base_url', ''],
  ['ai_triage_provider', ''],
  ['ai_triage_model', ''],
  ['ai_triage_base_url', 'http://localhost:11434'],
  ['ai_triage_enabled', 'true'],
  ['ai_triage_min_severity', 'medium'],
  ['ai_triage_daily_cap', '200'],
  ['ai_triage_max_concurrent', '2'],
  ['ai_triage_dedupe_hours', '6'],
  ['ai_triage_max_tool_calls', '6'],
  ['ai_triage_wall_budget_seconds', '110'],
  ['ti_abuseipdb_enabled', 'true'],
  ['ti_otx_enabled', 'false'],
  ['notify_exposure_enabled', 'false'],
  ['notify_exposure_min_severity', 'medium'],
  ['exposure_leaked_creds_enabled', 'true'],
  ['exposure_hibp_enabled', 'false'],
  ['exposure_domain_monitor_enabled', 'true'],
  ['exposure_domain_expiry_warning_days', '30'],
  ['exposure_lookalike_max_candidates', '300'],
  ['exposure_dns_secondary_resolver', '9.9.9.9'],
  [
    'exposure_hibp_domains',
    JSON.stringify({
      v: 1,
      key_ref: '9c1f0a2b7d3e4f50',
      checked_at: '2026-10-12T09:41:07.000Z',
      listed_at: '2026-10-12T09:41:07.000Z',
      stale: false,
      error: null,
      plan: { name: 'Core 2', domain_search_max_breached_accounts: 100, max_breached_domains: 3, subscribed_until: null },
      domains: [{ domain: 'example.com', pwn_count: 40, pwn_count_excluding_spam_lists: 38 }],
      truncated: false,
      skipped_entries: 0,
    }),
  ],
  ['onboarding_completed', '{"at":"2026-10-12T09:30:00.000Z","by":"admin"}'],
  ['log_discovery_manual_cidrs', '192.168.1.0/24,10.0.0.0/24'],
];

test('the inventory covers the readable list exactly', () => {
  assert.deepEqual(
    PLAIN_SETTINGS.map(([key]) => key).sort(),
    [...READABLE_SETTING_KEYS].sort(),
    'a key added to READABLE_SETTING_KEYS needs a line in PLAIN_SETTINGS, and the other way round'
  );
  for (const [key] of STORED_SECRETS) {
    assert.ok(!READABLE_SETTING_KEYS.has(key), `${key} must not be on the readable list`);
  }
});

test('no key on the readable list is named like a credential', () => {
  for (const key of READABLE_SETTING_KEYS) {
    assert.equal(isSecretSettingKey(key), false, key);
  }
});

for (const [key, writer] of STORED_SECRETS) {
  test(`${key} (${writer}) is never returned`, () => {
    assert.equal(isSecretSettingKey(key), true, 'named like a credential');
    const stored = envelope(`plaintext-of-${key}`);
    const row = settingRowForAdmin(key, stored);
    assert.deepEqual(row, { setting_key: key, setting_value: REDACTED_VALUE, redacted: true, configured: true });
    // A cleared key is stored as ''; a hand-edited row could hold the key in plaintext.
    assert.deepEqual(settingRowForAdmin(key, ''), { setting_key: key, setting_value: '', redacted: true, configured: false });
    assert.deepEqual(settingRowForAdmin(key, 'sk-plaintext-by-hand'), {
      setting_key: key,
      setting_value: REDACTED_VALUE,
      redacted: true,
      configured: true,
    });
    const { encrypted, iv, authTag } = JSON.parse(stored);
    const serialized = JSON.stringify(row);
    for (const part of [encrypted, iv, authTag, 'encrypted', 'authTag']) {
      assert.ok(!serialized.includes(part), `the row carries no part of the envelope (${part})`);
    }
  });
}

test('plain settings come back unchanged', () => {
  for (const [key, value] of PLAIN_SETTINGS) {
    assert.deepEqual(settingRowForAdmin(key, value), { setting_key: key, setting_value: value, redacted: false }, key);
  }
});

test('new credential-like keys are withheld without being listed anywhere', () => {
  for (const key of [
    'ti_greynoise_key', // a third reputation provider, same naming as ti_<name>_key
    'ai_embeddings_api_key',
    'slack_bot_token',
    'webhook_signing_secret',
    'smtp_password',
    'ldap_bind_passwd',
    'backup_passphrase',
    'edr_enrollment_token_hash',
    'vt_api_keys',
    'smtpPassword',
    'hibpAPIKey',
    'AI_API_KEY',
    'ai_api_key_v2',
    'oauth.client-secret',
  ]) {
    assert.equal(isSecretSettingKey(key), true, `${key} is named like a credential`);
    assert.equal(settingRowForAdmin(key, 'hunter2').setting_value, REDACTED_VALUE, key);
  }
});

test('a key that is not on the readable list is withheld (fails closed)', () => {
  // A plain-looking setting nobody has classified yet.
  assert.deepEqual(settingRowForAdmin('dashboard_default_view', 'true'), {
    setting_key: 'dashboard_default_view',
    setting_value: REDACTED_VALUE,
    redacted: true,
    configured: true,
  });
  assert.deepEqual(settingRowForAdmin('slack_webhook_url', ''), {
    setting_key: 'slack_webhook_url',
    setting_value: '',
    redacted: true,
    configured: false,
  });
});

test('a credential envelope is withheld whatever the key is called', () => {
  const stored = envelope('sk-under-an-innocent-name');
  assert.equal(holdsCredentialEnvelope(stored), true);
  // Even a key on the readable list.
  assert.equal(isReadableSetting('ai_base_url', stored), false);
  assert.deepEqual(settingRowForAdmin('ai_base_url', stored), {
    setting_key: 'ai_base_url',
    setting_value: REDACTED_VALUE,
    redacted: true,
    configured: true,
  });
  // Nested, encoded twice, spaced out, or cut short.
  for (const value of [
    JSON.stringify({ provider: 'x', key: JSON.parse(stored) }),
    JSON.stringify(stored),
    '{ "iv" : "abc", "encrypted" : "def" }',
    '{"encrypted":"UbgQlnf5GxrPjSpytl3HJWxU',
    '{"AuthTag":"x"}',
  ]) {
    assert.equal(holdsCredentialEnvelope(value), true, value);
    assert.equal(isReadableSetting('syslog_host', value), false, value);
  }
});

test('plain values are not mistaken for envelopes', () => {
  for (const value of ['', 'true', '30', '192.168.1.0/24', 'https://api.openai.com/v1', '{"ct":true,"dns":true}', 'encrypted']) {
    assert.equal(holdsCredentialEnvelope(value), false, value);
  }
});

test('names are matched by whole words, not substrings', () => {
  for (const key of ['exposure_leaked_creds_enabled', 'keyword_alerts', 'hotkey_enabled', 'monkey_mode', 'tokenizer', 'hashtag_feed']) {
    assert.equal(isSecretSettingKey(key), false, key);
  }
});

test('a missing value reads as not configured', () => {
  assert.deepEqual(settingRowForAdmin('ai_api_key', null), {
    setting_key: 'ai_api_key',
    setting_value: '',
    redacted: true,
    configured: false,
  });
  assert.deepEqual(settingRowForAdmin('retention_raw_logs_days', undefined), {
    setting_key: 'retention_raw_logs_days',
    setting_value: '',
    redacted: false,
  });
});
