import test from 'node:test';
import assert from 'node:assert/strict';
import { getNormalizedBaseUrl } from './src/api/client.js';

test('getNormalizedBaseUrl defaults to /api in local development', () => {
  assert.equal(getNormalizedBaseUrl(undefined, false, 'localhost'), '/api');
  assert.equal(getNormalizedBaseUrl('/api', false, 'localhost'), '/api');
  assert.equal(getNormalizedBaseUrl('', false, '127.0.0.1'), '/api');
});

test('getNormalizedBaseUrl falls back to Render backend in production when env is unset or /api', () => {
  assert.equal(
    getNormalizedBaseUrl(undefined, true, 'threatlens-cyber-threat-intelligence.vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('/api', true, 'threatlens-cyber-threat-intelligence.vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('', true, 'custom-domain.com'),
    'https://threatlens-api.onrender.com/api'
  );
});

test('getNormalizedBaseUrl normalizes configured Render backend URLs', () => {
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com/', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com/api', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com/api/', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
});

test('getNormalizedBaseUrl strips enclosing quotes from environment variables', () => {
  assert.equal(
    getNormalizedBaseUrl('"https://threatlens-api.onrender.com"', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl("'https://threatlens-api.onrender.com'", true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('"https://threatlens-api.onrender.com/api"', true, 'vercel.app'),
    'https://threatlens-api.onrender.com/api'
  );
});
