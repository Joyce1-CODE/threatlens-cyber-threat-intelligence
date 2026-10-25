import test from 'node:test';
import assert from 'node:assert/strict';
import { getNormalizedBaseUrl } from './src/api/client.js';

test('getNormalizedBaseUrl defaults to /api to support local Vite proxy and Vercel edge rewrite proxy', () => {
  assert.equal(getNormalizedBaseUrl(undefined), '/api');
  assert.equal(getNormalizedBaseUrl('/api'), '/api');
  assert.equal(getNormalizedBaseUrl(''), '/api');
  assert.equal(getNormalizedBaseUrl('   '), '/api');
  assert.equal(getNormalizedBaseUrl('"/api"'), '/api');
  assert.equal(getNormalizedBaseUrl("'/api'"), '/api');
});

test('getNormalizedBaseUrl normalizes configured Render backend URLs', () => {
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api-wwxr.onrender.com'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api-wwxr.onrender.com/'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api-wwxr.onrender.com/api'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api-wwxr.onrender.com/api/'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
});

test('getNormalizedBaseUrl automatically corrects legacy Render host without slug', () => {
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('https://threatlens-api.onrender.com/api'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
});

test('getNormalizedBaseUrl strips enclosing quotes from environment variables', () => {
  assert.equal(
    getNormalizedBaseUrl('"https://threatlens-api-wwxr.onrender.com"'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl("'https://threatlens-api-wwxr.onrender.com'"),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
  assert.equal(
    getNormalizedBaseUrl('"https://threatlens-api-wwxr.onrender.com/api"'),
    'https://threatlens-api-wwxr.onrender.com/api'
  );
});
