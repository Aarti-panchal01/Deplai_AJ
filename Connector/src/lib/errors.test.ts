import assert from 'node:assert/strict';
import { test } from 'node:test';

import { errorCode, errorMessage, errorStatus } from './errors.ts';

test('errorMessage handles Error, string, message-bearing objects and fallbacks', () => {
  assert.equal(errorMessage(new Error('boom')), 'boom');
  assert.equal(errorMessage('plain'), 'plain');
  assert.equal(errorMessage({ message: 'from object' }), 'from object');
  assert.equal(errorMessage(42), 'Unknown error');
  assert.equal(errorMessage(null, 'custom'), 'custom');
});

test('errorCode and errorStatus only accept the right types', () => {
  assert.equal(errorCode({ code: 'ECONNREFUSED' }), 'ECONNREFUSED');
  assert.equal(errorCode({ code: 5 }), undefined);
  assert.equal(errorStatus({ status: 404 }), 404);
  assert.equal(errorStatus({ status: '404' }), undefined);
  assert.equal(errorStatus(undefined), undefined);
});
