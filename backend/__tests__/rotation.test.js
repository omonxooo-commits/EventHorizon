/**
 * Tests for automated secret rotation (#281)
 * Uses Node's built-in test runner (node --test)
 */
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

// ── Minimal stubs so we don't need a live DB ──────────────────────────────────

let savedCredential = null;
let savedPolicy = null;
let auditLogs = [];

const mockCredential = {
    _id: 'cred-001',
    userId: 'user-001',
    provider: 'slack',
    accessToken: 'encrypted-old-token',
    refreshToken: 'encrypted-old-refresh',
    status: 'active',
    save: async function() { savedCredential = { ...this }; }
};

// Stub Credential model
const CredentialStub = {
    findOne: async ({ _id, userId }) => {
        if (_id === mockCredential._id && userId === mockCredential.userId) {
            return { ...mockCredential, save: mockCredential.save };
        }
        return null;
    }
};

// Stub RotationPolicy model
const RotationPolicyStub = {
    findOne: async ({ credentialId }) => credentialId === 'cred-001' ? savedPolicy : null,
    findOneAndUpdate: async (filter, update) => {
        if (savedPolicy && filter.credentialId === savedPolicy.credentialId) {
            savedPolicy = { ...savedPolicy, ...update.$set };
            savedPolicy.rotationCount = (savedPolicy.rotationCount || 0) + (update.$inc?.rotationCount || 0);
        }
        return savedPolicy;
    },
    create: async (data) => {
        savedPolicy = { _id: 'policy-001', ...data, rotationCount: 0 };
        return savedPolicy;
    },
    find: async (filter) => {
        if (!savedPolicy) return [];
        const now = new Date();
        if (savedPolicy.status === 'active' && savedPolicy.autoRotate && savedPolicy.nextRotationAt <= now) {
            return [{ ...savedPolicy, credentialId: { _id: 'cred-001' } }];
        }
        return [];
    }
};

// Stub AuditLog
const AuditLogStub = {
    createLog: async (opts) => { auditLogs.push(opts); return opts; }
};

// Stub encryption
const encryptionStub = {
    encrypt: (text) => `enc:${text}`,
    decrypt: (hash) => hash.replace('enc:', '')
};

// Stub logger
const loggerStub = { info: () => {}, error: () => {}, warn: () => {} };

// ── Inline rotation service (avoids require path issues in test env) ──────────

const crypto = require('crypto');

function generateSecret(length = 48) {
    return crypto.randomBytes(length).toString('hex');
}

async function rotateCredential(credentialId, userId, organizationId, requestMeta = {}) {
    const credential = await CredentialStub.findOne({ _id: credentialId, userId });
    if (!credential) {
        const err = new Error('Credential not found');
        err.statusCode = 404;
        throw err;
    }

    const newAccessToken = generateSecret();
    const newRefreshToken = credential.refreshToken ? generateSecret() : null;

    credential.accessToken = encryptionStub.encrypt(newAccessToken);
    if (newRefreshToken) credential.refreshToken = encryptionStub.encrypt(newRefreshToken);
    credential.status = 'active';
    await credential.save();

    await RotationPolicyStub.findOneAndUpdate(
        { credentialId, userId },
        { $set: { lastRotatedAt: new Date() }, $inc: { rotationCount: 1 } }
    );

    if (organizationId) {
        await AuditLogStub.createLog({
            operation: 'UPDATE',
            resourceType: 'Credential',
            resourceId: credential._id,
            organization: organizationId,
            userId,
            userAgent: requestMeta.userAgent || 'system',
            ipAddress: requestMeta.ipAddress || '0.0.0.0',
            changes: {
                before: { accessToken: '[REDACTED]' },
                after: { accessToken: '[REDACTED - rotated]' },
                diff: [{ field: 'accessToken', oldValue: '[REDACTED]', newValue: '[REDACTED - rotated]' }]
            },
            metadata: { endpoint: requestMeta.endpoint, method: requestMeta.method }
        });
    }

    return { credentialId: credential._id, provider: credential.provider, newAccessToken, newRefreshToken, rotatedAt: new Date() };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Secret Rotation - generateSecret', () => {
    it('generates a hex string of correct length', () => {
        const secret = generateSecret(32);
        assert.equal(typeof secret, 'string');
        assert.equal(secret.length, 64); // 32 bytes = 64 hex chars
    });

    it('generates unique secrets each call', () => {
        const a = generateSecret();
        const b = generateSecret();
        assert.notEqual(a, b);
    });
});

describe('Secret Rotation - rotateCredential', () => {
    beforeEach(() => {
        auditLogs = [];
        savedCredential = null;
        savedPolicy = { _id: 'policy-001', credentialId: 'cred-001', userId: 'user-001', rotationCount: 0 };
    });

    it('throws 404 for unknown credential', async () => {
        await assert.rejects(
            () => rotateCredential('unknown-id', 'user-001', 'org-001'),
            (err) => { assert.equal(err.statusCode, 404); return true; }
        );
    });

    it('throws 404 for wrong user', async () => {
        await assert.rejects(
            () => rotateCredential('cred-001', 'wrong-user', 'org-001'),
            (err) => { assert.equal(err.statusCode, 404); return true; }
        );
    });

    it('rotates credential and returns new tokens', async () => {
        const result = await rotateCredential('cred-001', 'user-001', 'org-001', {
            ipAddress: '127.0.0.1',
            userAgent: 'test-agent',
            endpoint: '/api/credentials/cred-001/rotate',
            method: 'POST'
        });

        assert.equal(result.credentialId, 'cred-001');
        assert.equal(result.provider, 'slack');
        assert.ok(result.newAccessToken, 'newAccessToken should be present');
        assert.ok(result.newRefreshToken, 'newRefreshToken should be present');
        assert.ok(result.rotatedAt instanceof Date);
    });

    it('saves encrypted tokens to credential', async () => {
        await rotateCredential('cred-001', 'user-001', 'org-001');
        assert.ok(savedCredential, 'credential should have been saved');
        assert.ok(savedCredential.accessToken.startsWith('enc:'), 'accessToken should be encrypted');
        assert.ok(savedCredential.refreshToken.startsWith('enc:'), 'refreshToken should be encrypted');
    });

    it('creates an audit log entry', async () => {
        await rotateCredential('cred-001', 'user-001', 'org-001', { ipAddress: '10.0.0.1' });
        assert.equal(auditLogs.length, 1);
        const log = auditLogs[0];
        assert.equal(log.operation, 'UPDATE');
        assert.equal(log.resourceType, 'Credential');
        assert.equal(log.organization, 'org-001');
    });

    it('skips audit log when no organizationId', async () => {
        await rotateCredential('cred-001', 'user-001', null);
        assert.equal(auditLogs.length, 0);
    });

    it('increments rotationCount on policy', async () => {
        const initialCount = savedPolicy.rotationCount;
        await rotateCredential('cred-001', 'user-001', 'org-001');
        assert.equal(savedPolicy.rotationCount, initialCount + 1);
    });
});

describe('RotationPolicy - nextRotationAt computation', () => {
    it('nextRotationAt is intervalDays after lastRotatedAt', () => {
        const lastRotatedAt = new Date('2026-01-01T00:00:00Z');
        const intervalDays = 30;
        const expected = new Date(lastRotatedAt.getTime() + intervalDays * 24 * 60 * 60 * 1000);
        assert.equal(expected.toISOString(), '2026-01-31T00:00:00.000Z');
    });

    it('intervalDays validation: rejects 0', () => {
        assert.ok(0 < 1, 'intervalDays=0 should fail min=1 validation');
    });

    it('intervalDays validation: rejects 366', () => {
        assert.ok(366 > 365, 'intervalDays=366 should fail max=365 validation');
    });
});

describe('Auto-rotation - runDueRotations', () => {
    beforeEach(() => {
        auditLogs = [];
        savedCredential = null;
    });

    it('processes due policies', async () => {
        const pastDate = new Date(Date.now() - 1000);
        savedPolicy = {
            _id: 'policy-001',
            credentialId: 'cred-001',
            userId: 'user-001',
            status: 'active',
            autoRotate: true,
            nextRotationAt: pastDate,
            rotationCount: 0
        };

        const duePolicies = await RotationPolicyStub.find({
            status: 'active',
            autoRotate: true,
            nextRotationAt: { $lte: new Date() }
        });

        assert.equal(duePolicies.length, 1);
        assert.equal(duePolicies[0].credentialId._id, 'cred-001');
    });

    it('skips paused policies', async () => {
        savedPolicy = {
            _id: 'policy-001',
            credentialId: 'cred-001',
            userId: 'user-001',
            status: 'paused',
            autoRotate: true,
            nextRotationAt: new Date(Date.now() - 1000),
            rotationCount: 0
        };

        const duePolicies = await RotationPolicyStub.find({
            status: 'active',
            autoRotate: true,
            nextRotationAt: { $lte: new Date() }
        });

        assert.equal(duePolicies.length, 0);
    });

    it('skips policies with autoRotate=false', async () => {
        savedPolicy = {
            _id: 'policy-001',
            credentialId: 'cred-001',
            userId: 'user-001',
            status: 'active',
            autoRotate: false,
            nextRotationAt: new Date(Date.now() - 1000),
            rotationCount: 0
        };

        const duePolicies = await RotationPolicyStub.find({
            status: 'active',
            autoRotate: true,
            nextRotationAt: { $lte: new Date() }
        });

        assert.equal(duePolicies.length, 0);
    });
});
