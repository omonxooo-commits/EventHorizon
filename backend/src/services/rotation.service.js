const crypto = require('crypto');
const Credential = require('../models/credential.model');
const RotationPolicy = require('../models/rotationPolicy.model');
const AuditLog = require('../models/audit.model');
const { encrypt } = require('../utils/encryption');
const logger = require('../config/logger');

/**
 * Generate a cryptographically secure random secret.
 */
function generateSecret(length = 48) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Rotate the accessToken (and optionally refreshToken) for a credential.
 * Returns the new plain-text tokens so the caller can relay them to the user.
 */
async function rotateCredential(credentialId, userId, organizationId, requestMeta = {}) {
    const credential = await Credential.findOne({ _id: credentialId, userId });
    if (!credential) {
        const err = new Error('Credential not found');
        err.statusCode = 404;
        throw err;
    }

    const newAccessToken = generateSecret();
    const newRefreshToken = credential.refreshToken ? generateSecret() : null;

    const before = {
        accessToken: '[REDACTED]',
        refreshToken: credential.refreshToken ? '[REDACTED]' : null,
        status: credential.status
    };

    credential.accessToken = encrypt(newAccessToken);
    if (newRefreshToken) credential.refreshToken = encrypt(newRefreshToken);
    credential.status = 'active';
    await credential.save();

    // Update rotation policy stats
    await RotationPolicy.findOneAndUpdate(
        { credentialId, userId },
        {
            $set: { lastRotatedAt: new Date() },
            $inc: { rotationCount: 1 }
        }
    );

    // Audit log
    await _auditRotation(credential, before, organizationId, userId, requestMeta);

    logger.info('Credential rotated', { credentialId, userId });

    return {
        credentialId: credential._id,
        provider: credential.provider,
        newAccessToken,
        newRefreshToken,
        rotatedAt: new Date()
    };
}

/**
 * Run auto-rotation for all due policies.
 * Called by a scheduler or manual trigger.
 */
async function runDueRotations() {
    const now = new Date();
    const duePolicies = await RotationPolicy.find({
        status: 'active',
        autoRotate: true,
        nextRotationAt: { $lte: now }
    }).populate('credentialId');

    const results = [];
    for (const policy of duePolicies) {
        try {
            const result = await rotateCredential(
                policy.credentialId._id,
                policy.userId,
                null, // no org context in background job
                { endpoint: 'auto-rotation', method: 'SYSTEM' }
            );
            results.push({ success: true, credentialId: policy.credentialId._id, ...result });
        } catch (err) {
            logger.error('Auto-rotation failed', { policyId: policy._id, error: err.message });
            results.push({ success: false, credentialId: policy.credentialId._id, error: err.message });
        }
    }

    return results;
}

async function _auditRotation(credential, before, organizationId, userId, requestMeta) {
    try {
        if (!organizationId) return; // skip audit in background jobs without org context
        await AuditLog.createLog({
            operation: 'UPDATE',
            resourceType: 'Credential',
            resourceId: credential._id,
            organization: organizationId,
            userId,
            userAgent: requestMeta.userAgent || 'system',
            ipAddress: requestMeta.ipAddress || '0.0.0.0',
            forwardedFor: requestMeta.forwardedFor,
            changes: {
                before,
                after: { accessToken: '[REDACTED]', refreshToken: '[REDACTED]', status: credential.status },
                diff: [{ field: 'accessToken', oldValue: '[REDACTED]', newValue: '[REDACTED - rotated]' }]
            },
            metadata: {
                endpoint: requestMeta.endpoint || '/api/credentials/rotate',
                method: requestMeta.method || 'POST',
                userAgent: requestMeta.userAgent,
                requestId: requestMeta.requestId
            }
        });
    } catch (err) {
        logger.error('Failed to write rotation audit log', { error: err.message });
    }
}

module.exports = { rotateCredential, runDueRotations, generateSecret };
