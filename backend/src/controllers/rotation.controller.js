const RotationPolicy = require('../models/rotationPolicy.model');
const Credential = require('../models/credential.model');
const { rotateCredential, runDueRotations } = require('../services/rotation.service');
const asyncHandler = require('../utils/asyncHandler');
const AppError = require('../utils/appError');

/**
 * GET /api/credentials/:credentialId/rotation-policy
 */
exports.getPolicy = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    await _assertOwnership(credentialId, req.user.id);

    const policy = await RotationPolicy.findOne({ credentialId, userId: req.user.id });
    if (!policy) throw new AppError('No rotation policy found for this credential', 404);

    res.json({ success: true, data: policy });
});

/**
 * POST /api/credentials/:credentialId/rotation-policy
 */
exports.createPolicy = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    await _assertOwnership(credentialId, req.user.id);

    const existing = await RotationPolicy.findOne({ credentialId, userId: req.user.id });
    if (existing) throw new AppError('Rotation policy already exists. Use PUT to update.', 409);

    const { intervalDays, autoRotate } = req.body;
    if (!intervalDays || intervalDays < 1 || intervalDays > 365) {
        throw new AppError('intervalDays must be between 1 and 365', 400);
    }

    const policy = await RotationPolicy.create({
        credentialId,
        userId: req.user.id,
        intervalDays,
        autoRotate: !!autoRotate
    });

    res.status(201).json({ success: true, data: policy });
});

/**
 * PUT /api/credentials/:credentialId/rotation-policy
 */
exports.updatePolicy = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    await _assertOwnership(credentialId, req.user.id);

    const { intervalDays, autoRotate, status } = req.body;
    const update = {};
    if (intervalDays !== undefined) {
        if (intervalDays < 1 || intervalDays > 365) throw new AppError('intervalDays must be between 1 and 365', 400);
        update.intervalDays = intervalDays;
    }
    if (autoRotate !== undefined) update.autoRotate = autoRotate;
    if (status !== undefined) {
        if (!['active', 'paused'].includes(status)) throw new AppError('status must be active or paused', 400);
        update.status = status;
    }

    const policy = await RotationPolicy.findOneAndUpdate(
        { credentialId, userId: req.user.id },
        { $set: update },
        { new: true, runValidators: true }
    );
    if (!policy) throw new AppError('Rotation policy not found', 404);

    res.json({ success: true, data: policy });
});

/**
 * DELETE /api/credentials/:credentialId/rotation-policy
 */
exports.deletePolicy = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    await _assertOwnership(credentialId, req.user.id);

    const policy = await RotationPolicy.findOneAndDelete({ credentialId, userId: req.user.id });
    if (!policy) throw new AppError('Rotation policy not found', 404);

    res.json({ success: true, message: 'Rotation policy deleted' });
});

/**
 * POST /api/credentials/:credentialId/rotate
 */
exports.rotateNow = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    await _assertOwnership(credentialId, req.user.id);

    const result = await rotateCredential(
        credentialId,
        req.user.id,
        req.user.organization._id,
        {
            ipAddress: req.ip || req.connection.remoteAddress,
            forwardedFor: req.get('X-Forwarded-For'),
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            method: req.method,
            requestId: req.id
        }
    );

    res.json({ success: true, data: result });
});

/**
 * POST /api/credentials/rotate/run-due  (admin)
 */
exports.runDue = asyncHandler(async (req, res) => {
    const results = await runDueRotations();
    res.json({ success: true, data: { processed: results.length, results } });
});

async function _assertOwnership(credentialId, userId) {
    const cred = await Credential.findOne({ _id: credentialId, userId });
    if (!cred) throw new AppError('Credential not found', 404);
}
