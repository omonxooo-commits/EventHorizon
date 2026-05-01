const express = require('express');
const router = express.Router();
const rotationController = require('../controllers/rotation.controller');
const authMiddleware = require('../middleware/auth.middleware');
const permissionMiddleware = require('../middleware/permission.middleware');

// All routes require authentication
router.use(authMiddleware);

/**
 * @openapi
 * /api/credentials/{credentialId}/rotation-policy:
 *   get:
 *     summary: Get rotation policy for a credential
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credentialId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Rotation policy retrieved
 *       404:
 *         description: Policy not found
 */
router.get('/:credentialId/rotation-policy', rotationController.getPolicy);

/**
 * @openapi
 * /api/credentials/{credentialId}/rotation-policy:
 *   post:
 *     summary: Create rotation policy for a credential
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credentialId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [intervalDays]
 *             properties:
 *               intervalDays:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 365
 *                 example: 30
 *               autoRotate:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       201:
 *         description: Policy created
 *       409:
 *         description: Policy already exists
 */
router.post('/:credentialId/rotation-policy', rotationController.createPolicy);

/**
 * @openapi
 * /api/credentials/{credentialId}/rotation-policy:
 *   put:
 *     summary: Update rotation policy
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credentialId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               intervalDays:
 *                 type: integer
 *               autoRotate:
 *                 type: boolean
 *               status:
 *                 type: string
 *                 enum: [active, paused]
 *     responses:
 *       200:
 *         description: Policy updated
 */
router.put('/:credentialId/rotation-policy', rotationController.updatePolicy);

/**
 * @openapi
 * /api/credentials/{credentialId}/rotation-policy:
 *   delete:
 *     summary: Delete rotation policy
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credentialId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Policy deleted
 */
router.delete('/:credentialId/rotation-policy', rotationController.deletePolicy);

/**
 * @openapi
 * /api/credentials/{credentialId}/rotate:
 *   post:
 *     summary: Manually rotate credential secrets now
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: credentialId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Credential rotated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *                   properties:
 *                     credentialId:
 *                       type: string
 *                     provider:
 *                       type: string
 *                     newAccessToken:
 *                       type: string
 *                     newRefreshToken:
 *                       type: string
 *                     rotatedAt:
 *                       type: string
 *                       format: date-time
 */
router.post('/:credentialId/rotate', rotationController.rotateNow);

/**
 * @openapi
 * /api/credentials/rotate/run-due:
 *   post:
 *     summary: Trigger auto-rotation for all due credentials (admin)
 *     tags: [Credentials, Rotation]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Due rotations processed
 */
router.post('/rotate/run-due', permissionMiddleware('manage_credentials'), rotationController.runDue);

module.exports = router;
