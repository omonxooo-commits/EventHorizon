const mongoose = require('mongoose');

const rotationPolicySchema = new mongoose.Schema({
    credentialId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Credential',
        required: true,
        index: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    intervalDays: {
        type: Number,
        required: true,
        min: 1,
        max: 365
    },
    autoRotate: {
        type: Boolean,
        default: false
    },
    lastRotatedAt: {
        type: Date,
        default: null
    },
    nextRotationAt: {
        type: Date,
        index: true
    },
    rotationCount: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['active', 'paused'],
        default: 'active'
    }
}, { timestamps: true });

// Compute nextRotationAt before save
rotationPolicySchema.pre('save', function(next) {
    if (this.isModified('intervalDays') || this.isModified('lastRotatedAt') || this.isNew) {
        const base = this.lastRotatedAt || this.createdAt || new Date();
        this.nextRotationAt = new Date(base.getTime() + this.intervalDays * 24 * 60 * 60 * 1000);
    }
    next();
});

module.exports = mongoose.model('RotationPolicy', rotationPolicySchema);
