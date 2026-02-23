const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');
const multer = require('multer');

const app = express();

if (!process.env.UPLOAD_DIR) {
    console.error('Missing env: UPLOAD_DIR');
    process.exit(1);
}

const uploadDir = process.env.UPLOAD_DIR;

(async () => {
    try {
        await fs.access(uploadDir);
    } catch {
        await fs.mkdir(uploadDir, { recursive: true, mode: 0o750 });
    }
})();

function generateRandomString(bytes = 6) {
    return crypto.randomBytes(bytes).toString('hex');
}

function sanitizeFilename(name) {
    return name
        .replace(/[/\\?%*:|"<>]/g, '_')
        .replace(/\s+/g, '_')
        .replace(/_{2,}/g, '_')
        .trim()
        .substring(0, 200);
}

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
            const ext = path.extname(file.originalname).toLowerCase();
            let tempName;
            
            if (['.apk', '.zip'].includes(ext)) {
                const baseName = path.basename(file.originalname, ext);
                const cleanBase = sanitizeFilename(baseName);
                tempName = `${cleanBase}${ext}`;
            } else {
                const timestamp = Math.floor(Date.now() / 1000);
                const randomStr = generateRandomString(6);
                tempName = `${timestamp}_${randomStr}${ext}`;
            }
            
            cb(null, tempName);
        }
    }),
    limits: {
        fileSize: 5 * 1024 * 1024,
    },
    fileFilter: (req, file, cb) => {
        const allowedExts = ['.jpg', '.png', '.gif', '.webp', '.apk', '.zip', '.sh'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('仅支持 JPG/PNG/GIF/WebP/APK/ZIP/Shell 脚本文件'));
        }
    },
});

app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: '我要的文件在哪里' });
    }

    const url = `${req.protocol}://${req.get('host')}/api/files/${encodeURIComponent(req.file.filename)}`;
    res.json({ url });
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: '文件大小超过限制（最大 300MB）' });
        }
        return res.status(400).json({ error: '文件上传错误' });
    }
    next(err);
});

module.exports = app;