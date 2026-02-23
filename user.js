// user.js
const express = require('express');
const pool = require('./db');

const app = express();

// 获取用户资料
async function getUserProfile(req, res) {
    const { username } = req.params;
    try {
        const { rows } = await pool.query('SELECT id, username FROM users WHERE username = $1', [username]);
        if (rows.length === 0) return res.status(404).json({ error: '用户不存在' });
        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: '获取用户资料失败' });
    }
}

app.get('/:username', getUserProfile);

module.exports = app;