const express = require('express');
const axios = require('axios');
const fs = require('fs').promises;
const path = require('path');
const { URL } = require('url');
const { HttpsProxyAgent } = require('https-proxy-agent');
const crypto = require('crypto');

// -----------------------
// Configuration
// -----------------------
const PROXY = "http://e69fabed73e045cc4132__cr.fr:1fd1088d784f5dcc@gw.dataimpulse.com:823"; // or null
const LOGIN_TIMEOUT = 6000;
const RESOLVE_TIMEOUT = 12000;
const JOIN_TIMEOUT = 15000;
const ACCOUNTS_FILE = "akun.txt";
const ALLOWED_DOMAIN = "capcut.team";

const app = express();
app.use(express.json());

// Trust proxy untuk mendapatkan IP yang benar
app.set('trust proxy', true);

// CORS middleware - hanya dari IP yang sama
app.use((req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const serverIP = req.connection.localAddress || '127.0.0.1';
    
    // Allow localhost dan IP yang sama
    if (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP === '::ffff:127.0.0.1' || 
        clientIP === serverIP || clientIP.includes('127.0.0.1') || clientIP.includes('localhost')) {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
    
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// UA fallback
const LOCAL_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
];

// -----------------------
// IP Restriction Middleware - hanya dari IP yang sama
// -----------------------
function checkIP(req, res, next) {
    const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress || '';
    const serverIP = req.connection.localAddress || '127.0.0.1';
    
    // Normalize IP addresses
    const normalizeIP = (ip) => {
        if (!ip) return '';
        // Handle IPv6-mapped IPv4
        if (ip.startsWith('::ffff:')) {
            return ip.replace('::ffff:', '');
        }
        return ip;
    };
    
    const normalizedClientIP = normalizeIP(clientIP);
    const normalizedServerIP = normalizeIP(serverIP);
    
    // Allow localhost, same IP, atau IP yang sama dengan server
    if (normalizedClientIP === '127.0.0.1' || 
        normalizedClientIP === '::1' || 
        normalizedClientIP === normalizedServerIP ||
        normalizedClientIP.includes('127.0.0.1') ||
        normalizedClientIP.includes('localhost') ||
        clientIP === serverIP) {
        next();
    } else {
        res.status(403).json({ 
            error: 'Access denied', 
            message: `Only requests from the same IP are allowed. Your IP: ${normalizedClientIP}, Server IP: ${normalizedServerIP}` 
        });
    }
}

// -----------------------
// Utils
// -----------------------
function generateVerifyToken() {
    const structure = [8, 8, 4, 4, 4, 12];
    const result = [];
    for (let i = 0; i < structure.length; i++) {
        const length = structure[i];
        const pool = i === structure.length - 1 
            ? 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            : 'abcdefghijklmnopqrstuvwxyz0123456789';
        let segment = '';
        for (let j = 0; j < length; j++) {
            segment += pool[Math.floor(Math.random() * pool.length)];
        }
        result.push(segment);
    }
    return "verify_" + result.join("_");
}

function xorEncrypt(text, key = 5) {
    let result = '';
    for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(text.charCodeAt(i) ^ key);
    }
    return Buffer.from(result, 'utf8').toString('hex');
}

function pickUA() {
    return LOCAL_UA[Math.floor(Math.random() * LOCAL_UA.length)];
}

function sanitizeSlugForFilename(link, maxLen = 80) {
    try {
        const parsed = new URL(link);
        let path = parsed.pathname.replace(/^\/|\/$/g, '');
        let candidate = path ? path.replace(/\//g, '_') : (parsed.hostname + '_' + (parsed.search || parsed.hash));
        let slug = candidate.replace(/[^0-9A-Za-z._-]+/g, '_');
        return slug.substring(0, maxLen).replace(/^_+|_+$/g, '') || "link";
    } catch (e) {
        return "link";
    }
}

// -----------------------
// HTTP Client Builder
// -----------------------
function createAxiosInstance(proxy = null) {
    const config = {
        timeout: 10000,
        headers: {
            'Connection': 'keep-alive',
            'Accept': '*/*'
        },
        maxRedirects: 0,
        validateStatus: (status) => status < 400
    };
    
    if (proxy) {
        config.httpsAgent = new HttpsProxyAgent(proxy);
        config.httpAgent = new HttpsProxyAgent(proxy);
    }
    
    return axios.create(config);
}

// -----------------------
// Resolve short link
// -----------------------
async function resolveShortLink(shortLink, timeout = RESOLVE_TIMEOUT) {
    const client = createAxiosInstance(PROXY);
    try {
        const response = await client.get(shortLink, {
            timeout: timeout,
            headers: { 'User-Agent': pickUA() },
            maxRedirects: 0,
            validateStatus: (status) => status >= 200 && status < 400
        });
        
        if (response.status >= 300 && response.status < 400 && response.headers.location) {
            return response.headers.location.replace(/&amp;/g, '&');
        }
        
        if (response.data && typeof response.data === 'string') {
            const match = response.data.match(/href="([^"]+)"/i);
            if (match) {
                return match[1].replace(/&amp;/g, '&');
            }
        }
        
        throw new Error("No redirect location found");
    } catch (error) {
        if (error.response && error.response.status >= 300 && error.response.status < 400) {
            const location = error.response.headers.location;
            if (location) {
                return location.replace(/&amp;/g, '&');
            }
        }
        throw new Error(`resolve error: ${error.message}`);
    }
}

// -----------------------
// Login
// -----------------------
async function fastLogin(email, password) {
    const url = "https://www.capcut.com/passport/web/email/login/";
    const params = {
        aid: "513641",
        account_sdk_source: "web",
        passport_jssdk_version: "1.0.7-beta.2",
        language: "en",
        verifyFp: generateVerifyToken()
    };
    
    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "origin": "https://dreamina.capcut.com",
        "referer": "https://dreamina.capcut.com/ai-tool/login?redirectUrl=%2Fhome",
        "user-agent": pickUA()
    };
    
    const data = new URLSearchParams({
        mix_mode: "1",
        email: xorEncrypt(email),
        password: xorEncrypt(password),
        fixed_mix_mode: "1"
    }).toString();
    
    const client = createAxiosInstance(PROXY);
    
    try {
        const response = await client.post(url, data, {
            params: params,
            headers: headers,
            timeout: LOGIN_TIMEOUT,
            maxRedirects: 0
        });
        
        if (response.status === 200) {
            const cookies = response.headers['set-cookie'] || [];
            let sessionid = null;
            
            for (const cookie of cookies) {
                const match = cookie.match(/sessionid=([^;]+)/);
                if (match) {
                    sessionid = match[1];
                    break;
                }
            }
            
            if (sessionid) {
                return { success: true, sessionid: sessionid, message: "OK" };
            }
            return { success: false, sessionid: null, message: "No sessionid cookie" };
        }
        return { success: false, sessionid: null, message: `HTTP ${response.status}` };
    } catch (error) {
        if (error.code === 'ECONNABORTED') {
            return { success: false, sessionid: null, message: "Timeout" };
        }
        return { success: false, sessionid: null, message: `RequestError: ${error.message}` };
    }
}

// -----------------------
// Join workspace
// -----------------------
async function joinWorkspaceWithInvite(cookieSessionid, resolvedInviteLink, maxRetries = 3) {
    const url = "https://edit-api-sg.capcut.com/cc/v1/workspace/join_workspace_with_apply";
    const headers = {
        "device-time": "1759683090",
        "sign-ver": "1",
        "appvr": "5.8.0",
        "sign": "d15774df3cc33528b8e1422fdc7dbc5b",
        "lan": "en",
        "pf": "7",
        "user-agent": pickUA(),
        "cookie": `sessionid=${cookieSessionid}`
    };
    
    const data = {
        join_workspace_type: 1,
        invite_link_param: { invitation_link: resolvedInviteLink },
        application_param: {}
    };
    
    const client = createAxiosInstance(PROXY);
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await client.post(url, data, {
                headers: headers,
                timeout: JOIN_TIMEOUT
            });
            
            const d = response.data || {};
            
            if (d.ret === "0" || (d.errmsg && d.errmsg.toLowerCase().includes("success"))) {
                return { status: "success", data: d };
            }
            if (d.ret === "2311" || (d.errmsg && d.errmsg.includes("ERR_REPEAT_ADD_WORKSPACE"))) {
                return { status: "already", data: d };
            }
            if (d.ret === "2308" || (d.errmsg && d.errmsg.includes("ERR_MEMBER_CNT_LIMIT"))) {
                return { status: "member_full", data: d };
            }
            if (d.ret === "2323" || (d.errmsg && d.errmsg.includes("ERR_WORKSPACE_INVITATION_LINK_FORMAT_IS_NOT_CORRECT"))) {
                return { status: "invalid_link", data: d };
            }
            if (d.ret === "1014" || (d.errmsg && d.errmsg.toLowerCase().includes("system busy"))) {
                if (attempt < maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, attempt * 1000));
                    continue;
                }
                return { status: "busy", data: d };
            }
            return { status: "failed", data: d };
        } catch (error) {
            if (attempt < maxRetries) {
                await new Promise(resolve => setTimeout(resolve, attempt * 1000));
                continue;
            }
            return { status: "error", error: error.message };
        }
    }
    return { status: "error", error: "Max retries reached" };
}

// -----------------------
// File ops
// -----------------------
async function readAccounts(filename) {
    try {
        const content = await fs.readFile(filename, 'utf8');
        const accounts = [];
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.includes('|')) {
                const [email, ...pwdParts] = line.trim().split('|');
                const pwd = pwdParts.join('|');
                if (email && pwd) {
                    accounts.push([email.trim(), pwd.trim()]);
                }
            }
        }
        return accounts;
    } catch (error) {
        return [];
    }
}

async function removeAccountFromFile(email, pwd) {
    const target = `${email}|${pwd}`;
    try {
        const content = await fs.readFile(ACCOUNTS_FILE, 'utf8');
        const lines = content.split('\n').filter(line => line.trim() !== target);
        await fs.writeFile(ACCOUNTS_FILE, lines.join('\n') + (lines.length > 0 ? '\n' : ''), 'utf8');
    } catch (error) {
        // File doesn't exist or error, ignore
    }
}

async function appendToResultFileForLink(link, email, pwd) {
    const slug = sanitizeSlugForFilename(link);
    const fname = `result_${slug}.txt`;
    try {
        await fs.appendFile(fname, `${email}|${pwd}\n`, 'utf8');
    } catch (error) {
        // Ignore errors
    }
}

// -----------------------
// Stats Tracker
// -----------------------
class StatsTracker {
    constructor() {
        this.success = 0;
        this.failed = 0;
        this.already_member = 0;
        this.lock = false;
    }
    
    async addSuccess() {
        while (this.lock) await new Promise(resolve => setTimeout(resolve, 1));
        this.lock = true;
        this.success++;
        this.lock = false;
    }
    
    async addFailed() {
        while (this.lock) await new Promise(resolve => setTimeout(resolve, 1));
        this.lock = true;
        this.failed++;
        this.lock = false;
    }
    
    async addAlready() {
        while (this.lock) await new Promise(resolve => setTimeout(resolve, 1));
        this.lock = true;
        this.already_member++;
        this.lock = false;
    }
    
    getStats() {
        return {
            success: this.success,
            failed: this.failed,
            already_member: this.already_member
        };
    }
}

// -----------------------
// Worker
// -----------------------
async function processAccount(account, link, stats, stopFlag) {
    if (stopFlag.value) {
        return;
    }
    
    const [email, pwd] = account;
    const displayEmail = email.length > 20 ? email.substring(0, 20) + "..." : email;
    
    try {
        const loginResult = await fastLogin(email, pwd);
        
        if (!loginResult.success) {
            await removeAccountFromFile(email, pwd);
            await stats.addFailed();
            return { email: displayEmail, status: 'login_failed', message: loginResult.message };
        }
        
        const resolved = await resolveShortLink(link);
        const res = await joinWorkspaceWithInvite(loginResult.sessionid, resolved);
        const status = res.status;
        
        if (status === "success") {
            await appendToResultFileForLink(link, email, pwd);
            await removeAccountFromFile(email, pwd);
            await stats.addSuccess();
            return { email: displayEmail, status: 'success', message: 'Successfully Joined!' };
        } else if (status === "already") {
            await removeAccountFromFile(email, pwd);
            await stats.addAlready();
            return { email: displayEmail, status: 'already', message: 'Already Member' };
        } else if (status === "member_full") {
            stopFlag.value = true;
            return { email: displayEmail, status: 'member_full', message: 'Workspace Full!' };
        } else {
            await removeAccountFromFile(email, pwd);
            await stats.addFailed();
            return { email: displayEmail, status: 'failed', message: status };
        }
    } catch (error) {
        await stats.addFailed();
        return { email: displayEmail, status: 'error', message: error.message.substring(0, 30) };
    }
}

// -----------------------
// Process accounts in batches
// -----------------------
async function processAccountsInBatches(accounts, link, workers) {
    const stats = new StatsTracker();
    const stopFlag = { value: false };
    const results = [];
    
    for (let i = 0; i < accounts.length; i += workers) {
        if (stopFlag.value) break;
        
        const batch = accounts.slice(i, i + workers);
        const promises = batch.map(account => processAccount(account, link, stats, stopFlag));
        const batchResults = await Promise.all(promises);
        results.push(...batchResults);
        
        if (stopFlag.value) break;
    }
    
    return { results, stats: stats.getStats() };
}

// -----------------------
// API Endpoint
// -----------------------
app.post('/api/join', checkIP, async (req, res) => {
    try {
        const { link, accounts, workers = 5 } = req.body;
        
        if (!link) {
            return res.status(400).json({ error: 'Link is required' });
        }
        
        if (!accounts || !Array.isArray(accounts) || accounts.length === 0) {
            return res.status(400).json({ error: 'Accounts array is required and must not be empty' });
        }
        
        // Validate account format: should be array of [email, password] or {email, password}
        const normalizedAccounts = accounts.map(acc => {
            if (Array.isArray(acc) && acc.length >= 2) {
                return [acc[0].trim(), acc[1].trim()];
            } else if (typeof acc === 'object' && acc.email && acc.password) {
                return [acc.email.trim(), acc.password.trim()];
            } else if (typeof acc === 'string' && acc.includes('|')) {
                const [email, ...pwdParts] = acc.split('|');
                return [email.trim(), pwdParts.join('|').trim()];
            }
            return null;
        }).filter(acc => acc !== null && acc[0] && acc[1]);
        
        if (normalizedAccounts.length === 0) {
            return res.status(400).json({ error: 'No valid accounts found. Format: [["email", "password"], ...] or [{"email": "...", "password": "..."}, ...]' });
        }
        
        const startTime = Date.now();
        const { results, stats } = await processAccountsInBatches(normalizedAccounts, link, parseInt(workers) || 5);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);
        
        res.json({
            success: true,
            summary: {
                total_accounts: normalizedAccounts.length,
                successfully_joined: stats.success,
                already_member: stats.already_member,
                failed: stats.failed,
                time_elapsed: `${elapsed}s`
            },
            results: results
        });
    } catch (error) {
        res.status(500).json({ 
            error: 'Internal server error', 
            message: error.message 
        });
    }
});

// Health check endpoint (no domain restriction)
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Allowed domain: ${ALLOWED_DOMAIN}`);
});

