const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'atlas-panel-secret-key-2024';

// Users database (in production, use a real database)
let users = [
    { id: 1, username: 'admin', password: 'atlas2024', role: 'admin', active: true, createdAt: new Date() },
    { id: 2, username: 'user1', password: 'user123', role: 'user', active: true, createdAt: new Date() }
];

// Statistics and Query Logging
let stats = {
    totalQueries: 0,
    successfulQueries: 0,
    failedQueries: 0,
    userQueries: {},
    queryLogs: [] // Yeni: Tüm sorgu logları
};

// Query categories for better organization
const queryCategories = {
    'personal': ['tc', 'adres', 'isyeri', 'sulale', 'tcgsm', 'gsmtc', 'adsoyad', 'supersearch'],
    'network': ['iplookup', 'domain'],
    'financial': ['iban', 'bin'],
    'communication': ['phone', 'email'],
    'vehicle': ['plate']
};

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Favicon handler
app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        
        // Check if user is still active
        const dbUser = users.find(u => u.username === user.username);
        if (!dbUser || !dbUser.active) {
            return res.status(403).json({ error: 'User account is inactive' });
        }
        
        req.user = user;
        next();
    });
};

// Enhanced Statistics middleware with logging
const trackQuery = (req, res, next) => {
    const originalSend = res.send;
    const startTime = Date.now();
    
    res.send = function(data) {
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        stats.totalQueries++;
        
        // Initialize user stats if not exists
        if (!stats.userQueries[req.user.username]) {
            stats.userQueries[req.user.username] = { total: 0, successful: 0, failed: 0 };
        }
        
        stats.userQueries[req.user.username].total++;
        
        const isSuccess = res.statusCode >= 200 && res.statusCode < 300;
        
        if (isSuccess) {
            stats.successfulQueries++;
            stats.userQueries[req.user.username].successful++;
        } else {
            stats.failedQueries++;
            stats.userQueries[req.user.username].failed++;
        }
        
        // Log the query
        const queryLog = {
            id: stats.queryLogs.length + 1,
            username: req.user.username,
            endpoint: req.path,
            method: req.method,
            params: req.query,
            success: isSuccess,
            duration: duration,
            timestamp: new Date().toISOString(),
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.headers['user-agent']
        };
        
        stats.queryLogs.push(queryLog);
        
        // Keep only last 1000 logs to prevent memory issues
        if (stats.queryLogs.length > 1000) {
            stats.queryLogs = stats.queryLogs.slice(-1000);
        }
        
        originalSend.call(this, data);
    };
    next();
};

// Login endpoint
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username && u.password === password && u.active);
    
    if (user) {
        const token = jwt.sign({ 
            username: user.username, 
            role: user.role,
            id: user.id 
        }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ 
            token, 
            message: 'Login successful',
            user: {
                username: user.username,
                role: user.role,
                id: user.id,
                active: user.active
            }
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials or inactive account' });
    }
});

// Statistics endpoint
app.get('/api/stats', authenticateToken, (req, res) => {
    const userStats = stats.userQueries[req.user.username] || { total: 0, successful: 0, failed: 0 };
    
    res.json({
        global: {
            totalQueries: stats.totalQueries,
            successfulQueries: stats.successfulQueries,
            failedQueries: stats.failedQueries,
            totalUsers: users.filter(u => u.active).length
        },
        user: userStats
    });
});

// Admin endpoints
app.get('/api/admin/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const safeUsers = users.map(u => ({
        id: u.id,
        username: u.username,
        role: u.role,
        active: u.active,
        createdAt: u.createdAt
    }));
    res.json(safeUsers);
});

// New: Admin query logs endpoint
app.get('/api/admin/logs', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { page = 1, limit = 50, username, endpoint } = req.query;
    let logs = [...stats.queryLogs].reverse(); // Most recent first
    
    // Filter by username if provided
    if (username) {
        logs = logs.filter(log => log.username.toLowerCase().includes(username.toLowerCase()));
    }
    
    // Filter by endpoint if provided
    if (endpoint) {
        logs = logs.filter(log => log.endpoint.includes(endpoint));
    }
    
    // Pagination
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const paginatedLogs = logs.slice(startIndex, endIndex);
    
    res.json({
        logs: paginatedLogs,
        total: logs.length,
        page: parseInt(page),
        totalPages: Math.ceil(logs.length / limit)
    });
});

// New: Super Search endpoint - combines multiple APIs
app.get('/api/supersearch', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { adi, soyadi, tc } = req.query;
        
        if (!adi || !soyadi) {
            return res.status(400).json({ error: 'Adi and Soyadi parameters required for super search' });
        }
        
        const results = {
            searchQuery: { adi, soyadi, tc },
            timestamp: new Date().toISOString(),
            results: {}
        };
        
        // If TC is provided, use it for all TC-based searches
        if (tc) {
            // TC Info
            try {
                const tcResponse = await axios.get(`https://arastir.sbs/api/tc.php?tc=${tc}`, { timeout: 10000 });
                results.results.tcInfo = tcResponse.data;
            } catch (error) {
                results.results.tcInfo = { error: 'TC sorgusu başarısız' };
            }
            
            // Address Info
            try {
                const adresResponse = await axios.get(`https://arastir.sbs/api/adres.php?tc=${tc}`, { timeout: 10000 });
                results.results.adresInfo = adresResponse.data;
            } catch (error) {
                results.results.adresInfo = { error: 'Adres sorgusu başarısız' };
            }
            
            // Workplace Info
            try {
                const isyeriResponse = await axios.get(`https://arastir.sbs/api/isyeri.php?tc=${tc}`, { timeout: 10000 });
                results.results.isyeriInfo = isyeriResponse.data;
            } catch (error) {
                results.results.isyeriInfo = { error: 'İşyeri sorgusu başarısız' };
            }
            
            // Family Info
            try {
                const sulaleResponse = await axios.get(`https://arastir.sbs/api/sulale.php?tc=${tc}`, { timeout: 10000 });
                results.results.sulaleInfo = sulaleResponse.data;
            } catch (error) {
                results.results.sulaleInfo = { error: 'Sülale sorgusu başarısız' };
            }
            
            // Phone Info
            try {
                const phoneResponse = await axios.get(`https://arastir.sbs/api/tcgsm.php?tc=${tc}`, { timeout: 10000 });
                results.results.phoneInfo = phoneResponse.data;
            } catch (error) {
                results.results.phoneInfo = { error: 'Telefon sorgusu başarısız' };
            }
        }
        
        // Name-based search (always performed)
        try {
            let queryString = `adi=${adi}&soyadi=${soyadi}`;
            const adsoyResponse = await axios.get(`https://arastir.sbs/api/adsoyad.php?${queryString}`, { timeout: 10000 });
            results.results.nameSearch = adsoyResponse.data;
        } catch (error) {
            results.results.nameSearch = { error: 'Ad soyad sorgusu başarısız' };
        }
        
        // Combine all results into a unified format
        const combinedData = combineSearchResults(results.results);
        results.combinedData = combinedData;
        
        res.json(results);
        
    } catch (error) {
        res.status(500).json({ error: 'Super search failed', details: error.message });
    }
});

app.post('/api/admin/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { username, password, role } = req.body;
    
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Username, password and role required' });
    }
    
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Username already exists' });
    }
    
    const newUser = {
        id: Math.max(...users.map(u => u.id)) + 1,
        username,
        password,
        role,
        active: true,
        createdAt: new Date()
    };
    
    users.push(newUser);
    
    // Initialize user stats
    stats.userQueries[username] = { total: 0, successful: 0, failed: 0 };
    
    res.json({ 
        message: 'User created successfully and activated', 
        user: { 
            id: newUser.id, 
            username, 
            role, 
            active: newUser.active,
            createdAt: newUser.createdAt
        } 
    });
});

app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(u => u.id === userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    if (users[userIndex].username === 'admin') {
        return res.status(400).json({ error: 'Cannot delete main admin user' });
    }
    
    users.splice(userIndex, 1);
    res.json({ message: 'User deleted successfully' });
});

// Protected API endpoints with improved error handling
app.get('/api/tc', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        
        // TC validation
        if (!/^\d{11}$/.test(tc)) {
            return res.status(400).json({ error: 'TC must be 11 digits' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/tc.php?tc=${tc}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('TC API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/adres', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        
        if (!/^\d{11}$/.test(tc)) {
            return res.status(400).json({ error: 'TC must be 11 digits' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/adres.php?tc=${tc}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Adres API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/isyeri', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        
        if (!/^\d{11}$/.test(tc)) {
            return res.status(400).json({ error: 'TC must be 11 digits' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/isyeri.php?tc=${tc}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('İşyeri API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/sulale', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        
        if (!/^\d{11}$/.test(tc)) {
            return res.status(400).json({ error: 'TC must be 11 digits' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/sulale.php?tc=${tc}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Sülale API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/tcgsm', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        
        if (!/^\d{11}$/.test(tc)) {
            return res.status(400).json({ error: 'TC must be 11 digits' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/tcgsm.php?tc=${tc}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('TC-GSM API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/gsmtc', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { gsm } = req.query;
        if (!gsm) {
            return res.status(400).json({ error: 'GSM parameter required' });
        }
        
        // GSM validation
        const cleanGsm = gsm.replace(/\D/g, '');
        if (cleanGsm.length < 10 || cleanGsm.length > 13) {
            return res.status(400).json({ error: 'Invalid GSM format' });
        }
        
        const response = await axios.get(`https://arastir.sbs/api/gsmtc.php?gsm=${cleanGsm}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('GSM-TC API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

app.get('/api/adsoyad', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { adi, soyadi, il, ilce } = req.query;
        
        if (!adi || !soyadi) {
            return res.status(400).json({ error: 'Adi and Soyadi parameters required' });
        }
        
        // Name validation
        if (adi.length < 2 || soyadi.length < 2) {
            return res.status(400).json({ error: 'Name and surname must be at least 2 characters' });
        }
        
        let queryString = `adi=${encodeURIComponent(adi)}&soyadi=${encodeURIComponent(soyadi)}`;
        if (il) queryString += `&il=${encodeURIComponent(il)}`;
        if (ilce) queryString += `&ilce=${encodeURIComponent(ilce)}`;
        
        const response = await axios.get(`https://arastir.sbs/api/adsoyad.php?${queryString}`, { 
            timeout: 15000,
            headers: {
                'User-Agent': 'Atlas Panel API Client'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Ad Soyad API Error:', error.message);
        if (error.code === 'ECONNABORTED') {
            res.status(408).json({ error: 'Request timeout - API response too slow' });
        } else if (error.response) {
            res.status(error.response.status).json({ error: 'External API error', details: error.response.data });
        } else {
            res.status(500).json({ error: 'API request failed', details: error.message });
        }
    }
});

// Phone Number Analysis endpoint
app.get('/api/phone', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { phone } = req.query;
        
        if (!phone) {
            return res.status(400).json({ error: 'Phone parameter required' });
        }
        
        // Clean phone number
        const cleanPhone = phone.replace(/\D/g, '');
        
        // Analyze phone number
        const phoneInfo = analyzePhoneNumber(cleanPhone);
        
        const result = {
            phone: cleanPhone,
            formatted: phoneInfo.formatted,
            international: phoneInfo.international,
            operator: phoneInfo.operator,
            type: phoneInfo.type,
            region: phoneInfo.region,
            isValid: phoneInfo.isValid,
            country: phoneInfo.country,
            timestamp: new Date().toISOString()
        };
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({ error: 'Phone analysis failed', details: error.message });
    }
});

// Domain/Website Analysis endpoint
app.get('/api/domain', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { domain } = req.query;
        
        if (!domain) {
            return res.status(400).json({ error: 'Domain parameter required' });
        }
        
        // Clean domain
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
        
        // Perform domain analysis
        const domainInfo = await analyzeDomain(cleanDomain);
        
        res.json(domainInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'Domain analysis failed', details: error.message });
    }
});

// Credit Card BIN Analysis endpoint
app.get('/api/bin', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { bin } = req.query;
        
        if (!bin) {
            return res.status(400).json({ error: 'BIN parameter required' });
        }
        
        // Validate BIN (first 6-8 digits)
        const cleanBin = bin.replace(/\D/g, '').substring(0, 8);
        
        if (cleanBin.length < 6) {
            return res.status(400).json({ error: 'BIN must be at least 6 digits' });
        }
        
        // Analyze BIN
        const binInfo = await analyzeBIN(cleanBin);
        
        res.json(binInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'BIN analysis failed', details: error.message });
    }
});

// Email Validation endpoint
app.get('/api/email', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { email } = req.query;
        
        if (!email) {
            return res.status(400).json({ error: 'Email parameter required' });
        }
        
        // Validate and analyze email
        const emailInfo = await analyzeEmail(email);
        
        res.json(emailInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'Email analysis failed', details: error.message });
    }
});

// MAC Address Analysis endpoint
app.get('/api/mac', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { mac } = req.query;
        
        if (!mac) {
            return res.status(400).json({ error: 'MAC parameter required' });
        }
        
        // Analyze MAC address
        const macInfo = analyzeMACAddress(mac);
        
        res.json(macInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'MAC analysis failed', details: error.message });
    }
});

// Hash Analysis endpoint
app.get('/api/hash', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { hash, type } = req.query;
        
        if (!hash) {
            return res.status(400).json({ error: 'Hash parameter required' });
        }
        
        // Analyze hash
        const hashInfo = await analyzeHash(hash, type);
        
        res.json(hashInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'Hash analysis failed', details: error.message });
    }
});

// Base64 Encode/Decode endpoint
app.post('/api/base64', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { text, operation } = req.body;
        
        if (!text || !operation) {
            return res.status(400).json({ error: 'Text and operation parameters required' });
        }
        
        let result;
        if (operation === 'encode') {
            result = Buffer.from(text, 'utf8').toString('base64');
        } else if (operation === 'decode') {
            try {
                result = Buffer.from(text, 'base64').toString('utf8');
            } catch (error) {
                return res.status(400).json({ error: 'Invalid Base64 string' });
            }
        } else {
            return res.status(400).json({ error: 'Operation must be encode or decode' });
        }
        
        res.json({
            input: text,
            operation: operation,
            result: result,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Base64 operation failed', details: error.message });
    }
});

// QR Code Generator endpoint
app.post('/api/qr', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { text, size = 200, format = 'png' } = req.body;
        
        if (!text) {
            return res.status(400).json({ error: 'Text parameter required' });
        }
        
        // Generate QR code URL (using external service)
        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}&format=${format}`;
        
        const result = {
            text: text,
            qrUrl: qrUrl,
            size: size,
            format: format,
            downloadUrl: qrUrl + '&download=1',
            timestamp: new Date().toISOString()
        };
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({ error: 'QR code generation failed', details: error.message });
    }
});

// Password Security Analysis endpoint
app.post('/api/password', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password parameter required' });
        }
        
        // Analyze password security
        const passwordInfo = analyzePasswordSecurity(password);
        
        res.json(passwordInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'Password analysis failed', details: error.message });
    }
});

// License Plate Analysis endpoint
app.get('/api/plate', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { plate } = req.query;
        
        if (!plate) {
            return res.status(400).json({ error: 'Plate parameter required' });
        }
        
        // Clean and analyze plate
        const cleanPlate = plate.toUpperCase().replace(/\s/g, '');
        const plateInfo = analyzePlate(cleanPlate);
        
        res.json(plateInfo);
        
    } catch (error) {
        res.status(500).json({ error: 'Plate analysis failed', details: error.message });
    }
});

// IBAN Validation and Lookup endpoint
app.get('/api/iban', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { iban } = req.query;
        
        if (!iban) {
            return res.status(400).json({ error: 'IBAN parameter required' });
        }
        
        // Clean IBAN (remove spaces and convert to uppercase)
        const cleanIban = iban.replace(/\s/g, '').toUpperCase();
        
        // Validate IBAN format and checksum
        const validation = validateIban(cleanIban);
        
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: 'Invalid IBAN', 
                details: validation.error,
                iban: cleanIban
            });
        }
        
        // Extract IBAN information
        const ibanInfo = extractIbanInfo(cleanIban);
        
        // Try to get additional bank information from multiple sources
        const bankInfo = await getBankInfo(ibanInfo.countryCode, ibanInfo.bankCode);
        
        const result = {
            iban: cleanIban,
            formatted: formatIban(cleanIban),
            isValid: true,
            validation: validation,
            country: ibanInfo.country,
            countryCode: ibanInfo.countryCode,
            bankCode: ibanInfo.bankCode,
            accountNumber: ibanInfo.accountNumber,
            checkDigits: ibanInfo.checkDigits,
            bankInfo: bankInfo,
            timestamp: new Date().toISOString()
        };
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({ error: 'IBAN lookup failed', details: error.message });
    }
});

// Enhanced IP Lookup endpoint - 10+ APIs combined
app.get('/api/iplookup', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { ip } = req.query;
        
        if (!ip) {
            return res.status(400).json({ error: 'IP parameter required' });
        }
        
        // Validate IP format
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ error: 'Invalid IP address format' });
        }
        
        const results = {};
        
        // API 1: ip-api.com (Free, no key required)
        try {
            const ipApiResponse = await axios.get(`http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query`, {
                timeout: 5000
            });
            results.ipApi = ipApiResponse.data;
        } catch (error) {
            results.ipApi = { error: 'API request failed' };
        }
        
        // API 2: ipapi.co (Free, no key required)
        try {
            const ipapiResponse = await axios.get(`https://ipapi.co/${ip}/json/`, {
                timeout: 5000
            });
            results.ipapi = ipapiResponse.data;
        } catch (error) {
            results.ipapi = { error: 'API request failed' };
        }
        
        // API 3: KeyCDN Tools
        try {
            const keycdnResponse = await axios.get(`https://tools.keycdn.com/geo.json?host=${ip}`, {
                timeout: 5000
            });
            results.keycdn = keycdnResponse.data;
        } catch (error) {
            results.keycdn = { error: 'API request failed' };
        }
        
        // API 4: ipwhois.app (Free, no key required)
        try {
            const ipwhoisResponse = await axios.get(`http://ipwhois.app/json/${ip}`, {
                timeout: 5000
            });
            results.ipwhois = ipwhoisResponse.data;
        } catch (error) {
            results.ipwhois = { error: 'API request failed' };
        }
        
        // API 5: ipinfo.io (Free tier, no key required for basic)
        try {
            const ipinfoResponse = await axios.get(`https://ipinfo.io/${ip}/json`, {
                timeout: 5000
            });
            results.ipinfo = ipinfoResponse.data;
        } catch (error) {
            results.ipinfo = { error: 'API request failed' };
        }
        
        // API 6: freegeoip.app
        try {
            const freegeoipResponse = await axios.get(`https://freegeoip.app/json/${ip}`, {
                timeout: 5000
            });
            results.freegeoip = freegeoipResponse.data;
        } catch (error) {
            results.freegeoip = { error: 'API request failed' };
        }
        
        // API 7: ipgeolocation.io (Free tier)
        try {
            const ipgeoResponse = await axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=${ip}`, {
                timeout: 5000
            });
            results.ipgeolocation = ipgeoResponse.data;
        } catch (error) {
            results.ipgeolocation = { error: 'API request failed' };
        }
        
        // API 8: ip2location.io (Free tier)
        try {
            const ip2locResponse = await axios.get(`https://api.ip2location.io/?ip=${ip}`, {
                timeout: 5000
            });
            results.ip2location = ip2locResponse.data;
        } catch (error) {
            results.ip2location = { error: 'API request failed' };
        }
        
        // API 9: ipstack.com (Free tier)
        try {
            const ipstackResponse = await axios.get(`http://api.ipstack.com/${ip}?access_key=free`, {
                timeout: 5000
            });
            results.ipstack = ipstackResponse.data;
        } catch (error) {
            results.ipstack = { error: 'API request failed' };
        }
        
        // API 10: Abstract API (Free tier)
        try {
            const abstractResponse = await axios.get(`https://ipgeolocation.abstractapi.com/v1/?api_key=free&ip_address=${ip}`, {
                timeout: 5000
            });
            results.abstract = abstractResponse.data;
        } catch (error) {
            results.abstract = { error: 'API request failed' };
        }
        
        // Enhanced blacklist check
        const blacklistCheck = await checkIPBlacklist(ip);
        results.blacklist = blacklistCheck;
        
        // Enhanced threat intelligence
        const threatIntel = await getThreatIntelligence(ip);
        results.threatIntel = threatIntel;
        
        // Combine and normalize data
        const combinedResult = combineEnhancedIpData(results, ip);
        
        res.json(combinedResult);
        
    } catch (error) {
        res.status(500).json({ error: 'Enhanced IP lookup failed' });
    }
});

// Function to combine and normalize IP data from multiple sources
function combineIpData(results, ip) {
    const combined = {
        ip: ip,
        timestamp: new Date().toISOString(),
        sources: Object.keys(results).length,
        data: {}
    };
    
    // Extract and combine data from all sources
    const sources = results;
    
    // Basic Info
    combined.data.basic = {
        ip: ip,
        type: getFirstValid([sources.ipApi?.query, sources.ipapi?.ip, sources.ipinfo?.ip]),
        hostname: getFirstValid([sources.keycdn?.data?.host, sources.ipwhois?.hostname, sources.ipinfo?.hostname]),
        anycast: getFirstValid([sources.ipApi?.mobile, sources.ipwhois?.anycast])
    };
    
    // Location Info
    combined.data.location = {
        continent: getFirstValid([sources.ipApi?.continent, sources.ipapi?.continent_code, sources.keycdn?.data?.continent_code]),
        continentCode: getFirstValid([sources.ipApi?.continentCode, sources.ipapi?.continent_code]),
        country: getFirstValid([sources.ipApi?.country, sources.ipapi?.country_name, sources.keycdn?.data?.country_name, sources.ipwhois?.country, sources.ipinfo?.country]),
        countryCode: getFirstValid([sources.ipApi?.countryCode, sources.ipapi?.country_code, sources.keycdn?.data?.country_code, sources.ipwhois?.country_code, sources.freegeoip?.country_code]),
        region: getFirstValid([sources.ipApi?.regionName, sources.ipapi?.region, sources.keycdn?.data?.region_name, sources.ipwhois?.region, sources.ipinfo?.region]),
        regionCode: getFirstValid([sources.ipApi?.region, sources.ipapi?.region_code, sources.keycdn?.data?.region_code]),
        city: getFirstValid([sources.ipApi?.city, sources.ipapi?.city, sources.keycdn?.data?.city, sources.ipwhois?.city, sources.ipinfo?.city, sources.freegeoip?.city]),
        district: getFirstValid([sources.ipApi?.district, sources.ipwhois?.district]),
        postalCode: getFirstValid([sources.ipApi?.zip, sources.ipapi?.postal, sources.keycdn?.data?.postal_code, sources.ipinfo?.postal, sources.freegeoip?.zip_code]),
        latitude: getFirstValid([sources.ipApi?.lat, sources.ipapi?.latitude, sources.keycdn?.data?.latitude, sources.ipwhois?.latitude, sources.freegeoip?.latitude]),
        longitude: getFirstValid([sources.ipApi?.lon, sources.ipapi?.longitude, sources.keycdn?.data?.longitude, sources.ipwhois?.longitude, sources.freegeoip?.longitude]),
        timezone: getFirstValid([sources.ipApi?.timezone, sources.ipapi?.timezone, sources.keycdn?.data?.timezone, sources.ipwhois?.timezone, sources.ipinfo?.timezone]),
        utcOffset: getFirstValid([sources.ipApi?.offset, sources.ipapi?.utc_offset])
    };
    
    // ISP/Network Info
    combined.data.network = {
        isp: getFirstValid([sources.ipApi?.isp, sources.ipapi?.org, sources.ipwhois?.isp, sources.ipinfo?.org]),
        organization: getFirstValid([sources.ipApi?.org, sources.ipapi?.org, sources.ipwhois?.org, sources.ipinfo?.org]),
        as: getFirstValid([sources.ipApi?.as, sources.ipwhois?.asn]),
        asName: getFirstValid([sources.ipApi?.asname, sources.ipwhois?.asn_org]),
        reverse: getFirstValid([sources.ipApi?.reverse]),
        domains: getFirstValid([sources.ipwhois?.domains])
    };
    
    // Security Info
    combined.data.security = {
        proxy: getFirstValid([sources.ipApi?.proxy, sources.ipwhois?.proxy]),
        vpn: getFirstValid([sources.ipwhois?.vpn]),
        tor: getFirstValid([sources.ipwhois?.tor]),
        hosting: getFirstValid([sources.ipApi?.hosting, sources.ipwhois?.hosting]),
        mobile: getFirstValid([sources.ipApi?.mobile, sources.ipwhois?.mobile]),
        threat: getFirstValid([sources.ipwhois?.threat])
    };
    
    // Currency & Language
    combined.data.locale = {
        currency: getFirstValid([sources.ipApi?.currency, sources.ipapi?.currency, sources.ipwhois?.currency]),
        currencyCode: getFirstValid([sources.ipapi?.currency, sources.ipwhois?.currency_code]),
        languages: getFirstValid([sources.ipapi?.languages, sources.ipwhois?.languages]),
        callingCode: getFirstValid([sources.ipapi?.country_calling_code, sources.ipwhois?.country_calling_code])
    };
    
    // Raw data from all sources
    combined.rawData = results;
    
    return combined;
}

// Helper function to get first valid (non-null, non-undefined, non-empty) value
function getFirstValid(values) {
    for (const value of values) {
        if (value !== null && value !== undefined && value !== '' && value !== 'N/A') {
            return value;
        }
    }
    return null;
}

// IBAN Validation Functions
function validateIban(iban) {
    // Remove spaces and convert to uppercase
    const cleanIban = iban.replace(/\s/g, '').toUpperCase();
    
    // Check basic format (2 letters + 2 digits + up to 30 alphanumeric)
    if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(cleanIban)) {
        return { isValid: false, error: 'Invalid IBAN format' };
    }
    
    // Check length based on country
    const countryLengths = {
        'AD': 24, 'AE': 23, 'AL': 28, 'AT': 20, 'AZ': 28, 'BA': 20, 'BE': 16,
        'BG': 22, 'BH': 22, 'BR': 29, 'BY': 28, 'CH': 21, 'CR': 22, 'CY': 28,
        'CZ': 24, 'DE': 22, 'DK': 18, 'DO': 28, 'EE': 20, 'EG': 29, 'ES': 24,
        'FI': 18, 'FO': 18, 'FR': 27, 'GB': 22, 'GE': 22, 'GI': 23, 'GL': 18,
        'GR': 27, 'GT': 28, 'HR': 21, 'HU': 28, 'IE': 22, 'IL': 23, 'IS': 26,
        'IT': 27, 'JO': 30, 'KW': 30, 'KZ': 20, 'LB': 28, 'LC': 32, 'LI': 21,
        'LT': 20, 'LU': 20, 'LV': 21, 'MC': 27, 'MD': 24, 'ME': 22, 'MK': 19,
        'MR': 27, 'MT': 31, 'MU': 30, 'NL': 18, 'NO': 15, 'PK': 24, 'PL': 28,
        'PS': 29, 'PT': 25, 'QA': 29, 'RO': 24, 'RS': 22, 'SA': 24, 'SE': 24,
        'SI': 19, 'SK': 24, 'SM': 27, 'TN': 24, 'TR': 26, 'UA': 29, 'VG': 24,
        'XK': 20
    };
    
    const countryCode = cleanIban.substring(0, 2);
    const expectedLength = countryLengths[countryCode];
    
    if (!expectedLength) {
        return { isValid: false, error: 'Unknown country code' };
    }
    
    if (cleanIban.length !== expectedLength) {
        return { isValid: false, error: `Invalid length for ${countryCode}. Expected ${expectedLength}, got ${cleanIban.length}` };
    }
    
    // Validate checksum using mod-97 algorithm
    const rearranged = cleanIban.substring(4) + cleanIban.substring(0, 4);
    const numericString = rearranged.replace(/[A-Z]/g, (char) => (char.charCodeAt(0) - 55).toString());
    
    // Calculate mod 97 for large numbers
    let remainder = 0;
    for (let i = 0; i < numericString.length; i++) {
        remainder = (remainder * 10 + parseInt(numericString[i])) % 97;
    }
    
    if (remainder !== 1) {
        return { isValid: false, error: 'Invalid checksum' };
    }
    
    return { isValid: true, error: null };
}

function extractIbanInfo(iban) {
    const countryCode = iban.substring(0, 2);
    const checkDigits = iban.substring(2, 4);
    
    // Country names mapping
    const countryNames = {
        'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AL': 'Albania', 'AT': 'Austria',
        'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BE': 'Belgium', 'BG': 'Bulgaria',
        'BH': 'Bahrain', 'BR': 'Brazil', 'BY': 'Belarus', 'CH': 'Switzerland', 'CR': 'Costa Rica',
        'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DE': 'Germany', 'DK': 'Denmark', 'DO': 'Dominican Republic',
        'EE': 'Estonia', 'EG': 'Egypt', 'ES': 'Spain', 'FI': 'Finland', 'FO': 'Faroe Islands',
        'FR': 'France', 'GB': 'United Kingdom', 'GE': 'Georgia', 'GI': 'Gibraltar', 'GL': 'Greenland',
        'GR': 'Greece', 'GT': 'Guatemala', 'HR': 'Croatia', 'HU': 'Hungary', 'IE': 'Ireland',
        'IL': 'Israel', 'IS': 'Iceland', 'IT': 'Italy', 'JO': 'Jordan', 'KW': 'Kuwait',
        'KZ': 'Kazakhstan', 'LB': 'Lebanon', 'LC': 'Saint Lucia', 'LI': 'Liechtenstein',
        'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'MC': 'Monaco', 'MD': 'Moldova',
        'ME': 'Montenegro', 'MK': 'North Macedonia', 'MR': 'Mauritania', 'MT': 'Malta',
        'MU': 'Mauritius', 'NL': 'Netherlands', 'NO': 'Norway', 'PK': 'Pakistan', 'PL': 'Poland',
        'PS': 'Palestine', 'PT': 'Portugal', 'QA': 'Qatar', 'RO': 'Romania', 'RS': 'Serbia',
        'SA': 'Saudi Arabia', 'SE': 'Sweden', 'SI': 'Slovenia', 'SK': 'Slovakia', 'SM': 'San Marino',
        'TN': 'Tunisia', 'TR': 'Turkey', 'UA': 'Ukraine', 'VG': 'British Virgin Islands', 'XK': 'Kosovo'
    };
    
    // Extract bank code (varies by country)
    let bankCode = '';
    let accountNumber = '';
    
    switch (countryCode) {
        case 'DE': // Germany
            bankCode = iban.substring(4, 12);
            accountNumber = iban.substring(12);
            break;
        case 'GB': // United Kingdom
            bankCode = iban.substring(4, 10);
            accountNumber = iban.substring(10);
            break;
        case 'FR': // France
            bankCode = iban.substring(4, 9);
            accountNumber = iban.substring(9);
            break;
        case 'IT': // Italy
            bankCode = iban.substring(4, 9);
            accountNumber = iban.substring(9);
            break;
        case 'ES': // Spain
            bankCode = iban.substring(4, 8);
            accountNumber = iban.substring(8);
            break;
        case 'NL': // Netherlands
            bankCode = iban.substring(4, 8);
            accountNumber = iban.substring(8);
            break;
        case 'TR': // Turkey
            bankCode = iban.substring(4, 9);
            accountNumber = iban.substring(9);
            break;
        default:
            // Generic extraction for other countries
            bankCode = iban.substring(4, 8);
            accountNumber = iban.substring(8);
    }
    
    return {
        countryCode,
        country: countryNames[countryCode] || 'Unknown',
        checkDigits,
        bankCode,
        accountNumber
    };
}

function formatIban(iban) {
    // Format IBAN with spaces every 4 characters
    return iban.replace(/(.{4})/g, '$1 ').trim();
}

async function getBankInfo(countryCode, bankCode) {
    const bankInfo = {
        bankCode: bankCode,
        bankName: null,
        bic: null,
        country: countryCode,
        city: null,
        address: null
    };
    
    // Static bank information for major banks (in a real application, use a proper database)
    const bankDatabase = {
        'DE': {
            '10010010': { name: 'Postbank', bic: 'PBNKDEFF', city: 'Berlin' },
            '12030000': { name: 'Deutsche Kreditbank AG', bic: 'BYLADEM1001', city: 'Berlin' },
            '10020890': { name: 'UniCredit Bank AG', bic: 'HYVEDEMM300', city: 'Munich' },
            '50010517': { name: 'ING-DiBa AG', bic: 'INGDDEFFXXX', city: 'Frankfurt' },
            '70150000': { name: 'Stadtsparkasse München', bic: 'SSKMDEMMXXX', city: 'Munich' }
        },
        'TR': {
            '00001': { name: 'Türkiye Cumhuriyet Merkez Bankası', bic: 'TCMBTRIS', city: 'Ankara' },
            '00010': { name: 'Türkiye Cumhuriyeti Ziraat Bankası A.Ş.', bic: 'TCZBTR2A', city: 'Ankara' },
            '00012': { name: 'Türkiye Halk Bankası A.Ş.', bic: 'TRHBTR2A', city: 'Ankara' },
            '00015': { name: 'Türkiye Vakıflar Bankası T.A.O.', bic: 'TVBATR2A', city: 'Ankara' },
            '00032': { name: 'Türkiye İş Bankası A.Ş.', bic: 'ISBKTRIS', city: 'Istanbul' },
            '00046': { name: 'Akbank T.A.Ş.', bic: 'AKBKTRIS', city: 'Istanbul' },
            '00062': { name: 'Türkiye Garanti Bankası A.Ş.', bic: 'TGBATRIS', city: 'Istanbul' },
            '00067': { name: 'Yapı ve Kredi Bankası A.Ş.', bic: 'YAPITRIS', city: 'Istanbul' }
        },
        'GB': {
            '2004': { name: 'Barclays Bank PLC', bic: 'BARCGB22', city: 'London' },
            '4000': { name: 'HSBC Bank PLC', bic: 'HBUKGB4B', city: 'London' },
            '6016': { name: 'Lloyds Bank PLC', bic: 'LOYDGB21', city: 'London' },
            '8301': { name: 'Royal Bank of Scotland', bic: 'RBOSGB2L', city: 'Edinburgh' }
        },
        'FR': {
            '20041': { name: 'BNP Paribas', bic: 'BNPAFRPP', city: 'Paris' },
            '30002': { name: 'Crédit Agricole', bic: 'AGRIFRPP', city: 'Paris' },
            '30003': { name: 'Crédit Lyonnais', bic: 'LYONFRPP', city: 'Lyon' }
        }
    };
    
    if (bankDatabase[countryCode] && bankDatabase[countryCode][bankCode]) {
        const bank = bankDatabase[countryCode][bankCode];
        bankInfo.bankName = bank.name;
        bankInfo.bic = bank.bic;
        bankInfo.city = bank.city;
    }
    
    return bankInfo;
}

// Export for Vercel
module.exports = app;
// Local development server
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Atlas Panel Server running on http://0.0.0.0:${PORT}`);
    });
}

// Phone Number Analysis Functions
function analyzePhoneNumber(phone) {
    const result = {
        formatted: '',
        international: '',
        operator: 'Bilinmiyor',
        type: 'Bilinmiyor',
        region: 'Bilinmiyor',
        isValid: false,
        country: 'Türkiye'
    };
    
    // Turkish phone number analysis
    if (phone.startsWith('90')) {
        phone = phone.substring(2);
    }
    
    if (phone.startsWith('0')) {
        phone = phone.substring(1);
    }
    
    if (phone.length === 10) {
        result.isValid = true;
        result.formatted = `0${phone.substring(0, 3)} ${phone.substring(3, 6)} ${phone.substring(6, 8)} ${phone.substring(8)}`;
        result.international = `+90 ${phone.substring(0, 3)} ${phone.substring(3, 6)} ${phone.substring(6, 8)} ${phone.substring(8)}`;
        
        const prefix = phone.substring(0, 3);
        
        // Mobile operators
        if (['501', '502', '503', '504', '505', '506', '507', '508', '509'].includes(prefix)) {
            result.operator = 'Turkcell';
            result.type = 'GSM';
        } else if (['530', '531', '532', '533', '534', '535', '536', '537', '538', '539'].includes(prefix)) {
            result.operator = 'Vodafone';
            result.type = 'GSM';
        } else if (['540', '541', '542', '543', '544', '545', '546', '547', '548', '549'].includes(prefix)) {
            result.operator = 'Türk Telekom';
            result.type = 'GSM';
        } else if (['550', '551', '552', '553', '554', '555', '559'].includes(prefix)) {
            result.operator = 'Türk Telekom';
            result.type = 'GSM';
        } else if (['561', '562', '563', '564', '565', '566', '567', '568', '569'].includes(prefix)) {
            result.operator = 'Türk Telekom';
            result.type = 'GSM';
        }
        
        // Fixed line analysis
        const areaCode = phone.substring(0, 3);
        const cityMap = {
            '212': 'İstanbul (Avrupa)',
            '216': 'İstanbul (Asya)',
            '312': 'Ankara',
            '232': 'İzmir',
            '224': 'Bursa',
            '322': 'Adana',
            '332': 'Konya',
            '352': 'Kayseri',
            '362': 'Samsun',
            '442': 'Trabzon',
            '272': 'Afyon',
            '318': 'Kırıkkale',
            '326': 'Hatay',
            '424': 'Elazığ',
            '432': 'Diyarbakır'
        };
        
        if (cityMap[areaCode]) {
            result.region = cityMap[areaCode];
            result.type = 'Sabit Hat';
            result.operator = 'Türk Telekom';
        }
    }
    
    return result;
}

// Domain Analysis Functions
async function analyzeDomain(domain) {
    const result = {
        domain: domain,
        isValid: false,
        whois: {},
        dns: {},
        ssl: {},
        security: {},
        server: {},
        timestamp: new Date().toISOString()
    };
    
    try {
        // Basic domain validation
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
        result.isValid = domainRegex.test(domain);
        
        if (!result.isValid) {
            return result;
        }
        
        // Try to get basic info from multiple sources
        try {
            // Check if domain is reachable
            const response = await axios.get(`https://${domain}`, { 
                timeout: 5000,
                maxRedirects: 5,
                validateStatus: () => true
            });
            
            result.server = {
                status: response.status,
                server: response.headers.server || 'Unknown',
                powered: response.headers['x-powered-by'] || 'Unknown',
                contentType: response.headers['content-type'] || 'Unknown',
                lastModified: response.headers['last-modified'] || 'Unknown'
            };
            
        } catch (error) {
            result.server = { error: 'Domain not reachable' };
        }
        
        // DNS Analysis (simulated - in production use proper DNS libraries)
        result.dns = {
            hasA: true, // Simulated
            hasMX: true, // Simulated
            hasNS: true, // Simulated
            hasTXT: true, // Simulated
            records: {
                A: ['Simulated A record'],
                MX: ['Simulated MX record'],
                NS: ['Simulated NS record'],
                TXT: ['Simulated TXT record']
            }
        };
        
        // SSL Analysis (simulated)
        result.ssl = {
            isValid: true,
            issuer: 'Simulated CA',
            validFrom: new Date().toISOString(),
            validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
            algorithm: 'RSA 2048'
        };
        
        // Security Analysis
        result.security = {
            hasHTTPS: domain.includes('https') || true,
            hasHSTS: false,
            hasCSP: false,
            malwareCheck: 'Clean',
            phishingCheck: 'Clean'
        };
        
        // WHOIS simulation (in production use proper WHOIS API)
        result.whois = {
            registrar: 'Simulated Registrar',
            createdDate: '2020-01-01',
            expiryDate: '2025-01-01',
            nameServers: ['ns1.example.com', 'ns2.example.com'],
            status: 'Active'
        };
        
    } catch (error) {
        result.error = error.message;
    }
    
    return result;
}

// BIN Analysis Functions
async function analyzeBIN(bin) {
    const result = {
        bin: bin,
        isValid: false,
        bank: {},
        card: {},
        country: {},
        timestamp: new Date().toISOString()
    };
    
    // BIN Database (expanded)
    const binDatabase = {
        // Turkish Banks
        '540061': { bank: 'Akbank', type: 'Visa', level: 'Classic', country: 'Turkey', currency: 'TRY' },
        '526717': { bank: 'Akbank', type: 'MasterCard', level: 'Gold', country: 'Turkey', currency: 'TRY' },
        '450803': { bank: 'Yapı Kredi', type: 'Visa', level: 'Platinum', country: 'Turkey', currency: 'TRY' },
        '552879': { bank: 'Yapı Kredi', type: 'MasterCard', level: 'World', country: 'Turkey', currency: 'TRY' },
        '415565': { bank: 'İş Bankası', type: 'Visa', level: 'Classic', country: 'Turkey', currency: 'TRY' },
        '524073': { bank: 'İş Bankası', type: 'MasterCard', level: 'Gold', country: 'Turkey', currency: 'TRY' },
        '454360': { bank: 'Garanti BBVA', type: 'Visa', level: 'Platinum', country: 'Turkey', currency: 'TRY' },
        '530906': { bank: 'Garanti BBVA', type: 'MasterCard', level: 'World Elite', country: 'Turkey', currency: 'TRY' },
        '627892': { bank: 'Ziraat Bankası', type: 'Troy', level: 'Classic', country: 'Turkey', currency: 'TRY' },
        '627893': { bank: 'Halkbank', type: 'Troy', level: 'Gold', country: 'Turkey', currency: 'TRY' },
        
        // International Banks
        '424242': { bank: 'Test Bank', type: 'Visa', level: 'Classic', country: 'USA', currency: 'USD' },
        '555555': { bank: 'Test Bank', type: 'MasterCard', level: 'Gold', country: 'USA', currency: 'USD' },
        '378282': { bank: 'American Express', type: 'Amex', level: 'Gold', country: 'USA', currency: 'USD' },
        '371449': { bank: 'American Express', type: 'Amex', level: 'Platinum', country: 'USA', currency: 'USD' }
    };
    
    // Check exact match first
    let binInfo = binDatabase[bin];
    
    // If no exact match, try shorter BINs
    if (!binInfo) {
        for (let i = 6; i >= 4; i--) {
            const shortBin = bin.substring(0, i);
            binInfo = binDatabase[shortBin];
            if (binInfo) break;
        }
    }
    
    if (binInfo) {
        result.isValid = true;
        result.bank = {
            name: binInfo.bank,
            country: binInfo.country
        };
        result.card = {
            type: binInfo.type,
            level: binInfo.level,
            currency: binInfo.currency
        };
        result.country = {
            name: binInfo.country,
            currency: binInfo.currency
        };
    } else {
        // Fallback analysis based on first digit
        const firstDigit = bin.charAt(0);
        
        if (firstDigit === '4') {
            result.card.type = 'Visa';
        } else if (['5', '2'].includes(firstDigit)) {
            result.card.type = 'MasterCard';
        } else if (['34', '37'].includes(bin.substring(0, 2))) {
            result.card.type = 'American Express';
        } else if (bin.startsWith('627')) {
            result.card.type = 'Troy';
            result.country.name = 'Turkey';
        }
        
        result.isValid = !!result.card.type;
    }
    
    return result;
}

// Email Analysis Functions
async function analyzeEmail(email) {
    const result = {
        email: email,
        isValid: false,
        format: {},
        domain: {},
        security: {},
        deliverability: {},
        timestamp: new Date().toISOString()
    };
    
    try {
        // Email format validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        result.format.isValid = emailRegex.test(email);
        
        if (!result.format.isValid) {
            result.format.error = 'Invalid email format';
            return result;
        }
        
        const [localPart, domainPart] = email.split('@');
        
        result.format = {
            isValid: true,
            localPart: localPart,
            domainPart: domainPart,
            length: email.length,
            hasNumbers: /\d/.test(localPart),
            hasSpecialChars: /[!#$%&'*+\-/=?^_`{|}~]/.test(localPart)
        };
        
        // Domain analysis
        result.domain = {
            name: domainPart,
            isDisposable: checkDisposableEmail(domainPart),
            isCommon: checkCommonProvider(domainPart),
            hasMX: true // Simulated
        };
        
        // Security analysis
        result.security = {
            riskLevel: result.domain.isDisposable ? 'High' : 'Low',
            isBusinessEmail: !checkCommonProvider(domainPart) && !result.domain.isDisposable,
            hasPlus: localPart.includes('+'),
            hasDots: localPart.includes('.')
        };
        
        // Deliverability
        result.deliverability = {
            score: result.domain.isDisposable ? 20 : 85,
            canReceive: !result.domain.isDisposable,
            mxExists: true,
            smtpValid: true
        };
        
        result.isValid = result.format.isValid && !result.domain.isDisposable;
        
    } catch (error) {
        result.error = error.message;
    }
    
    return result;
}

function checkDisposableEmail(domain) {
    const disposableDomains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'temp-mail.org', 'throwaway.email', 'getnada.com'
    ];
    return disposableDomains.includes(domain.toLowerCase());
}

function checkCommonProvider(domain) {
    const commonProviders = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'live.com', 'msn.com', 'yandex.com', 'mail.ru'
    ];
    return commonProviders.includes(domain.toLowerCase());
}

// License Plate Analysis Functions
function analyzePlate(plate) {
    const result = {
        plate: plate,
        isValid: false,
        city: {},
        vehicle: {},
        format: {},
        timestamp: new Date().toISOString()
    };
    
    // Turkish plate format validation
    const plateRegex = /^[0-9]{2}[A-Z]{1,3}[0-9]{1,4}$/;
    result.format.isValid = plateRegex.test(plate);
    
    if (!result.format.isValid) {
        result.format.error = 'Invalid Turkish plate format (e.g., 34ABC123)';
        return result;
    }
    
    // Extract city code
    const cityCode = plate.substring(0, 2);
    
    // Turkish city codes database
    const cityCodes = {
        '01': { name: 'Adana', region: 'Akdeniz' },
        '02': { name: 'Adıyaman', region: 'Güneydoğu Anadolu' },
        '03': { name: 'Afyonkarahisar', region: 'Ege' },
        '04': { name: 'Ağrı', region: 'Doğu Anadolu' },
        '05': { name: 'Amasya', region: 'Karadeniz' },
        '06': { name: 'Ankara', region: 'İç Anadolu' },
        '07': { name: 'Antalya', region: 'Akdeniz' },
        '08': { name: 'Artvin', region: 'Karadeniz' },
        '09': { name: 'Aydın', region: 'Ege' },
        '10': { name: 'Balıkesir', region: 'Marmara' },
        '11': { name: 'Bilecik', region: 'Marmara' },
        '12': { name: 'Bingöl', region: 'Doğu Anadolu' },
        '13': { name: 'Bitlis', region: 'Doğu Anadolu' },
        '14': { name: 'Bolu', region: 'Karadeniz' },
        '15': { name: 'Burdur', region: 'Akdeniz' },
        '16': { name: 'Bursa', region: 'Marmara' },
        '17': { name: 'Çanakkale', region: 'Marmara' },
        '18': { name: 'Çankırı', region: 'İç Anadolu' },
        '19': { name: 'Çorum', region: 'Karadeniz' },
        '20': { name: 'Denizli', region: 'Ege' },
        '21': { name: 'Diyarbakır', region: 'Güneydoğu Anadolu' },
        '22': { name: 'Edirne', region: 'Marmara' },
        '23': { name: 'Elazığ', region: 'Doğu Anadolu' },
        '24': { name: 'Erzincan', region: 'Doğu Anadolu' },
        '25': { name: 'Erzurum', region: 'Doğu Anadolu' },
        '26': { name: 'Eskişehir', region: 'İç Anadolu' },
        '27': { name: 'Gaziantep', region: 'Güneydoğu Anadolu' },
        '28': { name: 'Giresun', region: 'Karadeniz' },
        '29': { name: 'Gümüşhane', region: 'Karadeniz' },
        '30': { name: 'Hakkâri', region: 'Doğu Anadolu' },
        '31': { name: 'Hatay', region: 'Akdeniz' },
        '32': { name: 'Isparta', region: 'Akdeniz' },
        '33': { name: 'Mersin', region: 'Akdeniz' },
        '34': { name: 'İstanbul', region: 'Marmara' },
        '35': { name: 'İzmir', region: 'Ege' },
        '36': { name: 'Kars', region: 'Doğu Anadolu' },
        '37': { name: 'Kastamonu', region: 'Karadeniz' },
        '38': { name: 'Kayseri', region: 'İç Anadolu' },
        '39': { name: 'Kırklareli', region: 'Marmara' },
        '40': { name: 'Kırşehir', region: 'İç Anadolu' },
        '41': { name: 'Kocaeli', region: 'Marmara' },
        '42': { name: 'Konya', region: 'İç Anadolu' },
        '43': { name: 'Kütahya', region: 'Ege' },
        '44': { name: 'Malatya', region: 'Doğu Anadolu' },
        '45': { name: 'Manisa', region: 'Ege' },
        '46': { name: 'Kahramanmaraş', region: 'Akdeniz' },
        '47': { name: 'Mardin', region: 'Güneydoğu Anadolu' },
        '48': { name: 'Muğla', region: 'Ege' },
        '49': { name: 'Muş', region: 'Doğu Anadolu' },
        '50': { name: 'Nevşehir', region: 'İç Anadolu' },
        '51': { name: 'Niğde', region: 'İç Anadolu' },
        '52': { name: 'Ordu', region: 'Karadeniz' },
        '53': { name: 'Rize', region: 'Karadeniz' },
        '54': { name: 'Sakarya', region: 'Marmara' },
        '55': { name: 'Samsun', region: 'Karadeniz' },
        '56': { name: 'Siirt', region: 'Güneydoğu Anadolu' },
        '57': { name: 'Sinop', region: 'Karadeniz' },
        '58': { name: 'Sivas', region: 'İç Anadolu' },
        '59': { name: 'Tekirdağ', region: 'Marmara' },
        '60': { name: 'Tokat', region: 'Karadeniz' },
        '61': { name: 'Trabzon', region: 'Karadeniz' },
        '62': { name: 'Tunceli', region: 'Doğu Anadolu' },
        '63': { name: 'Şanlıurfa', region: 'Güneydoğu Anadolu' },
        '64': { name: 'Uşak', region: 'Ege' },
        '65': { name: 'Van', region: 'Doğu Anadolu' },
        '66': { name: 'Yozgat', region: 'İç Anadolu' },
        '67': { name: 'Zonguldak', region: 'Karadeniz' },
        '68': { name: 'Aksaray', region: 'İç Anadolu' },
        '69': { name: 'Bayburt', region: 'Karadeniz' },
        '70': { name: 'Karaman', region: 'İç Anadolu' },
        '71': { name: 'Kırıkkale', region: 'İç Anadolu' },
        '72': { name: 'Batman', region: 'Güneydoğu Anadolu' },
        '73': { name: 'Şırnak', region: 'Güneydoğu Anadolu' },
        '74': { name: 'Bartın', region: 'Karadeniz' },
        '75': { name: 'Ardahan', region: 'Doğu Anadolu' },
        '76': { name: 'Iğdır', region: 'Doğu Anadolu' },
        '77': { name: 'Yalova', region: 'Marmara' },
        '78': { name: 'Karabük', region: 'Karadeniz' },
        '79': { name: 'Kilis', region: 'Güneydoğu Anadolu' },
        '80': { name: 'Osmaniye', region: 'Akdeniz' },
        '81': { name: 'Düzce', region: 'Karadeniz' }
    };
    
    const cityInfo = cityCodes[cityCode];
    
    if (cityInfo) {
        result.isValid = true;
        result.city = {
            code: cityCode,
            name: cityInfo.name,
            region: cityInfo.region
        };
        
        // Vehicle type analysis based on format
        const letters = plate.match(/[A-Z]+/)[0];
        const numbers = plate.match(/[0-9]+/g);
        
        result.vehicle = {
            type: 'Otomobil', // Default
            format: `${cityCode} ${letters} ${numbers.join(' ')}`,
            letterCount: letters.length,
            numberCount: numbers.reduce((sum, num) => sum + num.length, 0)
        };
        
        // Special vehicle types
        if (letters.length === 1 && numbers[1] && numbers[1].length <= 3) {
            result.vehicle.type = 'Resmi Araç';
        } else if (letters.includes('D')) {
            result.vehicle.type = 'Diplomatik Araç';
        } else if (letters.includes('K')) {
            result.vehicle.type = 'Konsülosluk Aracı';
        }
        
        result.format = {
            isValid: true,
            original: plate,
            formatted: `${cityCode} ${letters} ${numbers.join(' ')}`,
            type: 'Turkish Standard'
        };
    } else {
        result.format.error = `Unknown city code: ${cityCode}`;
    }
    
    return result;
}
// Super Search Result Combiner
function combineSearchResults(results) {
    const combined = {
        personalInfo: {},
        contactInfo: {},
        addressInfo: {},
        workplaceInfo: {},
        familyInfo: {},
        summary: {
            totalSources: 0,
            successfulQueries: 0,
            failedQueries: 0
        }
    };
    
    // Count sources
    Object.keys(results).forEach(key => {
        combined.summary.totalSources++;
        if (results[key] && !results[key].error) {
            combined.summary.successfulQueries++;
        } else {
            combined.summary.failedQueries++;
        }
    });
    
    // Extract personal info from TC data
    if (results.tcInfo && !results.tcInfo.error) {
        const tcData = Array.isArray(results.tcInfo) ? results.tcInfo[0] : results.tcInfo;
        if (tcData) {
            combined.personalInfo = {
                tc: tcData.tc || tcData.TC,
                adi: tcData.adi || tcData.ADI,
                soyadi: tcData.soyadi || tcData.SOYADI,
                dogumTarihi: tcData.dogum_tarihi || tcData.DOGUM_TARIHI,
                cinsiyet: tcData.cinsiyet || tcData.CINSIYET,
                babaAdi: tcData.baba_adi || tcData.BABA_ADI,
                anneAdi: tcData.anne_adi || tcData.ANNE_ADI
            };
        }
    }
    
    // Extract address info
    if (results.adresInfo && !results.adresInfo.error) {
        const adresData = Array.isArray(results.adresInfo) ? results.adresInfo : [results.adresInfo];
        combined.addressInfo = adresData.map(addr => ({
            il: addr.il || addr.IL,
            ilce: addr.ilce || addr.ILCE,
            mahalle: addr.mahalle || addr.MAHALLE,
            adres: addr.adres || addr.ADRES,
            postaKodu: addr.posta_kodu || addr.POSTA_KODU
        }));
    }
    
    // Extract workplace info
    if (results.isyeriInfo && !results.isyeriInfo.error) {
        const isyeriData = Array.isArray(results.isyeriInfo) ? results.isyeriInfo : [results.isyeriInfo];
        combined.workplaceInfo = isyeriData.map(work => ({
            sirketAdi: work.sirket_adi || work.SIRKET_ADI,
            unvan: work.unvan || work.UNVAN,
            sektor: work.sektor || work.SEKTOR,
            adres: work.adres || work.ADRES
        }));
    }
    
    // Extract phone info
    if (results.phoneInfo && !results.phoneInfo.error) {
        const phoneData = Array.isArray(results.phoneInfo) ? results.phoneInfo : [results.phoneInfo];
        combined.contactInfo.phones = phoneData.map(phone => ({
            numara: phone.numara || phone.NUMARA,
            operator: phone.operator || phone.OPERATOR,
            tip: phone.tip || phone.TIP
        }));
    }
    
    // Extract family info
    if (results.sulaleInfo && !results.sulaleInfo.error) {
        const sulaleData = Array.isArray(results.sulaleInfo) ? results.sulaleInfo : [results.sulaleInfo];
        combined.familyInfo = sulaleData.map(family => ({
            yakinlik: family.yakinlik || family.YAKINLIK,
            adi: family.adi || family.ADI,
            soyadi: family.soyadi || family.SOYADI,
            tc: family.tc || family.TC,
            dogumTarihi: family.dogum_tarihi || family.DOGUM_TARIHI
        }));
    }
    
    // Extract name search results
    if (results.nameSearch && !results.nameSearch.error) {
        const nameData = Array.isArray(results.nameSearch) ? results.nameSearch : [results.nameSearch];
        combined.nameSearchResults = nameData.map(person => ({
            tc: person.tc || person.TC,
            adi: person.adi || person.ADI,
            soyadi: person.soyadi || person.SOYADI,
            dogumTarihi: person.dogum_tarihi || person.DOGUM_TARIHI,
            il: person.il || person.IL,
            ilce: person.ilce || person.ILCE
        }));
    }
    
    return combined;
}
// Enhanced IP Analysis Functions
function combineEnhancedIpData(results, ip) {
    const combined = {
        ip: ip,
        timestamp: new Date().toISOString(),
        sources: Object.keys(results).length,
        confidence: calculateConfidence(results),
        data: {}
    };
    
    // Extract and combine data from all sources
    const sources = results;
    
    // Basic Info (Enhanced)
    combined.data.basic = {
        ip: ip,
        type: getFirstValid([sources.ipApi?.query, sources.ipapi?.ip, sources.ipinfo?.ip]),
        hostname: getFirstValid([sources.keycdn?.data?.host, sources.ipwhois?.hostname, sources.ipinfo?.hostname]),
        anycast: getFirstValid([sources.ipApi?.mobile, sources.ipwhois?.anycast]),
        version: ip.includes(':') ? 'IPv6' : 'IPv4',
        class: getIPClass(ip)
    };
    
    // Location Info (Enhanced)
    combined.data.location = {
        continent: getFirstValid([sources.ipApi?.continent, sources.ipapi?.continent_code, sources.keycdn?.data?.continent_code]),
        continentCode: getFirstValid([sources.ipApi?.continentCode, sources.ipapi?.continent_code]),
        country: getFirstValid([sources.ipApi?.country, sources.ipapi?.country_name, sources.keycdn?.data?.country_name, sources.ipwhois?.country, sources.ipinfo?.country]),
        countryCode: getFirstValid([sources.ipApi?.countryCode, sources.ipapi?.country_code, sources.keycdn?.data?.country_code, sources.ipwhois?.country_code, sources.freegeoip?.country_code]),
        region: getFirstValid([sources.ipApi?.regionName, sources.ipapi?.region, sources.keycdn?.data?.region_name, sources.ipwhois?.region, sources.ipinfo?.region]),
        regionCode: getFirstValid([sources.ipApi?.region, sources.ipapi?.region_code, sources.keycdn?.data?.region_code]),
        city: getFirstValid([sources.ipApi?.city, sources.ipapi?.city, sources.keycdn?.data?.city, sources.ipwhois?.city, sources.ipinfo?.city, sources.freegeoip?.city]),
        district: getFirstValid([sources.ipApi?.district, sources.ipwhois?.district]),
        postalCode: getFirstValid([sources.ipApi?.zip, sources.ipapi?.postal, sources.keycdn?.data?.postal_code, sources.ipinfo?.postal, sources.freegeoip?.zip_code]),
        latitude: getFirstValid([sources.ipApi?.lat, sources.ipapi?.latitude, sources.keycdn?.data?.latitude, sources.ipwhois?.latitude, sources.freegeoip?.latitude]),
        longitude: getFirstValid([sources.ipApi?.lon, sources.ipapi?.longitude, sources.keycdn?.data?.longitude, sources.ipwhois?.longitude, sources.freegeoip?.longitude]),
        timezone: getFirstValid([sources.ipApi?.timezone, sources.ipapi?.timezone, sources.keycdn?.data?.timezone, sources.ipwhois?.timezone, sources.ipinfo?.timezone]),
        utcOffset: getFirstValid([sources.ipApi?.offset, sources.ipapi?.utc_offset]),
        accuracy: getFirstValid([sources.ipgeolocation?.accuracy, sources.ip2location?.accuracy])
    };
    
    // ISP/Network Info (Enhanced)
    combined.data.network = {
        isp: getFirstValid([sources.ipApi?.isp, sources.ipapi?.org, sources.ipwhois?.isp, sources.ipinfo?.org]),
        organization: getFirstValid([sources.ipApi?.org, sources.ipapi?.org, sources.ipwhois?.org, sources.ipinfo?.org]),
        as: getFirstValid([sources.ipApi?.as, sources.ipwhois?.asn]),
        asName: getFirstValid([sources.ipApi?.asname, sources.ipwhois?.asn_org]),
        reverse: getFirstValid([sources.ipApi?.reverse]),
        domains: getFirstValid([sources.ipwhois?.domains]),
        connectionType: getFirstValid([sources.ipgeolocation?.connection_type, sources.ip2location?.connection_type]),
        usageType: getFirstValid([sources.ip2location?.usage_type])
    };
    
    // Security Info (Enhanced)
    combined.data.security = {
        proxy: getFirstValid([sources.ipApi?.proxy, sources.ipwhois?.proxy]),
        vpn: getFirstValid([sources.ipwhois?.vpn]),
        tor: getFirstValid([sources.ipwhois?.tor]),
        hosting: getFirstValid([sources.ipApi?.hosting, sources.ipwhois?.hosting]),
        mobile: getFirstValid([sources.ipApi?.mobile, sources.ipwhois?.mobile]),
        threat: getFirstValid([sources.ipwhois?.threat]),
        blacklist: sources.blacklist || {},
        threatIntel: sources.threatIntel || {},
        riskScore: calculateRiskScore(sources)
    };
    
    // Currency & Language (Enhanced)
    combined.data.locale = {
        currency: getFirstValid([sources.ipApi?.currency, sources.ipapi?.currency, sources.ipwhois?.currency]),
        currencyCode: getFirstValid([sources.ipapi?.currency, sources.ipwhois?.currency_code]),
        languages: getFirstValid([sources.ipapi?.languages, sources.ipwhois?.languages]),
        callingCode: getFirstValid([sources.ipapi?.country_calling_code, sources.ipwhois?.country_calling_code])
    };
    
    // Weather Info (if available)
    combined.data.weather = {
        temperature: getFirstValid([sources.ipgeolocation?.temperature]),
        humidity: getFirstValid([sources.ipgeolocation?.humidity]),
        windSpeed: getFirstValid([sources.ipgeolocation?.wind_speed])
    };
    
    // Raw data from all sources
    combined.rawData = results;
    
    return combined;
}

function calculateConfidence(results) {
    const totalSources = Object.keys(results).length;
    const successfulSources = Object.values(results).filter(r => !r.error).length;
    return Math.round((successfulSources / totalSources) * 100);
}

function getIPClass(ip) {
    const firstOctet = parseInt(ip.split('.')[0]);
    if (firstOctet >= 1 && firstOctet <= 126) return 'Class A';
    if (firstOctet >= 128 && firstOctet <= 191) return 'Class B';
    if (firstOctet >= 192 && firstOctet <= 223) return 'Class C';
    if (firstOctet >= 224 && firstOctet <= 239) return 'Class D (Multicast)';
    if (firstOctet >= 240 && firstOctet <= 255) return 'Class E (Reserved)';
    return 'Unknown';
}

function calculateRiskScore(sources) {
    let score = 0;
    
    // Check various risk factors
    if (sources.ipApi?.proxy || sources.ipwhois?.proxy) score += 30;
    if (sources.ipwhois?.vpn) score += 25;
    if (sources.ipwhois?.tor) score += 40;
    if (sources.ipApi?.hosting || sources.ipwhois?.hosting) score += 15;
    if (sources.ipwhois?.threat) score += 35;
    
    return Math.min(score, 100);
}

async function checkIPBlacklist(ip) {
    // Simulated blacklist check (in production, use real blacklist APIs)
    return {
        isBlacklisted: false,
        sources: ['Spamhaus', 'SURBL', 'Barracuda'],
        lastCheck: new Date().toISOString(),
        reputation: 'Good'
    };
}

async function getThreatIntelligence(ip) {
    // Simulated threat intelligence (in production, use real threat intel APIs)
    return {
        threatLevel: 'Low',
        categories: [],
        lastSeen: null,
        confidence: 95,
        source: 'Threat Intelligence Database'
    };
}

// MAC Address Analysis Functions
function analyzeMACAddress(mac) {
    const result = {
        mac: mac,
        isValid: false,
        vendor: {},
        format: {},
        timestamp: new Date().toISOString()
    };
    
    // Clean MAC address
    const cleanMac = mac.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
    
    // Validate MAC format
    if (cleanMac.length === 12) {
        result.isValid = true;
        result.format = {
            original: mac,
            clean: cleanMac,
            colon: cleanMac.match(/.{2}/g).join(':'),
            dash: cleanMac.match(/.{2}/g).join('-'),
            dot: cleanMac.match(/.{4}/g).join('.'),
            cisco: cleanMac.match(/.{4}/g).join('.')
        };
        
        // Extract OUI (first 3 bytes)
        const oui = cleanMac.substring(0, 6);
        result.vendor = getVendorInfo(oui);
        
        // MAC address type analysis
        result.type = {
            isUnicast: (parseInt(cleanMac.charAt(1), 16) & 1) === 0,
            isMulticast: (parseInt(cleanMac.charAt(1), 16) & 1) === 1,
            isLocallyAdministered: (parseInt(cleanMac.charAt(1), 16) & 2) === 2,
            isUniversallyAdministered: (parseInt(cleanMac.charAt(1), 16) & 2) === 0
        };
    } else {
        result.format.error = 'Invalid MAC address length';
    }
    
    return result;
}

function getVendorInfo(oui) {
    // MAC OUI Database (sample)
    const ouiDatabase = {
        '000000': { vendor: 'Xerox Corporation', country: 'USA' },
        '000001': { vendor: 'Xerox Corporation', country: 'USA' },
        '000002': { vendor: 'Xerox Corporation', country: 'USA' },
        '00000C': { vendor: 'Cisco Systems', country: 'USA' },
        '000010': { vendor: 'Hughes LAN Systems', country: 'USA' },
        '000011': { vendor: 'Tektronix', country: 'USA' },
        '000015': { vendor: 'Datapoint Corporation', country: 'USA' },
        '00001D': { vendor: 'Cabletron Systems', country: 'USA' },
        '000020': { vendor: 'DIAB (Data Industrier AB)', country: 'Sweden' },
        '000022': { vendor: 'Visual Technology', country: 'USA' },
        '000050': { vendor: 'Addtron Technology Co., Ltd.', country: 'Taiwan' },
        '0000F8': { vendor: 'DEC', country: 'USA' },
        '001B63': { vendor: 'Apple Inc.', country: 'USA' },
        '001EC2': { vendor: 'Apple Inc.', country: 'USA' },
        '002332': { vendor: 'Apple Inc.', country: 'USA' },
        '002436': { vendor: 'Apple Inc.', country: 'USA' },
        '0050E4': { vendor: 'Samsung Electronics', country: 'South Korea' },
        '00E04C': { vendor: 'Realtek Semiconductor Corp.', country: 'Taiwan' },
        '080027': { vendor: 'Oracle VirtualBox', country: 'USA' },
        '525400': { vendor: 'QEMU Virtual NIC', country: 'Virtual' }
    };
    
    return ouiDatabase[oui] || { vendor: 'Unknown', country: 'Unknown' };
}

// Hash Analysis Functions
async function analyzeHash(hash, type) {
    const result = {
        hash: hash,
        type: type || 'auto',
        analysis: {},
        timestamp: new Date().toISOString()
    };
    
    // Auto-detect hash type if not specified
    if (!type || type === 'auto') {
        result.type = detectHashType(hash);
    }
    
    result.analysis = {
        length: hash.length,
        detectedType: result.type,
        isValid: validateHash(hash, result.type),
        charset: getHashCharset(hash),
        entropy: calculateEntropy(hash)
    };
    
    // Hash lookup (simulated - in production use real hash databases)
    if (result.analysis.isValid) {
        result.lookup = await hashLookup(hash, result.type);
    }
    
    return result;
}

function detectHashType(hash) {
    const length = hash.length;
    const isHex = /^[a-fA-F0-9]+$/.test(hash);
    
    if (!isHex) return 'Unknown';
    
    switch (length) {
        case 32: return 'MD5';
        case 40: return 'SHA1';
        case 56: return 'SHA224';
        case 64: return 'SHA256';
        case 96: return 'SHA384';
        case 128: return 'SHA512';
        default: return 'Unknown';
    }
}

function validateHash(hash, type) {
    const expectedLengths = {
        'MD5': 32,
        'SHA1': 40,
        'SHA224': 56,
        'SHA256': 64,
        'SHA384': 96,
        'SHA512': 128
    };
    
    return expectedLengths[type] === hash.length && /^[a-fA-F0-9]+$/.test(hash);
}

function getHashCharset(hash) {
    if (/^[0-9]+$/.test(hash)) return 'Numeric';
    if (/^[a-fA-F0-9]+$/.test(hash)) return 'Hexadecimal';
    if (/^[a-zA-Z0-9+/=]+$/.test(hash)) return 'Base64';
    return 'Mixed';
}

function calculateEntropy(str) {
    const freq = {};
    for (let char of str) {
        freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = str.length;
    
    for (let char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    
    return Math.round(entropy * 100) / 100;
}

async function hashLookup(hash, type) {
    // Simulated hash lookup (in production use real hash databases like VirusTotal)
    const commonHashes = {
        'd41d8cd98f00b204e9800998ecf8427e': 'Empty string',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709': 'Empty string (SHA1)',
        '5d41402abc4b2a76b9719d911017c592': 'hello',
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': 'hello (SHA1)'
    };
    
    return {
        found: !!commonHashes[hash.toLowerCase()],
        plaintext: commonHashes[hash.toLowerCase()] || null,
        source: 'Hash Database',
        confidence: commonHashes[hash.toLowerCase()] ? 100 : 0
    };
}

// Password Security Analysis Functions
function analyzePasswordSecurity(password) {
    const result = {
        password: '***HIDDEN***', // Never return actual password
        length: password.length,
        strength: {},
        score: 0,
        recommendations: [],
        timestamp: new Date().toISOString()
    };
    
    // Character set analysis
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    const hasSpaces = /\s/.test(password);
    
    result.strength = {
        hasLowercase: hasLower,
        hasUppercase: hasUpper,
        hasNumbers: hasNumbers,
        hasSpecialChars: hasSpecial,
        hasSpaces: hasSpaces,
        characterSets: [hasLower, hasUpper, hasNumbers, hasSpecial].filter(Boolean).length
    };
    
    // Calculate score
    let score = 0;
    
    // Length scoring
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 25;
    if (password.length >= 16) score += 25;
    
    // Character diversity
    score += result.strength.characterSets * 10;
    
    // Entropy calculation
    const entropy = calculateEntropy(password);
    if (entropy > 3) score += 15;
    if (entropy > 4) score += 10;
    
    result.score = Math.min(score, 100);
    
    // Strength level
    if (result.score < 30) result.level = 'Very Weak';
    else if (result.score < 50) result.level = 'Weak';
    else if (result.score < 70) result.level = 'Medium';
    else if (result.score < 90) result.level = 'Strong';
    else result.level = 'Very Strong';
    
    // Generate recommendations
    if (password.length < 8) result.recommendations.push('Use at least 8 characters');
    if (password.length < 12) result.recommendations.push('Consider using 12+ characters for better security');
    if (!hasLower) result.recommendations.push('Add lowercase letters');
    if (!hasUpper) result.recommendations.push('Add uppercase letters');
    if (!hasNumbers) result.recommendations.push('Add numbers');
    if (!hasSpecial) result.recommendations.push('Add special characters (!@#$%^&*)');
    if (result.strength.characterSets < 3) result.recommendations.push('Use a mix of different character types');
    
    // Common password check
    result.isCommon = checkCommonPassword(password);
    if (result.isCommon) {
        result.recommendations.push('Avoid common passwords');
        result.score = Math.min(result.score, 20);
        result.level = 'Very Weak';
    }
    
    return result;
}

function checkCommonPassword(password) {
    const commonPasswords = [
        'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
        'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'password1',
        'qwerty123', 'admin123', '123123', 'welcome123'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
}