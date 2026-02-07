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

// Statistics
let stats = {
    totalQueries: 0,
    successfulQueries: 0,
    failedQueries: 0,
    userQueries: {}
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

// Statistics middleware
const trackQuery = (req, res, next) => {
    const originalSend = res.send;
    res.send = function(data) {
        stats.totalQueries++;
        
        // Initialize user stats if not exists
        if (!stats.userQueries[req.user.username]) {
            stats.userQueries[req.user.username] = { total: 0, successful: 0, failed: 0 };
        }
        
        stats.userQueries[req.user.username].total++;
        
        if (res.statusCode >= 200 && res.statusCode < 300) {
            stats.successfulQueries++;
            stats.userQueries[req.user.username].successful++;
        } else {
            stats.failedQueries++;
            stats.userQueries[req.user.username].failed++;
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

// Protected API endpoints
app.get('/api/tc', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/tc.php?tc=${tc}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/adres', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/adres.php?tc=${tc}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/isyeri', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/isyeri.php?tc=${tc}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/sulale', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/sulale.php?tc=${tc}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/tcgsm', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { tc } = req.query;
        if (!tc) {
            return res.status(400).json({ error: 'TC parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/tcgsm.php?tc=${tc}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/gsmtc', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { gsm } = req.query;
        if (!gsm) {
            return res.status(400).json({ error: 'GSM parameter required' });
        }
        const response = await axios.get(`https://arastir.sbs/api/gsmtc.php?gsm=${gsm}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

app.get('/api/adsoyad', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { adi, soyadi, il, ilce } = req.query;
        
        if (!adi || !soyadi) {
            return res.status(400).json({ error: 'Adi and Soyadi parameters required' });
        }
        
        let queryString = `adi=${adi}&soyadi=${soyadi}`;
        if (il) queryString += `&il=${il}`;
        if (ilce) queryString += `&ilce=${ilce}`;
        
        const response = await axios.get(`https://arastir.sbs/api/adsoyad.php?${queryString}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
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

// IP Lookup endpoint - Multiple APIs combined
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
        
        // Combine and normalize data
        const combinedResult = combineIpData(results, ip);
        
        res.json(combinedResult);
        
    } catch (error) {
        res.status(500).json({ error: 'IP lookup failed' });
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

// Export for Vercel
module.exports = app;
// Local development server
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Atlas Panel Server running on http://0.0.0.0:${PORT}`);
    });
}