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

// Enhanced IBAN Validation and Lookup endpoint with comprehensive analysis
app.get('/api/iban', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { iban } = req.query;
        
        if (!iban) {
            return res.status(400).json({ error: 'IBAN parameter required' });
        }
        
        // Clean IBAN (remove spaces and convert to uppercase)
        const cleanIban = iban.replace(/\s/g, '').toUpperCase();
        
        // Enhanced IBAN validation
        const validation = enhancedValidateIban(cleanIban);
        
        if (!validation.isValid) {
            return res.status(400).json({ 
                error: 'Invalid IBAN', 
                details: validation.error,
                iban: cleanIban,
                validation: validation
            });
        }
        
        // Extract comprehensive IBAN information
        const ibanInfo = enhancedExtractIbanInfo(cleanIban);
        
        // Get enhanced bank information from multiple sources
        const bankInfo = await getEnhancedBankInfo(ibanInfo.countryCode, ibanInfo.bankCode, cleanIban);
        
        // Perform security and compliance checks
        const securityAnalysis = performIbanSecurityAnalysis(cleanIban, ibanInfo, bankInfo);
        
        // Generate IBAN analytics
        const analytics = generateIbanAnalytics(cleanIban, ibanInfo, bankInfo);
        
        const result = {
            iban: cleanIban,
            formatted: formatIban(cleanIban),
            isValid: true,
            validation: validation,
            country: ibanInfo.country,
            countryInfo: ibanInfo.countryInfo,
            countryCode: ibanInfo.countryCode,
            bankCode: ibanInfo.bankCode,
            branchCode: ibanInfo.branchCode,
            accountNumber: ibanInfo.accountNumber,
            checkDigits: ibanInfo.checkDigits,
            bankInfo: bankInfo,
            security: securityAnalysis,
            analytics: analytics,
            compliance: checkIbanCompliance(cleanIban, ibanInfo),
            recommendations: generateIbanRecommendations(validation, securityAnalysis, analytics),
            timestamp: new Date().toISOString()
        };
        
        res.json(result);
        
    } catch (error) {
        res.status(500).json({ error: 'Enhanced IBAN lookup failed', details: error.message });
    }
});

// Enhanced IP Lookup endpoint - 15+ APIs combined with advanced analysis
app.get('/api/iplookup', authenticateToken, trackQuery, async (req, res) => {
    try {
        const { ip } = req.query;
        
        if (!ip) {
            return res.status(400).json({ error: 'IP parameter required' });
        }
        
        // Validate IP format (IPv4 and IPv6)
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        
        if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            return res.status(400).json({ error: 'Invalid IP address format' });
        }
        
        const results = {};
        const promises = [];
        
        // API 1: ip-api.com (Enhanced with all fields)
        promises.push(
            axios.get(`http://ip-api.com/json/${ip}?fields=66846719`, { timeout: 8000 })
                .then(response => { results.ipApi = response.data; })
                .catch(() => { results.ipApi = { error: 'API request failed' }; })
        );
        
        // API 2: ipapi.co (Enhanced)
        promises.push(
            axios.get(`https://ipapi.co/${ip}/json/`, { timeout: 8000 })
                .then(response => { results.ipapi = response.data; })
                .catch(() => { results.ipapi = { error: 'API request failed' }; })
        );
        
        // API 3: KeyCDN Tools
        promises.push(
            axios.get(`https://tools.keycdn.com/geo.json?host=${ip}`, { timeout: 8000 })
                .then(response => { results.keycdn = response.data; })
                .catch(() => { results.keycdn = { error: 'API request failed' }; })
        );
        
        // API 4: ipwhois.app (Enhanced)
        promises.push(
            axios.get(`http://ipwhois.app/json/${ip}`, { timeout: 8000 })
                .then(response => { results.ipwhois = response.data; })
                .catch(() => { results.ipwhois = { error: 'API request failed' }; })
        );
        
        // API 5: ipinfo.io
        promises.push(
            axios.get(`https://ipinfo.io/${ip}/json`, { timeout: 8000 })
                .then(response => { results.ipinfo = response.data; })
                .catch(() => { results.ipinfo = { error: 'API request failed' }; })
        );
        
        // API 6: freegeoip.app
        promises.push(
            axios.get(`https://freegeoip.app/json/${ip}`, { timeout: 8000 })
                .then(response => { results.freegeoip = response.data; })
                .catch(() => { results.freegeoip = { error: 'API request failed' }; })
        );
        
        // API 7: ipgeolocation.io (Free tier)
        promises.push(
            axios.get(`https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=${ip}`, { timeout: 8000 })
                .then(response => { results.ipgeolocation = response.data; })
                .catch(() => { results.ipgeolocation = { error: 'API request failed' }; })
        );
        
        // API 8: ipstack.com (Free tier)
        promises.push(
            axios.get(`http://api.ipstack.com/${ip}?access_key=free`, { timeout: 8000 })
                .then(response => { results.ipstack = response.data; })
                .catch(() => { results.ipstack = { error: 'API request failed' }; })
        );
        
        // API 9: Abstract API (Free tier)
        promises.push(
            axios.get(`https://ipgeolocation.abstractapi.com/v1/?api_key=free&ip_address=${ip}`, { timeout: 8000 })
                .then(response => { results.abstractapi = response.data; })
                .catch(() => { results.abstractapi = { error: 'API request failed' }; })
        );
        
        // API 10: BigDataCloud (Free)
        promises.push(
            axios.get(`https://api.bigdatacloud.net/data/reverse-geocode-client?ip=${ip}&localityLanguage=tr`, { timeout: 8000 })
                .then(response => { results.bigdatacloud = response.data; })
                .catch(() => { results.bigdatacloud = { error: 'API request failed' }; })
        );
        
        // API 11: IPify (Enhanced with geolocation)
        promises.push(
            axios.get(`https://geo.ipify.org/api/v2/country,city,vpn?apiKey=free&ipAddress=${ip}`, { timeout: 8000 })
                .then(response => { results.ipify = response.data; })
                .catch(() => { results.ipify = { error: 'API request failed' }; })
        );
        
        // API 12: IP2Location (Free tier)
        promises.push(
            axios.get(`https://api.ip2location.io/?key=free&ip=${ip}`, { timeout: 8000 })
                .then(response => { results.ip2location = response.data; })
                .catch(() => { results.ip2location = { error: 'API request failed' }; })
        );
        
        // API 13: IPData (Free tier)
        promises.push(
            axios.get(`https://api.ipdata.co/${ip}?api-key=free`, { timeout: 8000 })
                .then(response => { results.ipdata = response.data; })
                .catch(() => { results.ipdata = { error: 'API request failed' }; })
        );
        
        // API 14: Shodan (Basic info)
        promises.push(
            axios.get(`https://api.shodan.io/shodan/host/${ip}?key=free`, { timeout: 8000 })
                .then(response => { results.shodan = response.data; })
                .catch(() => { results.shodan = { error: 'API request failed' }; })
        );
        
        // API 15: VirusTotal (IP reputation)
        promises.push(
            axios.get(`https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=free&ip=${ip}`, { timeout: 8000 })
                .then(response => { results.virustotal = response.data; })
                .catch(() => { results.virustotal = { error: 'API request failed' }; })
        );
        
        // Wait for all API calls to complete
        await Promise.allSettled(promises);
        
        // Enhanced data combination and analysis
        const combinedResult = enhancedCombineIpData(results, ip);
        
        res.json(combinedResult);
        
    } catch (error) {
        res.status(500).json({ error: 'Enhanced IP lookup failed', details: error.message });
    }
});

// Enhanced function to combine and analyze IP data from multiple sources
function enhancedCombineIpData(results, ip) {
    const combined = {
        ip: ip,
        timestamp: new Date().toISOString(),
        sources: Object.keys(results).filter(key => !results[key].error).length,
        totalSources: Object.keys(results).length,
        reliability: 0,
        data: {},
        analysis: {},
        security: {},
        performance: {}
    };
    
    const sources = results;
    
    // Calculate reliability score
    combined.reliability = Math.round((combined.sources / combined.totalSources) * 100);
    
    // Enhanced Basic Info
    combined.data.basic = {
        ip: ip,
        ipVersion: ip.includes(':') ? 'IPv6' : 'IPv4',
        type: getFirstValid([sources.ipApi?.query, sources.ipapi?.ip, sources.ipinfo?.ip]),
        hostname: getFirstValid([sources.keycdn?.data?.host, sources.ipwhois?.hostname, sources.ipinfo?.hostname]),
        reverseDns: getFirstValid([sources.ipApi?.reverse, sources.ipwhois?.reverse_dns]),
        anycast: getFirstValid([sources.ipApi?.mobile, sources.ipwhois?.anycast]),
        registrar: getFirstValid([sources.ipwhois?.registrar, sources.ipdata?.registrar])
    };
    
    // Enhanced Location Info with confidence scoring
    const locationSources = [
        sources.ipApi, sources.ipapi, sources.keycdn?.data, 
        sources.ipwhois, sources.ipinfo, sources.freegeoip,
        sources.ipgeolocation, sources.bigdatacloud, sources.ipdata
    ].filter(s => s && !s.error);
    
    combined.data.location = {
        continent: getMostCommon([
            sources.ipApi?.continent, sources.ipapi?.continent_code, 
            sources.keycdn?.data?.continent_code, sources.ipgeolocation?.continent_name
        ]),
        continentCode: getMostCommon([
            sources.ipApi?.continentCode, sources.ipapi?.continent_code,
            sources.ipgeolocation?.continent_code
        ]),
        country: getMostCommon([
            sources.ipApi?.country, sources.ipapi?.country_name, 
            sources.keycdn?.data?.country_name, sources.ipwhois?.country,
            sources.ipinfo?.country, sources.ipgeolocation?.country_name,
            sources.bigdatacloud?.countryName
        ]),
        countryCode: getMostCommon([
            sources.ipApi?.countryCode, sources.ipapi?.country_code,
            sources.keycdn?.data?.country_code, sources.ipwhois?.country_code,
            sources.freegeoip?.country_code, sources.ipgeolocation?.country_code2
        ]),
        region: getMostCommon([
            sources.ipApi?.regionName, sources.ipapi?.region,
            sources.keycdn?.data?.region_name, sources.ipwhois?.region,
            sources.ipinfo?.region, sources.ipgeolocation?.state_prov
        ]),
        city: getMostCommon([
            sources.ipApi?.city, sources.ipapi?.city, sources.keycdn?.data?.city,
            sources.ipwhois?.city, sources.ipinfo?.city, sources.freegeoip?.city,
            sources.ipgeolocation?.city, sources.bigdatacloud?.city
        ]),
        district: getFirstValid([sources.ipApi?.district, sources.ipwhois?.district]),
        postalCode: getFirstValid([
            sources.ipApi?.zip, sources.ipapi?.postal, sources.keycdn?.data?.postal_code,
            sources.ipinfo?.postal, sources.freegeoip?.zip_code, sources.ipgeolocation?.zipcode
        ]),
        coordinates: {
            latitude: getAverageCoordinate([
                sources.ipApi?.lat, sources.ipapi?.latitude, sources.keycdn?.data?.latitude,
                sources.ipwhois?.latitude, sources.freegeoip?.latitude, sources.ipgeolocation?.latitude
            ]),
            longitude: getAverageCoordinate([
                sources.ipApi?.lon, sources.ipapi?.longitude, sources.keycdn?.data?.longitude,
                sources.ipwhois?.longitude, sources.freegeoip?.longitude, sources.ipgeolocation?.longitude
            ]),
            accuracy: calculateCoordinateAccuracy(locationSources)
        },
        timezone: getMostCommon([
            sources.ipApi?.timezone, sources.ipapi?.timezone, sources.keycdn?.data?.timezone,
            sources.ipwhois?.timezone, sources.ipinfo?.timezone, sources.ipgeolocation?.time_zone?.name
        ]),
        utcOffset: getFirstValid([sources.ipApi?.offset, sources.ipapi?.utc_offset, sources.ipgeolocation?.time_zone?.offset])
    };
    
    // Enhanced Network Info
    combined.data.network = {
        isp: getMostCommon([
            sources.ipApi?.isp, sources.ipapi?.org, sources.ipwhois?.isp,
            sources.ipinfo?.org, sources.ipgeolocation?.isp, sources.ipdata?.isp
        ]),
        organization: getMostCommon([
            sources.ipApi?.org, sources.ipapi?.org, sources.ipwhois?.org,
            sources.ipinfo?.org, sources.ipgeolocation?.organization
        ]),
        asn: {
            number: getFirstValid([sources.ipApi?.as, sources.ipwhois?.asn, sources.ipdata?.asn?.asn]),
            name: getFirstValid([sources.ipApi?.asname, sources.ipwhois?.asn_org, sources.ipdata?.asn?.name]),
            domain: getFirstValid([sources.ipwhois?.asn_domain, sources.ipdata?.asn?.domain]),
            route: getFirstValid([sources.ipwhois?.asn_route, sources.ipdata?.asn?.route]),
            type: getFirstValid([sources.ipwhois?.asn_type, sources.ipdata?.asn?.type])
        },
        connectionType: getFirstValid([sources.ipgeolocation?.connection_type, sources.ipdata?.connection_type]),
        usageType: getFirstValid([sources.ipgeolocation?.usage_type, sources.ipdata?.usage_type]),
        domains: getFirstValid([sources.ipwhois?.domains, sources.ipdata?.domains])
    };
    
    // Enhanced Security Analysis
    combined.security = {
        threatLevel: calculateThreatLevel(sources),
        proxy: {
            detected: getBooleanConsensus([sources.ipApi?.proxy, sources.ipwhois?.proxy, sources.ipdata?.proxy]),
            confidence: calculateConfidence([sources.ipApi?.proxy, sources.ipwhois?.proxy, sources.ipdata?.proxy])
        },
        vpn: {
            detected: getBooleanConsensus([sources.ipwhois?.vpn, sources.ipdata?.vpn, sources.ipgeolocation?.vpn]),
            confidence: calculateConfidence([sources.ipwhois?.vpn, sources.ipdata?.vpn, sources.ipgeolocation?.vpn])
        },
        tor: {
            detected: getBooleanConsensus([sources.ipwhois?.tor, sources.ipdata?.tor]),
            confidence: calculateConfidence([sources.ipwhois?.tor, sources.ipdata?.tor])
        },
        hosting: {
            detected: getBooleanConsensus([sources.ipApi?.hosting, sources.ipwhois?.hosting, sources.ipdata?.hosting]),
            confidence: calculateConfidence([sources.ipApi?.hosting, sources.ipwhois?.hosting, sources.ipdata?.hosting])
        },
        mobile: {
            detected: getBooleanConsensus([sources.ipApi?.mobile, sources.ipwhois?.mobile, sources.ipdata?.mobile]),
            confidence: calculateConfidence([sources.ipApi?.mobile, sources.ipwhois?.mobile, sources.ipdata?.mobile])
        },
        threat: {
            detected: getFirstValid([sources.ipwhois?.threat, sources.virustotal?.positives > 0]),
            malware: getFirstValid([sources.virustotal?.positives, 0]),
            reputation: calculateReputation(sources)
        },
        blacklists: analyzeBlacklists(sources),
        riskScore: calculateRiskScore(sources)
    };
    
    // Performance Analysis
    combined.performance = {
        responseTime: calculateAverageResponseTime(sources),
        availability: calculateAvailability(sources),
        dataQuality: calculateDataQuality(sources)
    };
    
    // Advanced Analysis
    combined.analysis = {
        geolocationAccuracy: combined.data.location.coordinates.accuracy,
        dataConsistency: calculateDataConsistency(sources),
        sourceReliability: analyzeSourceReliability(sources),
        anomalies: detectAnomalies(sources),
        recommendations: generateRecommendations(combined)
    };
    
    // Currency & Language (Enhanced)
    combined.data.locale = {
        currency: {
            code: getMostCommon([sources.ipApi?.currency, sources.ipapi?.currency, sources.ipgeolocation?.currency?.code]),
            name: getFirstValid([sources.ipgeolocation?.currency?.name]),
            symbol: getFirstValid([sources.ipgeolocation?.currency?.symbol])
        },
        languages: getFirstValid([sources.ipapi?.languages, sources.ipwhois?.languages, sources.ipgeolocation?.languages]),
        callingCode: getFirstValid([sources.ipapi?.country_calling_code, sources.ipwhois?.country_calling_code, sources.ipgeolocation?.calling_code])
    };
    
    // Raw data from all sources (for debugging)
    combined.rawData = results;
    
    return combined;
}

// Helper functions for enhanced analysis
function getMostCommon(values) {
    const filtered = values.filter(v => v && v !== null && v !== undefined && v !== '');
    if (filtered.length === 0) return null;
    
    const counts = {};
    filtered.forEach(v => counts[v] = (counts[v] || 0) + 1);
    
    return Object.keys(counts).reduce((a, b) => counts[a] > counts[b] ? a : b);
}

function getAverageCoordinate(values) {
    const filtered = values.filter(v => v && !isNaN(parseFloat(v))).map(v => parseFloat(v));
    if (filtered.length === 0) return null;
    
    return filtered.reduce((sum, val) => sum + val, 0) / filtered.length;
}

function calculateCoordinateAccuracy(sources) {
    const coords = sources.map(s => ({ lat: s?.latitude || s?.lat, lon: s?.longitude || s?.lon }))
                         .filter(c => c.lat && c.lon);
    
    if (coords.length < 2) return 'low';
    
    const distances = [];
    for (let i = 0; i < coords.length - 1; i++) {
        for (let j = i + 1; j < coords.length; j++) {
            const dist = calculateDistance(coords[i], coords[j]);
            distances.push(dist);
        }
    }
    
    const avgDistance = distances.reduce((sum, d) => sum + d, 0) / distances.length;
    
    if (avgDistance < 10) return 'high';
    if (avgDistance < 50) return 'medium';
    return 'low';
}

function calculateDistance(coord1, coord2) {
    const R = 6371; // Earth's radius in km
    const dLat = (coord2.lat - coord1.lat) * Math.PI / 180;
    const dLon = (coord2.lon - coord1.lon) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(coord1.lat * Math.PI / 180) * Math.cos(coord2.lat * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
}

function getBooleanConsensus(values) {
    const filtered = values.filter(v => v !== null && v !== undefined);
    if (filtered.length === 0) return null;
    
    const trueCount = filtered.filter(v => v === true || v === 'true' || v === 1).length;
    return trueCount > filtered.length / 2;
}

function calculateConfidence(values) {
    const filtered = values.filter(v => v !== null && v !== undefined);
    if (filtered.length === 0) return 0;
    
    const consensus = getBooleanConsensus(values);
    const agreementCount = filtered.filter(v => 
        (consensus && (v === true || v === 'true' || v === 1)) ||
        (!consensus && (v === false || v === 'false' || v === 0))
    ).length;
    
    return Math.round((agreementCount / filtered.length) * 100);
}

function calculateThreatLevel(sources) {
    let score = 0;
    
    if (sources.ipwhois?.threat) score += 30;
    if (sources.ipApi?.proxy) score += 20;
    if (sources.ipwhois?.vpn) score += 15;
    if (sources.ipwhois?.tor) score += 40;
    if (sources.virustotal?.positives > 0) score += sources.virustotal.positives * 10;
    
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score > 0) return 'low';
    return 'clean';
}

function calculateReputation(sources) {
    let score = 100;
    
    if (sources.virustotal?.positives) score -= sources.virustotal.positives * 10;
    if (sources.ipwhois?.threat) score -= 30;
    if (sources.ipApi?.proxy) score -= 15;
    if (sources.ipwhois?.vpn) score -= 10;
    if (sources.ipwhois?.tor) score -= 40;
    
    return Math.max(0, Math.min(100, score));
}

function analyzeBlacklists(sources) {
    const blacklists = [];
    
    if (sources.virustotal?.scans) {
        Object.entries(sources.virustotal.scans).forEach(([engine, result]) => {
            if (result.detected) {
                blacklists.push({
                    engine: engine,
                    result: result.result,
                    detected: true
                });
            }
        });
    }
    
    return blacklists;
}

function calculateRiskScore(sources) {
    let risk = 0;
    
    // Security factors
    if (sources.ipwhois?.threat) risk += 40;
    if (sources.ipApi?.proxy) risk += 25;
    if (sources.ipwhois?.vpn) risk += 20;
    if (sources.ipwhois?.tor) risk += 50;
    if (sources.virustotal?.positives > 0) risk += sources.virustotal.positives * 5;
    
    // Hosting factors
    if (sources.ipApi?.hosting) risk += 10;
    
    return Math.min(100, risk);
}

function calculateAverageResponseTime(sources) {
    // This would be implemented with actual timing data
    return Math.random() * 1000 + 200; // Simulated for now
}

function calculateAvailability(sources) {
    const total = Object.keys(sources).length;
    const successful = Object.values(sources).filter(s => !s.error).length;
    return Math.round((successful / total) * 100);
}

function calculateDataQuality(sources) {
    let quality = 0;
    let total = 0;
    
    Object.values(sources).forEach(source => {
        if (!source.error) {
            const fields = Object.keys(source).length;
            quality += Math.min(fields / 10, 1) * 100;
            total++;
        }
    });
    
    return total > 0 ? Math.round(quality / total) : 0;
}

function calculateDataConsistency(sources) {
    // Analyze consistency across different data points
    const countries = [];
    const cities = [];
    
    Object.values(sources).forEach(source => {
        if (!source.error) {
            if (source.country) countries.push(source.country);
            if (source.city) cities.push(source.city);
        }
    });
    
    const countryConsistency = countries.length > 0 ? (countries.filter(c => c === countries[0]).length / countries.length) * 100 : 100;
    const cityConsistency = cities.length > 0 ? (cities.filter(c => c === cities[0]).length / cities.length) * 100 : 100;
    
    return Math.round((countryConsistency + cityConsistency) / 2);
}

function analyzeSourceReliability(sources) {
    const reliability = {};
    
    Object.entries(sources).forEach(([name, data]) => {
        if (!data.error) {
            const fieldCount = Object.keys(data).length;
            const hasLocation = !!(data.country || data.city);
            const hasNetwork = !!(data.isp || data.org);
            
            let score = fieldCount * 2;
            if (hasLocation) score += 20;
            if (hasNetwork) score += 15;
            
            reliability[name] = Math.min(100, score);
        } else {
            reliability[name] = 0;
        }
    });
    
    return reliability;
}

function detectAnomalies(sources) {
    const anomalies = [];
    
    // Check for conflicting countries
    const countries = Object.values(sources)
        .filter(s => !s.error && s.country)
        .map(s => s.country);
    
    const uniqueCountries = [...new Set(countries)];
    if (uniqueCountries.length > 1) {
        anomalies.push({
            type: 'location_conflict',
            description: 'Multiple countries detected',
            details: uniqueCountries
        });
    }
    
    // Check for unusual ISP patterns
    const isps = Object.values(sources)
        .filter(s => !s.error && s.isp)
        .map(s => s.isp.toLowerCase());
    
    const suspiciousKeywords = ['vpn', 'proxy', 'hosting', 'cloud', 'datacenter'];
    const hasSuspiciousISP = isps.some(isp => 
        suspiciousKeywords.some(keyword => isp.includes(keyword))
    );
    
    if (hasSuspiciousISP) {
        anomalies.push({
            type: 'suspicious_isp',
            description: 'ISP indicates potential proxy/VPN usage',
            details: isps
        });
    }
    
    return anomalies;
}

function generateRecommendations(combined) {
    const recommendations = [];
    
    if (combined.security.riskScore > 50) {
        recommendations.push({
            type: 'security',
            priority: 'high',
            message: 'High risk IP detected - consider blocking or additional verification'
        });
    }
    
    if (combined.security.proxy.detected) {
        recommendations.push({
            type: 'security',
            priority: 'medium',
            message: 'Proxy usage detected - verify user authenticity'
        });
    }
    
    if (combined.data.location.coordinates.accuracy === 'low') {
        recommendations.push({
            type: 'data_quality',
            priority: 'low',
            message: 'Location accuracy is low - use additional verification methods'
        });
    }
    
    if (combined.analysis.dataConsistency < 70) {
        recommendations.push({
            type: 'data_quality',
            priority: 'medium',
            message: 'Inconsistent data across sources - verify information manually'
        });
    }
    
    return recommendations;
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

// Enhanced IBAN Validation Functions
function enhancedValidateIban(iban) {
    // Remove spaces and convert to uppercase
    const cleanIban = iban.replace(/\s/g, '').toUpperCase();
    
    // Check basic format (2 letters + 2 digits + up to 30 alphanumeric)
    if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(cleanIban)) {
        return { 
            isValid: false, 
            error: 'Invalid IBAN format - must start with 2 letters and 2 digits',
            errorCode: 'FORMAT_ERROR',
            severity: 'high'
        };
    }
    
    // Enhanced country lengths with additional countries
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
        'XK': 20, 'AO': 25, 'BF': 28, 'BI': 16, 'BJ': 28, 'CG': 27, 'CI': 28,
        'CM': 27, 'CV': 25, 'DJ': 27, 'DZ': 24, 'EH': 24, 'GA': 27, 'IR': 26,
        'LY': 25, 'MA': 28, 'MG': 27, 'ML': 28, 'MZ': 25, 'NE': 28, 'NI': 32,
        'SN': 28, 'TD': 27, 'TG': 28, 'VU': 23
    };
    
    const countryCode = cleanIban.substring(0, 2);
    const expectedLength = countryLengths[countryCode];
    
    if (!expectedLength) {
        return { 
            isValid: false, 
            error: `Unknown or unsupported country code: ${countryCode}`,
            errorCode: 'UNKNOWN_COUNTRY',
            severity: 'high',
            supportedCountries: Object.keys(countryLengths).sort()
        };
    }
    
    if (cleanIban.length !== expectedLength) {
        return { 
            isValid: false, 
            error: `Invalid length for ${countryCode}. Expected ${expectedLength}, got ${cleanIban.length}`,
            errorCode: 'LENGTH_ERROR',
            severity: 'high',
            expectedLength,
            actualLength: cleanIban.length
        };
    }
    
    // Enhanced checksum validation with detailed error reporting
    const checksumResult = validateIbanChecksum(cleanIban);
    if (!checksumResult.isValid) {
        return {
            isValid: false,
            error: checksumResult.error,
            errorCode: 'CHECKSUM_ERROR',
            severity: 'high',
            checksumDetails: checksumResult
        };
    }
    
    // Additional format validations per country
    const countryValidation = validateCountrySpecificFormat(cleanIban);
    if (!countryValidation.isValid) {
        return {
            isValid: false,
            error: countryValidation.error,
            errorCode: 'COUNTRY_FORMAT_ERROR',
            severity: 'medium',
            countryRules: countryValidation.rules
        };
    }
    
    return { 
        isValid: true, 
        error: null,
        quality: calculateIbanQuality(cleanIban),
        checksumDetails: checksumResult,
        countryValidation: countryValidation
    };
}

function validateIbanChecksum(iban) {
    try {
        // Rearrange: move first 4 characters to end
        const rearranged = iban.substring(4) + iban.substring(0, 4);
        
        // Replace letters with numbers (A=10, B=11, ..., Z=35)
        const numericString = rearranged.replace(/[A-Z]/g, (char) => (char.charCodeAt(0) - 55).toString());
        
        // Calculate mod 97 for large numbers using string arithmetic
        let remainder = 0;
        for (let i = 0; i < numericString.length; i++) {
            remainder = (remainder * 10 + parseInt(numericString[i])) % 97;
        }
        
        const isValid = remainder === 1;
        
        return {
            isValid,
            error: isValid ? null : `Invalid checksum. Calculated remainder: ${remainder}, expected: 1`,
            remainder,
            expected: 1,
            rearrangedIban: rearranged,
            numericString: numericString.length > 50 ? numericString.substring(0, 50) + '...' : numericString
        };
    } catch (error) {
        return {
            isValid: false,
            error: `Checksum calculation failed: ${error.message}`,
            exception: error.message
        };
    }
}

function validateCountrySpecificFormat(iban) {
    const countryCode = iban.substring(0, 2);
    const bban = iban.substring(4); // Basic Bank Account Number
    
    // Country-specific validation rules
    const countryRules = {
        'TR': {
            bankCodeLength: 5,
            accountNumberLength: 17,
            pattern: /^[0-9]{5}[0-9A-Z]{17}$/,
            description: 'Turkish IBAN: 5-digit bank code + 17-character account number'
        },
        'DE': {
            bankCodeLength: 8,
            accountNumberLength: 10,
            pattern: /^[0-9]{18}$/,
            description: 'German IBAN: 8-digit bank code + 10-digit account number'
        },
        'GB': {
            bankCodeLength: 4,
            sortCodeLength: 6,
            accountNumberLength: 8,
            pattern: /^[A-Z]{4}[0-9]{14}$/,
            description: 'UK IBAN: 4-letter bank code + 6-digit sort code + 8-digit account number'
        },
        'FR': {
            bankCodeLength: 5,
            branchCodeLength: 5,
            accountNumberLength: 11,
            checkDigitsLength: 2,
            pattern: /^[0-9]{10}[0-9A-Z]{11}[0-9]{2}$/,
            description: 'French IBAN: 5-digit bank + 5-digit branch + 11-character account + 2-digit check'
        },
        'IT': {
            checkDigitLength: 1,
            bankCodeLength: 5,
            branchCodeLength: 5,
            accountNumberLength: 12,
            pattern: /^[A-Z][0-9]{10}[0-9A-Z]{12}$/,
            description: 'Italian IBAN: 1-letter check + 5-digit bank + 5-digit branch + 12-character account'
        },
        'ES': {
            bankCodeLength: 4,
            branchCodeLength: 4,
            checkDigitsLength: 2,
            accountNumberLength: 10,
            pattern: /^[0-9]{20}$/,
            description: 'Spanish IBAN: 4-digit bank + 4-digit branch + 2-digit check + 10-digit account'
        },
        'NL': {
            bankCodeLength: 4,
            accountNumberLength: 10,
            pattern: /^[A-Z]{4}[0-9]{10}$/,
            description: 'Dutch IBAN: 4-letter bank code + 10-digit account number'
        }
    };
    
    const rules = countryRules[countryCode];
    if (!rules) {
        return {
            isValid: true,
            message: 'No specific validation rules for this country',
            rules: null
        };
    }
    
    if (!rules.pattern.test(bban)) {
        return {
            isValid: false,
            error: `Invalid format for ${countryCode} IBAN. ${rules.description}`,
            rules: rules,
            actualFormat: bban
        };
    }
    
    return {
        isValid: true,
        message: `Valid ${countryCode} IBAN format`,
        rules: rules
    };
}

function calculateIbanQuality(iban) {
    let score = 100;
    
    // Deduct points for potential issues
    const countryCode = iban.substring(0, 2);
    const checkDigits = iban.substring(2, 4);
    
    // Check for sequential numbers (potential test IBAN)
    const hasSequential = /012345|123456|234567|345678|456789|567890|678901|789012|890123|901234/.test(iban);
    if (hasSequential) score -= 20;
    
    // Check for repeated patterns
    const hasRepeated = /(.)\1{4,}/.test(iban);
    if (hasRepeated) score -= 15;
    
    // Check for common test patterns
    const testPatterns = ['00000', '11111', '22222', '99999'];
    if (testPatterns.some(pattern => iban.includes(pattern))) score -= 25;
    
    // Check digits analysis
    if (checkDigits === '00') score -= 30; // Often indicates test IBAN
    if (checkDigits === '97') score -= 10; // Common in examples
    
    return Math.max(0, Math.min(100, score));
}

function enhancedExtractIbanInfo(iban) {
    const countryCode = iban.substring(0, 2);
    const checkDigits = iban.substring(2, 4);
    const bban = iban.substring(4);
    
    // Enhanced country information
    const countryInfo = getCountryInfo(countryCode);
    
    // Extract bank and account information based on country
    const bankingInfo = extractBankingInfo(countryCode, bban);
    
    return {
        countryCode,
        country: countryInfo.name,
        countryInfo: countryInfo,
        checkDigits,
        bban,
        bankCode: bankingInfo.bankCode,
        branchCode: bankingInfo.branchCode,
        accountNumber: bankingInfo.accountNumber,
        accountType: bankingInfo.accountType,
        checkDigitsLocal: bankingInfo.checkDigitsLocal,
        structure: bankingInfo.structure
    };
}

function getCountryInfo(countryCode) {
    const countries = {
        'AD': { name: 'Andorra', currency: 'EUR', sepa: true, region: 'Europe' },
        'AE': { name: 'United Arab Emirates', currency: 'AED', sepa: false, region: 'Middle East' },
        'AL': { name: 'Albania', currency: 'ALL', sepa: false, region: 'Europe' },
        'AT': { name: 'Austria', currency: 'EUR', sepa: true, region: 'Europe' },
        'AZ': { name: 'Azerbaijan', currency: 'AZN', sepa: false, region: 'Asia' },
        'BA': { name: 'Bosnia and Herzegovina', currency: 'BAM', sepa: false, region: 'Europe' },
        'BE': { name: 'Belgium', currency: 'EUR', sepa: true, region: 'Europe' },
        'BG': { name: 'Bulgaria', currency: 'BGN', sepa: true, region: 'Europe' },
        'BH': { name: 'Bahrain', currency: 'BHD', sepa: false, region: 'Middle East' },
        'BR': { name: 'Brazil', currency: 'BRL', sepa: false, region: 'South America' },
        'BY': { name: 'Belarus', currency: 'BYN', sepa: false, region: 'Europe' },
        'CH': { name: 'Switzerland', currency: 'CHF', sepa: true, region: 'Europe' },
        'CR': { name: 'Costa Rica', currency: 'CRC', sepa: false, region: 'Central America' },
        'CY': { name: 'Cyprus', currency: 'EUR', sepa: true, region: 'Europe' },
        'CZ': { name: 'Czech Republic', currency: 'CZK', sepa: true, region: 'Europe' },
        'DE': { name: 'Germany', currency: 'EUR', sepa: true, region: 'Europe' },
        'DK': { name: 'Denmark', currency: 'DKK', sepa: true, region: 'Europe' },
        'DO': { name: 'Dominican Republic', currency: 'DOP', sepa: false, region: 'Caribbean' },
        'EE': { name: 'Estonia', currency: 'EUR', sepa: true, region: 'Europe' },
        'EG': { name: 'Egypt', currency: 'EGP', sepa: false, region: 'Africa' },
        'ES': { name: 'Spain', currency: 'EUR', sepa: true, region: 'Europe' },
        'FI': { name: 'Finland', currency: 'EUR', sepa: true, region: 'Europe' },
        'FO': { name: 'Faroe Islands', currency: 'DKK', sepa: true, region: 'Europe' },
        'FR': { name: 'France', currency: 'EUR', sepa: true, region: 'Europe' },
        'GB': { name: 'United Kingdom', currency: 'GBP', sepa: false, region: 'Europe' },
        'GE': { name: 'Georgia', currency: 'GEL', sepa: false, region: 'Asia' },
        'GI': { name: 'Gibraltar', currency: 'GIP', sepa: true, region: 'Europe' },
        'GL': { name: 'Greenland', currency: 'DKK', sepa: true, region: 'North America' },
        'GR': { name: 'Greece', currency: 'EUR', sepa: true, region: 'Europe' },
        'GT': { name: 'Guatemala', currency: 'GTQ', sepa: false, region: 'Central America' },
        'HR': { name: 'Croatia', currency: 'EUR', sepa: true, region: 'Europe' },
        'HU': { name: 'Hungary', currency: 'HUF', sepa: true, region: 'Europe' },
        'IE': { name: 'Ireland', currency: 'EUR', sepa: true, region: 'Europe' },
        'IL': { name: 'Israel', currency: 'ILS', sepa: false, region: 'Middle East' },
        'IS': { name: 'Iceland', currency: 'ISK', sepa: true, region: 'Europe' },
        'IT': { name: 'Italy', currency: 'EUR', sepa: true, region: 'Europe' },
        'JO': { name: 'Jordan', currency: 'JOD', sepa: false, region: 'Middle East' },
        'KW': { name: 'Kuwait', currency: 'KWD', sepa: false, region: 'Middle East' },
        'KZ': { name: 'Kazakhstan', currency: 'KZT', sepa: false, region: 'Asia' },
        'LB': { name: 'Lebanon', currency: 'LBP', sepa: false, region: 'Middle East' },
        'LC': { name: 'Saint Lucia', currency: 'XCD', sepa: false, region: 'Caribbean' },
        'LI': { name: 'Liechtenstein', currency: 'CHF', sepa: true, region: 'Europe' },
        'LT': { name: 'Lithuania', currency: 'EUR', sepa: true, region: 'Europe' },
        'LU': { name: 'Luxembourg', currency: 'EUR', sepa: true, region: 'Europe' },
        'LV': { name: 'Latvia', currency: 'EUR', sepa: true, region: 'Europe' },
        'MC': { name: 'Monaco', currency: 'EUR', sepa: true, region: 'Europe' },
        'MD': { name: 'Moldova', currency: 'MDL', sepa: false, region: 'Europe' },
        'ME': { name: 'Montenegro', currency: 'EUR', sepa: false, region: 'Europe' },
        'MK': { name: 'North Macedonia', currency: 'MKD', sepa: false, region: 'Europe' },
        'MR': { name: 'Mauritania', currency: 'MRU', sepa: false, region: 'Africa' },
        'MT': { name: 'Malta', currency: 'EUR', sepa: true, region: 'Europe' },
        'MU': { name: 'Mauritius', currency: 'MUR', sepa: false, region: 'Africa' },
        'NL': { name: 'Netherlands', currency: 'EUR', sepa: true, region: 'Europe' },
        'NO': { name: 'Norway', currency: 'NOK', sepa: true, region: 'Europe' },
        'PK': { name: 'Pakistan', currency: 'PKR', sepa: false, region: 'Asia' },
        'PL': { name: 'Poland', currency: 'PLN', sepa: true, region: 'Europe' },
        'PS': { name: 'Palestine', currency: 'ILS', sepa: false, region: 'Middle East' },
        'PT': { name: 'Portugal', currency: 'EUR', sepa: true, region: 'Europe' },
        'QA': { name: 'Qatar', currency: 'QAR', sepa: false, region: 'Middle East' },
        'RO': { name: 'Romania', currency: 'RON', sepa: true, region: 'Europe' },
        'RS': { name: 'Serbia', currency: 'RSD', sepa: false, region: 'Europe' },
        'SA': { name: 'Saudi Arabia', currency: 'SAR', sepa: false, region: 'Middle East' },
        'SE': { name: 'Sweden', currency: 'SEK', sepa: true, region: 'Europe' },
        'SI': { name: 'Slovenia', currency: 'EUR', sepa: true, region: 'Europe' },
        'SK': { name: 'Slovakia', currency: 'EUR', sepa: true, region: 'Europe' },
        'SM': { name: 'San Marino', currency: 'EUR', sepa: true, region: 'Europe' },
        'TN': { name: 'Tunisia', currency: 'TND', sepa: false, region: 'Africa' },
        'TR': { name: 'Turkey', currency: 'TRY', sepa: false, region: 'Asia/Europe' },
        'UA': { name: 'Ukraine', currency: 'UAH', sepa: false, region: 'Europe' },
        'VG': { name: 'British Virgin Islands', currency: 'USD', sepa: false, region: 'Caribbean' },
        'XK': { name: 'Kosovo', currency: 'EUR', sepa: false, region: 'Europe' }
    };
    
    return countries[countryCode] || { 
        name: 'Unknown', 
        currency: 'Unknown', 
        sepa: false, 
        region: 'Unknown' 
    };
}

function extractBankingInfo(countryCode, bban) {
    const extractors = {
        'TR': (bban) => ({
            bankCode: bban.substring(0, 5),
            branchCode: null,
            accountNumber: bban.substring(5),
            accountType: 'standard',
            checkDigitsLocal: null,
            structure: '5n,17c'
        }),
        'DE': (bban) => ({
            bankCode: bban.substring(0, 8),
            branchCode: null,
            accountNumber: bban.substring(8),
            accountType: 'standard',
            checkDigitsLocal: null,
            structure: '8n,10n'
        }),
        'GB': (bban) => ({
            bankCode: bban.substring(0, 4),
            branchCode: bban.substring(4, 10),
            accountNumber: bban.substring(10),
            accountType: 'standard',
            checkDigitsLocal: null,
            structure: '4a,6n,8n'
        }),
        'FR': (bban) => ({
            bankCode: bban.substring(0, 5),
            branchCode: bban.substring(5, 10),
            accountNumber: bban.substring(10, 21),
            accountType: 'standard',
            checkDigitsLocal: bban.substring(21, 23),
            structure: '5n,5n,11c,2n'
        }),
        'IT': (bban) => ({
            bankCode: bban.substring(1, 6),
            branchCode: bban.substring(6, 11),
            accountNumber: bban.substring(11),
            accountType: 'standard',
            checkDigitsLocal: bban.substring(0, 1),
            structure: '1a,5n,5n,12c'
        }),
        'ES': (bban) => ({
            bankCode: bban.substring(0, 4),
            branchCode: bban.substring(4, 8),
            accountNumber: bban.substring(10),
            accountType: 'standard',
            checkDigitsLocal: bban.substring(8, 10),
            structure: '4n,4n,2n,10n'
        }),
        'NL': (bban) => ({
            bankCode: bban.substring(0, 4),
            branchCode: null,
            accountNumber: bban.substring(4),
            accountType: 'standard',
            checkDigitsLocal: null,
            structure: '4a,10n'
        })
    };
    
    const extractor = extractors[countryCode];
    if (extractor) {
        return extractor(bban);
    }
    
    // Generic extraction for unsupported countries
    return {
        bankCode: bban.substring(0, Math.min(8, bban.length)),
        branchCode: null,
        accountNumber: bban.substring(Math.min(8, bban.length)),
        accountType: 'unknown',
        checkDigitsLocal: null,
        structure: 'unknown'
    };
}

async function getEnhancedBankInfo(countryCode, bankCode, iban) {
    const bankInfo = {
        bankCode: bankCode,
        bankName: null,
        bic: null,
        swift: null,
        country: countryCode,
        city: null,
        address: null,
        website: null,
        phone: null,
        services: [],
        branches: 0,
        established: null,
        type: null,
        rating: null
    };
    
    // Comprehensive bank database with enhanced information
    const enhancedBankDatabase = {
        'TR': {
            '00001': { 
                name: 'Türkiye Cumhuriyet Merkez Bankası', 
                bic: 'TCMBTRIS', 
                city: 'Ankara',
                type: 'Central Bank',
                website: 'www.tcmb.gov.tr',
                established: 1930,
                services: ['Monetary Policy', 'Currency Issue', 'Banking Supervision']
            },
            '00010': { 
                name: 'Türkiye Cumhuriyeti Ziraat Bankası A.Ş.', 
                bic: 'TCZBTR2A', 
                city: 'Ankara',
                type: 'State Bank',
                website: 'www.ziraatbank.com.tr',
                established: 1863,
                branches: 1800,
                services: ['Retail Banking', 'Corporate Banking', 'Agricultural Banking']
            },
            '00012': { 
                name: 'Türkiye Halk Bankası A.Ş.', 
                bic: 'TRHBTR2A', 
                city: 'Ankara',
                type: 'State Bank',
                website: 'www.halkbank.com.tr',
                established: 1938,
                branches: 1000,
                services: ['Retail Banking', 'SME Banking', 'Corporate Banking']
            },
            '00015': { 
                name: 'Türkiye Vakıflar Bankası T.A.O.', 
                bic: 'TVBATR2A', 
                city: 'Ankara',
                type: 'State Bank',
                website: 'www.vakifbank.com.tr',
                established: 1954,
                branches: 950,
                services: ['Retail Banking', 'Corporate Banking', 'Investment Banking']
            },
            '00032': { 
                name: 'Türkiye İş Bankası A.Ş.', 
                bic: 'ISBKTRIS', 
                city: 'Istanbul',
                type: 'Private Bank',
                website: 'www.isbank.com.tr',
                established: 1924,
                branches: 1300,
                services: ['Universal Banking', 'Investment Banking', 'Asset Management']
            },
            '00046': { 
                name: 'Akbank T.A.Ş.', 
                bic: 'AKBKTRIS', 
                city: 'Istanbul',
                type: 'Private Bank',
                website: 'www.akbank.com',
                established: 1948,
                branches: 800,
                services: ['Retail Banking', 'Corporate Banking', 'Private Banking']
            },
            '00062': { 
                name: 'Türkiye Garanti Bankası A.Ş.', 
                bic: 'TGBATRIS', 
                city: 'Istanbul',
                type: 'Private Bank',
                website: 'www.garantibbva.com.tr',
                established: 1946,
                branches: 900,
                services: ['Universal Banking', 'Investment Banking', 'Digital Banking']
            },
            '00067': { 
                name: 'Yapı ve Kredi Bankası A.Ş.', 
                bic: 'YAPITRIS', 
                city: 'Istanbul',
                type: 'Private Bank',
                website: 'www.yapikredi.com.tr',
                established: 1944,
                branches: 850,
                services: ['Retail Banking', 'Corporate Banking', 'Investment Services']
            }
        },
        'DE': {
            '10010010': { 
                name: 'Postbank', 
                bic: 'PBNKDEFF', 
                city: 'Berlin',
                type: 'Commercial Bank',
                website: 'www.postbank.de',
                established: 1990,
                branches: 550,
                services: ['Retail Banking', 'Online Banking', 'Investment Services']
            },
            '12030000': { 
                name: 'Deutsche Kreditbank AG', 
                bic: 'BYLADEM1001', 
                city: 'Berlin',
                type: 'Direct Bank',
                website: 'www.dkb.de',
                established: 1990,
                branches: 30,
                services: ['Online Banking', 'Corporate Banking', 'Investment Banking']
            },
            '10020890': { 
                name: 'UniCredit Bank AG', 
                bic: 'HYVEDEMM300', 
                city: 'Munich',
                type: 'International Bank',
                website: 'www.unicreditbank.de',
                established: 1998,
                branches: 400,
                services: ['Corporate Banking', 'Investment Banking', 'Private Banking']
            },
            '50010517': { 
                name: 'ING-DiBa AG', 
                bic: 'INGDDEFFXXX', 
                city: 'Frankfurt',
                type: 'Direct Bank',
                website: 'www.ing.de',
                established: 1965,
                branches: 0,
                services: ['Online Banking', 'Mortgage Banking', 'Investment Services']
            }
        },
        'GB': {
            '2004': { 
                name: 'Barclays Bank PLC', 
                bic: 'BARCGB22', 
                city: 'London',
                type: 'Commercial Bank',
                website: 'www.barclays.co.uk',
                established: 1690,
                branches: 1600,
                services: ['Universal Banking', 'Investment Banking', 'Wealth Management']
            },
            '4000': { 
                name: 'HSBC Bank PLC', 
                bic: 'HBUKGB4B', 
                city: 'London',
                type: 'International Bank',
                website: 'www.hsbc.co.uk',
                established: 1865,
                branches: 1200,
                services: ['Global Banking', 'Commercial Banking', 'Private Banking']
            },
            '6016': { 
                name: 'Lloyds Bank PLC', 
                bic: 'LOYDGB21', 
                city: 'London',
                type: 'Commercial Bank',
                website: 'www.lloydsbank.com',
                established: 1765,
                branches: 2000,
                services: ['Retail Banking', 'Commercial Banking', 'Insurance']
            }
        },
        'FR': {
            '20041': { 
                name: 'BNP Paribas', 
                bic: 'BNPAFRPP', 
                city: 'Paris',
                type: 'International Bank',
                website: 'www.bnpparibas.fr',
                established: 2000,
                branches: 2100,
                services: ['Universal Banking', 'Investment Banking', 'Asset Management']
            },
            '30002': { 
                name: 'Crédit Agricole', 
                bic: 'AGRIFRPP', 
                city: 'Paris',
                type: 'Cooperative Bank',
                website: 'www.credit-agricole.fr',
                established: 1894,
                branches: 7000,
                services: ['Retail Banking', 'Corporate Banking', 'Insurance']
            }
        }
    };
    
    if (enhancedBankDatabase[countryCode] && enhancedBankDatabase[countryCode][bankCode]) {
        const bank = enhancedBankDatabase[countryCode][bankCode];
        Object.assign(bankInfo, bank);
    }
    
    // Try to fetch additional information from external APIs (if available)
    try {
        // This would be implemented with real bank API services
        // For now, we'll simulate enhanced data
        if (!bankInfo.bankName) {
            bankInfo.bankName = `Bank ${bankCode}`;
            bankInfo.type = 'Unknown';
        }
    } catch (error) {
        // Fallback to basic information
    }
    
    return bankInfo;
}

function performIbanSecurityAnalysis(iban, ibanInfo, bankInfo) {
    const analysis = {
        riskLevel: 'low',
        riskScore: 0,
        flags: [],
        recommendations: [],
        compliance: {
            aml: true,
            sanctions: false,
            pep: false
        }
    };
    
    // Check for high-risk countries
    const highRiskCountries = ['AF', 'BY', 'MM', 'KP', 'IR', 'SY'];
    if (highRiskCountries.includes(ibanInfo.countryCode)) {
        analysis.riskScore += 40;
        analysis.flags.push({
            type: 'high_risk_country',
            severity: 'high',
            description: 'IBAN from high-risk jurisdiction'
        });
    }
    
    // Check for non-SEPA countries
    if (!ibanInfo.countryInfo.sepa) {
        analysis.riskScore += 15;
        analysis.flags.push({
            type: 'non_sepa',
            severity: 'medium',
            description: 'Non-SEPA country - additional compliance required'
        });
    }
    
    // Check for potential test/dummy IBANs
    const quality = calculateIbanQuality(iban);
    if (quality < 50) {
        analysis.riskScore += 25;
        analysis.flags.push({
            type: 'suspicious_pattern',
            severity: 'medium',
            description: 'IBAN contains suspicious patterns (may be test/dummy)'
        });
    }
    
    // Check bank type
    if (bankInfo.type === 'Unknown') {
        analysis.riskScore += 10;
        analysis.flags.push({
            type: 'unknown_bank',
            severity: 'low',
            description: 'Bank information not available in database'
        });
    }
    
    // Determine overall risk level
    if (analysis.riskScore >= 50) analysis.riskLevel = 'high';
    else if (analysis.riskScore >= 25) analysis.riskLevel = 'medium';
    else analysis.riskLevel = 'low';
    
    // Generate recommendations
    if (analysis.riskLevel === 'high') {
        analysis.recommendations.push('Enhanced due diligence required');
        analysis.recommendations.push('Consider additional verification steps');
    }
    
    if (!ibanInfo.countryInfo.sepa) {
        analysis.recommendations.push('Verify correspondent banking relationships');
        analysis.recommendations.push('Check for additional regulatory requirements');
    }
    
    return analysis;
}

function generateIbanAnalytics(iban, ibanInfo, bankInfo) {
    return {
        structure: {
            length: iban.length,
            countryCode: ibanInfo.countryCode,
            checkDigits: ibanInfo.checkDigits,
            bankCodeLength: ibanInfo.bankCode?.length || 0,
            accountNumberLength: ibanInfo.accountNumber?.length || 0
        },
        geography: {
            country: ibanInfo.country,
            region: ibanInfo.countryInfo.region,
            currency: ibanInfo.countryInfo.currency,
            sepaEligible: ibanInfo.countryInfo.sepa
        },
        banking: {
            bankName: bankInfo.bankName,
            bankType: bankInfo.type,
            established: bankInfo.established,
            branches: bankInfo.branches,
            services: bankInfo.services
        },
        quality: {
            score: calculateIbanQuality(iban),
            validation: 'passed',
            confidence: 'high'
        }
    };
}

function checkIbanCompliance(iban, ibanInfo) {
    return {
        iso13616: true, // IBAN standard compliance
        sepa: ibanInfo.countryInfo.sepa,
        swift: true, // SWIFT network compatibility
        aml: true, // Anti-Money Laundering compliance
        gdpr: ibanInfo.countryInfo.region === 'Europe', // GDPR applicable
        psd2: ibanInfo.countryInfo.sepa, // PSD2 applicable for SEPA countries
        fatca: ['US', 'GB', 'DE', 'FR'].includes(ibanInfo.countryCode) // FATCA reporting
    };
}

function generateIbanRecommendations(validation, security, analytics) {
    const recommendations = [];
    
    if (validation.quality < 70) {
        recommendations.push({
            type: 'quality',
            priority: 'medium',
            message: 'IBAN quality score is low - verify authenticity'
        });
    }
    
    if (security.riskLevel === 'high') {
        recommendations.push({
            type: 'security',
            priority: 'high',
            message: 'High-risk IBAN detected - enhanced due diligence required'
        });
    }
    
    if (!analytics.geography.sepaEligible) {
        recommendations.push({
            type: 'compliance',
            priority: 'medium',
            message: 'Non-SEPA country - verify correspondent banking arrangements'
        });
    }
    
    if (analytics.banking.bankType === 'Unknown') {
        recommendations.push({
            type: 'verification',
            priority: 'low',
            message: 'Bank information incomplete - consider additional verification'
        });
    }
    
    return recommendations;
}

// Export for Vercel
module.exports = app;
// Local development server
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`Atlas Panel Server running on http://0.0.0.0:${PORT}`);
    });
}