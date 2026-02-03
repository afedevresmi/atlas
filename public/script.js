// Global Variables
let authToken = null;
let currentUser = null;
let stats = {
    global: { totalQueries: 0, successfulQueries: 0, failedQueries: 0, totalUsers: 0 },
    user: { total: 0, successful: 0, failed: 0 }
};

// Initialize App
document.addEventListener('DOMContentLoaded', function() {
    // Initialize AOS animations
    AOS.init({
        duration: 800,
        easing: 'ease-out-cubic',
        once: true
    });
    
    // Check stored credentials
    authToken = localStorage.getItem('atlasToken');
    const storedUser = localStorage.getItem('atlasUser');
    
    if (authToken && storedUser) {
        try {
            currentUser = JSON.parse(storedUser);
            showMainPanel();
            loadStats();
            return;
        } catch (e) {
            localStorage.clear();
        }
    }
    
    showLoginScreen();
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Logout button
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const page = this.getAttribute('data-page');
            showPage(page);
            
            // Update active nav
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Enter key for inputs
    document.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const activeElement = document.activeElement;
            if (activeElement.tagName === 'INPUT') {
                const page = activeElement.closest('.page');
                if (page) {
                    const queryBtn = page.querySelector('.query-btn');
                    if (queryBtn) queryBtn.click();
                }
            }
        }
    });
}

// Authentication Functions
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const loginBtn = document.querySelector('.login-btn');
    const btnText = document.querySelector('.btn-text');
    const btnLoader = document.querySelector('.btn-loader');
    
    if (!username || !password) {
        showError('Kullanıcı adı ve şifre gereklidir!');
        return;
    }
    
    // Show loading
    loginBtn.disabled = true;
    btnText.classList.add('hidden');
    btnLoader.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            authToken = data.token;
            currentUser = data.user;
            localStorage.setItem('atlasToken', authToken);
            localStorage.setItem('atlasUser', JSON.stringify(currentUser));
            
            setTimeout(() => {
                showMainPanel();
                loadStats();
                showToast('Giriş başarılı! Hoş geldiniz.', 'success');
            }, 500);
        } else {
            showError(data.error || 'Giriş başarısız!');
        }
    } catch (error) {
        showError('Bağlantı hatası! Lütfen tekrar deneyin.');
    } finally {
        loginBtn.disabled = false;
        btnText.classList.remove('hidden');
        btnLoader.classList.add('hidden');
    }
}

function handleLogout() {
    authToken = null;
    currentUser = null;
    localStorage.clear();
    
    const mainPanel = document.getElementById('mainPanel');
    mainPanel.style.animation = 'slideOutToRight 0.5s ease-in-out';
    
    setTimeout(() => {
        showLoginScreen();
        showToast('Güvenli çıkış yapıldı.', 'success');
    }, 500);
}

// UI Functions
function showLoginScreen() {
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('mainPanel').classList.add('hidden');
    
    // Clear form
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    hideError();
}

function showMainPanel() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('mainPanel').classList.remove('hidden');
    
    // Show/hide admin menu
    const adminMenuItem = document.getElementById('adminMenuItem');
    if (currentUser && currentUser.role === 'admin') {
        adminMenuItem.classList.remove('hidden');
    } else {
        adminMenuItem.classList.add('hidden');
    }
    
    showPage('home');
    setupEventListeners();
    
    // Load stats immediately
    setTimeout(() => {
        loadStats();
    }, 100);
}

function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    // Show selected page
    const targetPage = document.getElementById(pageId + 'Page');
    if (targetPage) {
        targetPage.classList.add('active');
        
        // Refresh AOS animations
        AOS.refresh();
        
        // Load specific page data
        if (pageId === 'admin' && currentUser && currentUser.role === 'admin') {
            loadUsers();
        } else if (pageId === 'home') {
            loadStats();
        }
    }
}

function showError(message) {
    const errorDiv = document.getElementById('loginError');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
}

function hideError() {
    document.getElementById('loginError').classList.add('hidden');
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    
    toastMessage.textContent = message;
    toast.className = `toast ${type}`;
    toast.classList.remove('hidden');
    
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 4000);
}

// Statistics Functions
async function loadStats() {
    if (!authToken) return;
    
    try {
        console.log('Loading stats...');
        const response = await fetch('/api/stats', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        console.log('Stats response status:', response.status);
        
        if (response.ok) {
            const newStats = await response.json();
            console.log('Stats data:', newStats);
            stats = newStats;
            updateStatsDisplay();
        } else {
            console.error('Stats load failed:', response.status);
            // Set default stats if API fails
            stats = {
                global: { totalQueries: 0, successfulQueries: 0, failedQueries: 0, totalUsers: 1 },
                user: { total: 0, successful: 0, failed: 0 }
            };
            updateStatsDisplay();
        }
    } catch (error) {
        console.error('Stats load error:', error);
        // Set default stats if request fails
        stats = {
            global: { totalQueries: 0, successfulQueries: 0, failedQueries: 0, totalUsers: 1 },
            user: { total: 0, successful: 0, failed: 0 }
        };
        updateStatsDisplay();
    }
}

function updateStatsDisplay() {
    console.log('Updating stats display with:', stats);
    
    // Global stats with null checks
    const totalQueriesEl = document.getElementById('totalQueries');
    const successfulQueriesEl = document.getElementById('successfulQueries');
    const failedQueriesEl = document.getElementById('failedQueries');
    const totalUsersEl = document.getElementById('totalUsers');
    
    if (totalQueriesEl) totalQueriesEl.textContent = stats.global?.totalQueries || 0;
    if (successfulQueriesEl) successfulQueriesEl.textContent = stats.global?.successfulQueries || 0;
    if (failedQueriesEl) failedQueriesEl.textContent = stats.global?.failedQueries || 0;
    if (totalUsersEl) totalUsersEl.textContent = stats.global?.totalUsers || 0;
    
    // User stats with null checks
    const userTotalQueriesEl = document.getElementById('userTotalQueries');
    const userSuccessfulQueriesEl = document.getElementById('userSuccessfulQueries');
    const userSuccessRateEl = document.getElementById('userSuccessRate');
    
    if (userTotalQueriesEl) userTotalQueriesEl.textContent = stats.user?.total || 0;
    if (userSuccessfulQueriesEl) userSuccessfulQueriesEl.textContent = stats.user?.successful || 0;
    
    // Success rate calculation
    const userTotal = stats.user?.total || 0;
    const userSuccessful = stats.user?.successful || 0;
    const successRate = userTotal > 0 ? Math.round((userSuccessful / userTotal) * 100) : 0;
    
    if (userSuccessRateEl) userSuccessRateEl.textContent = successRate + '%';
    
    // Animate numbers
    animateNumbers();
}

function animateNumbers() {
    const numbers = document.querySelectorAll('.stat-number, .user-stat-value');
    numbers.forEach(num => {
        num.style.animation = 'pulse 0.6s ease-out';
        setTimeout(() => {
            num.style.animation = '';
        }, 600);
    });
}

// API Functions
async function makeApiRequest(endpoint, params = {}) {
    if (!authToken) {
        showToast('Oturum süresi dolmuş. Lütfen tekrar giriş yapın.', 'error');
        handleLogout();
        return null;
    }
    
    const queryString = new URLSearchParams(params).toString();
    const url = `/api/${endpoint}?${queryString}`;
    
    try {
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.status === 401 || response.status === 403) {
            showToast('Oturum süresi dolmuş. Lütfen tekrar giriş yapın.', 'error');
            handleLogout();
            return null;
        }
        
        const data = await response.json();
        
        if (response.ok) {
            // Refresh stats after successful query
            setTimeout(loadStats, 500);
            return data;
        } else {
            throw new Error(data.error || 'API hatası');
        }
    } catch (error) {
        showToast(`Hata: ${error.message}`, 'error');
        return null;
    }
}

// Query Functions
async function queryAdsoyad() {
    const adi = document.getElementById('adi').value.trim();
    const soyadi = document.getElementById('soyadi').value.trim();
    const il = document.getElementById('il').value.trim();
    const ilce = document.getElementById('ilce').value.trim();
    
    if (!adi || !soyadi) {
        showToast('Ad ve soyad alanları zorunludur!', 'error');
        return;
    }
    
    const params = { adi, soyadi };
    if (il) params.il = il;
    if (ilce) params.ilce = ilce;
    
    showLoading('adsoyadResults');
    
    const data = await makeApiRequest('adsoyad', params);
    if (data) {
        displayResults('adsoyadResults', data, 'Ad Soyad Sorgu');
        showToast('Ad soyad sorgusu tamamlandı!', 'success');
    }
}

async function queryTC() {
    const tc = document.getElementById('tcInput').value.trim();
    
    if (!tc || !/^[0-9]{11}$/.test(tc)) {
        showToast('Geçerli bir 11 haneli TC kimlik numarası girin!', 'error');
        return;
    }
    
    showLoading('tcResults');
    
    const data = await makeApiRequest('tc', { tc });
    if (data) {
        displayResults('tcResults', data, 'TC Sorgu');
        showToast('TC sorgusu tamamlandı!', 'success');
    }
}

async function queryAdres() {
    const tc = document.getElementById('adresTc').value.trim();
    
    if (!tc || !/^[0-9]{11}$/.test(tc)) {
        showToast('Geçerli bir 11 haneli TC kimlik numarası girin!', 'error');
        return;
    }
    
    showLoading('adresResults');
    
    const data = await makeApiRequest('adres', { tc });
    if (data) {
        displayResults('adresResults', data, 'Adres Sorgu');
        showToast('Adres sorgusu tamamlandı!', 'success');
    }
}

async function queryIsyeri() {
    const tc = document.getElementById('isyeriTc').value.trim();
    
    if (!tc || !/^[0-9]{11}$/.test(tc)) {
        showToast('Geçerli bir 11 haneli TC kimlik numarası girin!', 'error');
        return;
    }
    
    showLoading('isyeriResults');
    
    const data = await makeApiRequest('isyeri', { tc });
    if (data) {
        displayResults('isyeriResults', data, 'İşyeri Sorgu');
        showToast('İşyeri sorgusu tamamlandı!', 'success');
    }
}

async function querySulale() {
    const tc = document.getElementById('sulaleTc').value.trim();
    
    if (!tc || !/^[0-9]{11}$/.test(tc)) {
        showToast('Geçerli bir 11 haneli TC kimlik numarası girin!', 'error');
        return;
    }
    
    showLoading('sulaleResults');
    
    const data = await makeApiRequest('sulale', { tc });
    if (data) {
        displayResults('sulaleResults', data, 'Sulale Sorgu');
        showToast('Sulale sorgusu tamamlandı!', 'success');
    }
}

async function queryTcGsm() {
    const tc = document.getElementById('tcgsmInput').value.trim();
    
    if (!tc || !/^[0-9]{11}$/.test(tc)) {
        showToast('Geçerli bir 11 haneli TC kimlik numarası girin!', 'error');
        return;
    }
    
    showLoading('tcgsmResults');
    
    const data = await makeApiRequest('tcgsm', { tc });
    if (data) {
        displayResults('tcgsmResults', data, 'TC-GSM Sorgu');
        showToast('TC-GSM sorgusu tamamlandı!', 'success');
    }
}

async function queryGsmTc() {
    const gsm = document.getElementById('gsmInput').value.trim();
    
    if (!gsm || !/^[0-9]{10}$/.test(gsm)) {
        showToast('Geçerli bir 10 haneli GSM numarası girin!', 'error');
        return;
    }
    
    showLoading('gsmtcResults');
    
    const data = await makeApiRequest('gsmtc', { gsm });
    if (data) {
        displayResults('gsmtcResults', data, 'GSM-TC Sorgu');
        showToast('GSM-TC sorgusu tamamlandı!', 'success');
    }
}

// IP Lookup Functions
async function queryIPLookup() {
    const ip = document.getElementById('ipInput').value.trim();
    
    if (!ip) {
        showToast('IP adresi girin!', 'error');
        return;
    }
    
    // Validate IP format
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipRegex.test(ip)) {
        showToast('Geçerli bir IP adresi girin! (örn: 192.168.1.1)', 'error');
        return;
    }
    
    showLoading('iplookupResults');
    
    const data = await makeApiRequest('iplookup', { ip });
    if (data) {
        displayIPResults('iplookupResults', data);
        showToast('IP sorgusu tamamlandı!', 'success');
    }
}

function setExampleIP(ip) {
    document.getElementById('ipInput').value = ip;
}

async function getMyIP() {
    try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        document.getElementById('ipInput').value = data.ip;
        showToast('IP adresiniz otomatik olarak alındı!', 'success');
    } catch (error) {
        showToast('IP adresiniz alınamadı!', 'error');
    }
}

function displayIPResults(containerId, data) {
    const container = document.getElementById(containerId);
    
    if (!data || data.error) {
        container.innerHTML = `
            <div style="text-align: center; padding: 60px; color: #888;">
                <div style="font-size: 4rem; margin-bottom: 20px;"><i class="fas fa-exclamation-triangle" style="opacity: 0.3;"></i></div>
                <h3>IP Sorgusu Başarısız</h3>
                <p>IP adresi sorgulanamadı veya geçersiz.</p>
            </div>
        `;
        return;
    }
    
    let html = `
        <div class="ip-sources-info">
            <h5><i class="fas fa-database"></i> Veri Kaynakları</h5>
            <p>${data.sources} farklı API'den birleştirilmiş sonuç | Sorgu Zamanı: ${new Date(data.timestamp).toLocaleString('tr-TR')}</p>
        </div>
    `;
    
    // Basic Information
    if (data.data.basic) {
        html += `
            <div class="ip-result-section">
                <h4><i class="fas fa-info-circle"></i> Temel Bilgiler</h4>
                <div class="ip-result-grid">
                    ${createIPResultItem('IP Adresi', data.data.basic.ip)}
                    ${createIPResultItem('Hostname', data.data.basic.hostname)}
                    ${createIPResultItem('Tip', data.data.basic.type)}
                    ${createIPResultItem('Anycast', data.data.basic.anycast ? 'Evet' : 'Hayır')}
                </div>
            </div>
        `;
    }
    
    // Location Information
    if (data.data.location) {
        html += `
            <div class="ip-result-section">
                <h4><i class="fas fa-map-marker-alt"></i> Konum Bilgileri</h4>
                <div class="ip-result-grid">
                    ${createIPResultItem('Kıta', data.data.location.continent)}
                    ${createIPResultItem('Ülke', `${data.data.location.country} (${data.data.location.countryCode})`)}
                    ${createIPResultItem('Bölge', `${data.data.location.region} (${data.data.location.regionCode})`)}
                    ${createIPResultItem('Şehir', data.data.location.city)}
                    ${createIPResultItem('Posta Kodu', data.data.location.postalCode)}
                    ${createIPResultItem('Enlem', data.data.location.latitude)}
                    ${createIPResultItem('Boylam', data.data.location.longitude)}
                    ${createIPResultItem('Zaman Dilimi', data.data.location.timezone)}
                </div>
            </div>
        `;
    }
    
    // Network Information
    if (data.data.network) {
        html += `
            <div class="ip-result-section">
                <h4><i class="fas fa-network-wired"></i> Ağ Bilgileri</h4>
                <div class="ip-result-grid">
                    ${createIPResultItem('İnternet Sağlayıcı', data.data.network.isp)}
                    ${createIPResultItem('Organizasyon', data.data.network.organization)}
                    ${createIPResultItem('AS Numarası', data.data.network.as)}
                    ${createIPResultItem('AS Adı', data.data.network.asName)}
                    ${createIPResultItem('Reverse DNS', data.data.network.reverse)}
                </div>
            </div>
        `;
    }
    
    // Security Information
    if (data.data.security) {
        const hasSecurityIssues = data.data.security.proxy || data.data.security.vpn || data.data.security.tor || data.data.security.threat;
        
        html += `
            <div class="ip-result-section">
                <h4><i class="fas fa-shield-alt"></i> Güvenlik Bilgileri</h4>
                <div class="ip-result-grid">
                    ${createIPResultItem('Proxy', data.data.security.proxy ? 'Evet' : 'Hayır', data.data.security.proxy)}
                    ${createIPResultItem('VPN', data.data.security.vpn ? 'Evet' : 'Hayır', data.data.security.vpn)}
                    ${createIPResultItem('Tor', data.data.security.tor ? 'Evet' : 'Hayır', data.data.security.tor)}
                    ${createIPResultItem('Hosting', data.data.security.hosting ? 'Evet' : 'Hayır', data.data.security.hosting)}
                    ${createIPResultItem('Mobil', data.data.security.mobile ? 'Evet' : 'Hayır')}
                    ${createIPResultItem('Tehdit', data.data.security.threat ? 'Evet' : 'Hayır', data.data.security.threat)}
                </div>
                ${hasSecurityIssues ? `
                    <div class="security-warning">
                        <i class="fas fa-exclamation-triangle"></i> Bu IP adresi güvenlik riski taşıyabilir!
                    </div>
                ` : ''}
            </div>
        `;
    }
    
    // Locale Information
    if (data.data.locale) {
        html += `
            <div class="ip-result-section">
                <h4><i class="fas fa-globe"></i> Yerel Bilgiler</h4>
                <div class="ip-result-grid">
                    ${createIPResultItem('Para Birimi', data.data.locale.currency)}
                    ${createIPResultItem('Diller', data.data.locale.languages)}
                    ${createIPResultItem('Ülke Kodu', data.data.locale.callingCode)}
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
    
    // Add action buttons
    addActionButtons(container, data, 'IP Lookup');
}

function createIPResultItem(label, value, isWarning = false) {
    if (!value || value === 'null' || value === 'undefined') {
        return '';
    }
    
    const warningClass = isWarning ? 'style="color: #ffc107;"' : '';
    
    return `
        <div class="ip-result-item">
            <span class="ip-result-label">${label}:</span>
            <span class="ip-result-value" ${warningClass}>${value}</span>
        </div>
    `;
}

// Display Functions
function showLoading(containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <div class="loading-text">Sorgu yapılıyor...</div>
        </div>
    `;
}

function displayResults(containerId, data, queryType) {
    const container = document.getElementById(containerId);
    
    if (!data || (Array.isArray(data) && data.length === 0)) {
        container.innerHTML = `
            <div style="text-align: center; padding: 60px; color: #888;">
                <div style="font-size: 4rem; margin-bottom: 20px;"><i class="fas fa-search" style="opacity: 0.3;"></i></div>
                <h3>Sonuç Bulunamadı</h3>
                <p>Arama kriterlerinize uygun sonuç bulunamadı.</p>
            </div>
        `;
        return;
    }
    
    // Always display as table for consistency
    if (Array.isArray(data) && data.length > 0) {
        displayTable(container, data, queryType);
    } else if (typeof data === 'object') {
        // Convert single object to array for table display
        displayTable(container, [data], queryType);
    }
    
    // Add action buttons
    addActionButtons(container, data, queryType);
}

function displayTable(container, data, queryType) {
    if (!data.length) return;
    
    const keys = Object.keys(data[0]);
    let html = `
        <div style="overflow-x: auto;">
            <table class="results-table">
                <thead>
                    <tr>
                        ${keys.map(key => `<th>${key}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
    `;
    
    data.forEach((item, index) => {
        html += `<tr style="animation: fadeInUp 0.4s ease-out ${index * 0.1}s both;">`;
        keys.forEach(key => {
            html += `<td>${item[key] || '-'}</td>`;
        });
        html += '</tr>';
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    container.innerHTML = html;
}

function addActionButtons(container, data, queryType) {
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'action-buttons';
    
    // Clear Results Button
    const clearBtn = document.createElement('button');
    clearBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Sorgu Temizle';
    clearBtn.className = 'action-btn clear-btn';
    clearBtn.onclick = () => clearResults(container.id);
    
    // Export to Excel Button
    const exportBtn = document.createElement('button');
    exportBtn.innerHTML = '<i class="fas fa-file-excel"></i> Excel\'e Aktar';
    exportBtn.className = 'action-btn export-btn';
    exportBtn.onclick = () => exportToExcel(data, queryType);
    
    // Copy JSON Button
    const copyBtn = document.createElement('button');
    copyBtn.innerHTML = '<i class="fas fa-copy"></i> JSON Kopyala';
    copyBtn.className = 'action-btn copy-btn';
    copyBtn.onclick = () => copyToClipboard(JSON.stringify(data, null, 2));
    
    // Export to TXT Button
    const txtBtn = document.createElement('button');
    txtBtn.innerHTML = '<i class="fas fa-file-alt"></i> TXT İndir';
    txtBtn.className = 'action-btn export-btn';
    txtBtn.onclick = () => downloadAsText(data, queryType);
    
    actionsDiv.appendChild(clearBtn);
    actionsDiv.appendChild(exportBtn);
    actionsDiv.appendChild(copyBtn);
    actionsDiv.appendChild(txtBtn);
    
    container.appendChild(actionsDiv);
}

// Utility Functions
function clearResults(containerId) {
    const container = document.getElementById(containerId);
    container.innerHTML = `
        <div style="text-align: center; padding: 60px; color: #888;">
            <div style="font-size: 4rem; margin-bottom: 20px;"><i class="fas fa-broom" style="opacity: 0.3;"></i></div>
            <h3>Sonuçlar Temizlendi</h3>
            <p>Yeni bir sorgu yapmak için formu doldurun.</p>
        </div>
    `;
    showToast('Sonuçlar temizlendi!', 'success');
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('JSON panoya kopyalandı!', 'success');
    }).catch(() => {
        showToast('Kopyalama başarısız!', 'error');
    });
}

function downloadAsText(data, queryType) {
    const text = JSON.stringify(data, null, 2);
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${queryType}-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('TXT dosyası indirildi!', 'success');
}

function exportToExcel(data, queryType) {
    if (!Array.isArray(data) || data.length === 0) {
        showToast('Dışa aktarılacak veri bulunamadı!', 'error');
        return;
    }
    
    // Create CSV content
    const keys = Object.keys(data[0]);
    let csvContent = keys.join(',') + '\n';
    
    data.forEach(item => {
        const row = keys.map(key => {
            const value = item[key] || '';
            // Escape commas and quotes
            return `"${String(value).replace(/"/g, '""')}"`;
        });
        csvContent += row.join(',') + '\n';
    });
    
    // Create and download file
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${queryType}-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Excel dosyası indirildi!', 'success');
}

// Admin Functions
async function loadUsers() {
    if (!currentUser || currentUser.role !== 'admin') return;
    
    try {
        const response = await fetch('/api/admin/users', {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        if (response.ok) {
            const users = await response.json();
            displayUsers(users);
        } else {
            showToast('Kullanıcılar yüklenemedi!', 'error');
        }
    } catch (error) {
        showToast('Bağlantı hatası!', 'error');
    }
}

function displayUsers(users) {
    const container = document.getElementById('usersList');
    
    if (!users.length) {
        container.innerHTML = '<p style="text-align: center; color: #888; padding: 40px;">Kullanıcı bulunamadı.</p>';
        return;
    }
    
    let html = '';
    users.forEach((user, index) => {
        html += `
            <div class="user-item" style="animation: fadeInUp 0.4s ease-out ${index * 0.1}s both;">
                <div class="user-info">
                    <div class="username">${user.username}</div>
                    <div class="role ${user.role}">${user.role === 'admin' ? 'Yönetici' : 'Kullanıcı'}</div>
                </div>
                <button 
                    class="delete-btn" 
                    onclick="deleteUser(${user.id})"
                    ${user.username === 'admin' ? 'disabled title="Ana admin silinemez"' : ''}
                >
                    <i class="fas fa-trash-alt"></i> Sil
                </button>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

async function addUser() {
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value.trim();
    const role = document.getElementById('newRole').value;
    
    if (!username || !password) {
        showToast('Kullanıcı adı ve şifre gereklidir!', 'error');
        return;
    }
    
    if (username.length < 3) {
        showToast('Kullanıcı adı en az 3 karakter olmalıdır!', 'error');
        return;
    }
    
    if (password.length < 6) {
        showToast('Şifre en az 6 karakter olmalıdır!', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ username, password, role })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Kullanıcı başarıyla eklendi ve aktif edildi!', 'success');
            
            // Clear form
            document.getElementById('newUsername').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('newRole').value = 'user';
            
            // Reload users list and stats
            loadUsers();
            loadStats();
        } else {
            showToast(data.error || 'Kullanıcı eklenemedi!', 'error');
        }
    } catch (error) {
        showToast('Bağlantı hatası!', 'error');
    }
}

async function deleteUser(userId) {
    if (!confirm('Bu kullanıcıyı silmek istediğinizden emin misiniz?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Kullanıcı başarıyla silindi!', 'success');
            loadUsers();
            loadStats();
        } else {
            showToast(data.error || 'Kullanıcı silinemedi!', 'error');
        }
    } catch (error) {
        showToast('Bağlantı hatası!', 'error');
    }
}

// Add CSS animations for logout
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOutToRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100px);
        }
    }
`;
document.head.appendChild(style);

// IBAN Lookup Functions
async function queryIBAN() {
    const iban = document.getElementById('ibanInput').value.trim();
    
    if (!iban) {
        showToast('IBAN numarası girin!', 'error');
        return;
    }
    
    // Clean IBAN (remove spaces)
    const cleanIban = iban.replace(/\s/g, '').toUpperCase();
    
    // Basic IBAN format validation
    if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]+$/.test(cleanIban)) {
        showToast('Geçerli bir IBAN numarası girin! (örn: TR330006100519786457841326)', 'error');
        return;
    }
    
    if (cleanIban.length < 15 || cleanIban.length > 34) {
        showToast('IBAN numarası 15-34 karakter arasında olmalıdır!', 'error');
        return;
    }
    
    showLoading('ibanResults');
    
    const data = await makeApiRequest('iban', { iban: cleanIban });
    if (data) {
        displayIBANResults('ibanResults', data);
        showToast('IBAN sorgusu tamamlandı!', 'success');
    }
}

function setExampleIBAN(iban) {
    document.getElementById('ibanInput').value = iban;
}

function displayIBANResults(containerId, data) {
    const container = document.getElementById(containerId);
    
    if (!data || data.error) {
        container.innerHTML = `
            <div style="text-align: center; padding: 60px; color: #888;">
                <div style="font-size: 4rem; margin-bottom: 20px;"><i class="fas fa-exclamation-triangle" style="opacity: 0.3;"></i></div>
                <h3>IBAN Sorgusu Başarısız</h3>
                <p>${data?.details || 'IBAN numarası doğrulanamadı veya geçersiz.'}</p>
            </div>
        `;
        return;
    }
    
    let html = `
        <div class="iban-sources-info">
            <h5><i class="fas fa-university"></i> IBAN Doğrulama Sonucu</h5>
            <p>Sorgu Zamanı: ${new Date(data.timestamp).toLocaleString('tr-TR')}</p>
        </div>
    `;
    
    // IBAN Validation Status
    html += `
        <div class="iban-result-section">
            <h4><i class="fas fa-check-circle"></i> Doğrulama Durumu</h4>
            <div class="iban-validation">
                <span class="validation-badge ${data.isValid ? 'validation-valid' : 'validation-invalid'}">
                    <i class="fas fa-${data.isValid ? 'check' : 'times'}"></i>
                    ${data.isValid ? 'Geçerli IBAN' : 'Geçersiz IBAN'}
                </span>
            </div>
            <div class="iban-formatted">${data.formatted}</div>
        </div>
    `;
    
    // Basic IBAN Information
    html += `
        <div class="iban-result-section">
            <h4><i class="fas fa-info-circle"></i> IBAN Bilgileri</h4>
            <div class="iban-result-grid">
                ${createIBANResultItem('IBAN Numarası', data.iban)}
                ${createIBANResultItem('Ülke', `${data.country} (${data.countryCode})`)}
                ${createIBANResultItem('Kontrol Rakamları', data.checkDigits)}
                ${createIBANResultItem('Banka Kodu', data.bankCode)}
                ${createIBANResultItem('Hesap Numarası', data.accountNumber)}
            </div>
        </div>
    `;
    
    // Bank Information
    if (data.bankInfo && (data.bankInfo.bankName || data.bankInfo.bic)) {
        html += `
            <div class="iban-result-section">
                <h4><i class="fas fa-building"></i> Banka Bilgileri</h4>
                <div class="bank-info-card">
                    <h5><i class="fas fa-university"></i> Banka Detayları</h5>
                    <div class="iban-result-grid">
                        ${createIBANResultItem('Banka Adı', data.bankInfo.bankName || 'Bilinmiyor')}
                        ${createIBANResultItem('BIC/SWIFT Kodu', data.bankInfo.bic || 'Bilinmiyor')}
                        ${createIBANResultItem('Şehir', data.bankInfo.city || 'Bilinmiyor')}
                        ${createIBANResultItem('Ülke', data.bankInfo.country)}
                    </div>
                </div>
            </div>
        `;
    } else {
        html += `
            <div class="iban-result-section">
                <h4><i class="fas fa-building"></i> Banka Bilgileri</h4>
                <div class="bank-info-card">
                    <p style="color: #888; text-align: center; padding: 20px;">
                        <i class="fas fa-info-circle"></i>
                        Bu IBAN için detaylı banka bilgisi bulunamadı.
                    </p>
                </div>
            </div>
        `;
    }
    
    // Validation Details
    if (data.validation) {
        html += `
            <div class="iban-result-section">
                <h4><i class="fas fa-cogs"></i> Teknik Detaylar</h4>
                <div class="iban-result-grid">
                    ${createIBANResultItem('Doğrulama Durumu', data.validation.isValid ? 'Başarılı' : 'Başarısız')}
                    ${data.validation.error ? createIBANResultItem('Hata Detayı', data.validation.error) : ''}
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
    
    // Add action buttons
    addActionButtons(container, data, 'IBAN Lookup');
}

function createIBANResultItem(label, value) {
    if (!value || value === 'null' || value === 'undefined' || value === 'Bilinmiyor') {
        if (value === 'Bilinmiyor') {
            return `
                <div class="iban-result-item">
                    <span class="iban-result-label">${label}:</span>
                    <span class="iban-result-value" style="color: #888; font-style: italic;">${value}</span>
                </div>
            `;
        }
        return '';
    }
    
    return `
        <div class="iban-result-item">
            <span class="iban-result-label">${label}:</span>
            <span class="iban-result-value">${value}</span>
        </div>
    `;
}

// Format IBAN input as user types
document.addEventListener('DOMContentLoaded', function() {
    const ibanInput = document.getElementById('ibanInput');
    if (ibanInput) {
        ibanInput.addEventListener('input', function(e) {
            let value = e.target.value.replace(/\s/g, '').toUpperCase();
            let formatted = value.replace(/(.{4})/g, '$1 ').trim();
            if (formatted.length <= 34 + 8) { // 34 chars + 8 spaces max
                e.target.value = formatted;
            }
        });
        
        ibanInput.addEventListener('paste', function(e) {
            setTimeout(() => {
                let value = e.target.value.replace(/\s/g, '').toUpperCase();
                let formatted = value.replace(/(.{4})/g, '$1 ').trim();
                e.target.value = formatted;
            }, 10);
        });
    }
});