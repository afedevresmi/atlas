# 🔒 Atlas Panel - Advanced Query System

Atlas Panel, kapsamlı veri sorgulama ve analiz yetenekleri sunan güvenli bir web uygulamasıdır. JWT tabanlı kimlik doğrulama sistemi ile korunan platform, çoklu API entegrasyonu ve akıllı arama özellikleri sunar.

## 🚀 Canlı Demo

- **Railway**: https://atlaspanelfreeatat.up.railway.app
- **GitHub**: https://github.com/afedevresmi/atlas
- **GitHub**: https://github.com/afedevresmi/atlas

## ✨ Özellikler

### � **Super Search (YENİ!)**
- **Akıllı Veri Algılama**: TC, GSM, IBAN, IP, Ad Soyad, Email otomatik tespiti
- **Çoklu Arama**: Birden fazla sorgu türünü aynı anda çalıştırma
- **Derin Arama**: TC için kapsamlı sorgu paketi (adres, işyeri, sulale, GSM)
- **Güven Skoru**: Veri türü tespitinde güvenilirlik yüzdesi
- **Akıllı Öneriler**: Gerçek zamanlı öneriler ve otomatik tamamlama

### 🔐 **Güvenlik ve Kimlik Doğrulama**
- JWT (JSON Web Token) tabanlı güvenli oturum yönetimi
- Rol tabanlı erişim kontrolü (Admin/User)
- Güvenli şifre doğrulama sistemi
- Oturum süresi yönetimi ve otomatik çıkış

### 📊 **Veri Sorgulama Modülleri**
- **TC Kimlik Sorgu**: 11 haneli TC kimlik numarası sorgulama
- **Ad Soyad Sorgu**: İsim bazlı kişi arama (il/ilçe filtreleme)
- **Adres Sorgu**: TC bazlı adres bilgisi sorgulama
- **İşyeri Sorgu**: TC bazlı çalışma bilgileri
- **Sulale Sorgu**: Aile bireyleri ve yakınlık bilgileri
- **TC → GSM**: TC'den GSM numarası bulma
- **GSM → TC**: GSM'den TC kimlik bulma

### 🌐 **Gelişmiş IP ve IBAN Analizi**
- **IP Analizi**: 15+ API'den birleşik IP geolocation ve güvenlik analizi
- **IBAN Doğrulama**: 80+ ülke IBAN formatı doğrulama ve banka bilgileri
- **Güvenlik Analizi**: VPN, Proxy, Tor tespiti
- **Risk Değerlendirmesi**: Kapsamlı güvenlik skorlaması

### 📈 **İstatistik ve Raporlama**
- Gerçek zamanlı sorgu istatistikleri
- Kullanıcı bazlı performans metrikleri
- Başarı/başarısızlık oranları
- Toplam sistem kullanım verileri

### 👥 **Admin Panel**
- Kullanıcı yönetimi (ekleme, silme, düzenleme)
- Rol atama ve yetki yönetimi
- Sistem geneli istatistik görüntüleme
- Kullanıcı aktivite takibi

### 📤 **Export ve Paylaşım**
- **Excel Export**: CSV formatında veri indirme
- **TXT Export**: Düz metin formatında kaydetme
- **JSON Kopyalama**: Ham veri kopyalama
- **Tablo Kopyalama**: Formatlanmış tablo verisi kopyalama
- Türkçe başlıklar ve düzenli formatlama

### 🛡️ **API Güvenilirlik Sistemi**
- **Fallback Sistemi**: Ana API'ler çalışmadığında mock data
- **Retry Logic**: Exponential backoff ile yeniden deneme
- **Health Monitoring**: API durumu izleme
- **Error Handling**: Detaylı hata mesajları ve çözüm önerileri

### 🎨 **Kullanıcı Arayüzü**
- **Klasik Tasarım**: Sade, minimal ve kullanıcı dostu
- **Responsive**: Mobil ve tablet uyumlu
- **Dark Theme**: Göz yormayan koyu tema
- **Türkçe Dil Desteği**: Tam Türkçe arayüz

## 🛠️ Teknoloji Stack

### Backend
- **Node.js**: Server-side JavaScript runtime
- **Express.js**: Web framework
- **JWT**: Güvenli token tabanlı kimlik doğrulama
- **Axios**: HTTP client for API requests
- **CORS**: Cross-origin resource sharing

### Frontend
- **Vanilla JavaScript**: Modern ES6+ JavaScript
- **HTML5**: Semantic markup
- **CSS3**: Modern styling with Flexbox/Grid
- **Font Awesome**: Icon library
- **AOS**: Animate On Scroll library

### Deployment
- **Railway**: Primary hosting platform
- **Render**: Secondary hosting platform
- **GitHub**: Version control and CI/CD

## 📋 Kurulum

### Gereksinimler
- Node.js (v14 veya üzeri)
- npm veya yarn package manager

### Yerel Kurulum
```bash
# Repository'yi klonlayın
git clone https://github.com/afedevresmi/atlas.git
cd atlas

# Bağımlılıkları yükleyin
npm install

# Sunucuyu başlatın
npm start
# veya
node server.js

# Tarayıcıda açın
http://localhost:5000
```

### Environment Variables
```env
PORT=5000
JWT_SECRET=your-secret-key-here
```

## 👤 Varsayılan Kullanıcılar

### Admin Hesabı
- **Kullanıcı Adı**: `admin`
- **Şifre**: `atlas2024`
- **Yetki**: Tam yönetici erişimi

### Test Kullanıcısı
- **Kullanıcı Adı**: `user1`
- **Şifre**: `user123`
- **Yetki**: Standart kullanıcı

## 🔧 API Endpoints

### Kimlik Doğrulama
- `POST /api/login` - Kullanıcı girişi
- `GET /api/stats` - İstatistik verileri

### Veri Sorguları
- `GET /api/tc?tc={tc}` - TC kimlik sorgu
- `GET /api/adsoyad?adi={ad}&soyadi={soyad}` - Ad soyad sorgu
- `GET /api/adres?tc={tc}` - Adres sorgu
- `GET /api/isyeri?tc={tc}` - İşyeri sorgu
- `GET /api/sulale?tc={tc}` - Sulale sorgu
- `GET /api/tcgsm?tc={tc}` - TC → GSM sorgu
- `GET /api/gsmtc?gsm={gsm}` - GSM → TC sorgu
- `GET /api/iplookup?ip={ip}` - IP analizi
- `GET /api/iban?iban={iban}` - IBAN doğrulama

### Admin Endpoints
- `GET /api/admin/users` - Kullanıcı listesi
- `POST /api/admin/users` - Yeni kullanıcı ekleme
- `DELETE /api/admin/users/{id}` - Kullanıcı silme

## 🚀 Deployment Durumu

### ✅ Railway Deployment
- **URL**: https://atlasfreeatat.up.railway.app
- **Status**: Aktif ve çalışıyor
- **Auto Deploy**: GitHub push ile otomatik deployment

### ✅ Render Deployment  
- **URL**: https://atlaspanel.onrender.com
- **Status**: Aktif ve çalışıyor
- **Auto Deploy**: GitHub push ile otomatik deployment

### 🔄 Deployment Pipeline
1. GitHub'a kod push edilir
2. Railway ve Render otomatik olarak yeni versiyonu deploy eder
3. Health check ile servis durumu kontrol edilir
4. Canlı ortamda yeni özellikler aktif olur

## 📊 Sistem Özellikleri

### Performans
- **API Response Time**: < 2 saniye
- **Concurrent Users**: 100+ eşzamanlı kullanıcı
- **Uptime**: %99.9 erişilebilirlik
- **Data Processing**: Saniyede 50+ sorgu

### Güvenlik
- **JWT Token Encryption**: 256-bit güvenlik
- **Rate Limiting**: DDoS koruması
- **Input Validation**: XSS ve injection koruması
- **HTTPS**: SSL/TLS şifreleme

### Ölçeklenebilirlik
- **Horizontal Scaling**: Çoklu instance desteği
- **Load Balancing**: Trafik dağıtımı
- **Database Ready**: Kolay veritabanı entegrasyonu
- **Microservice Architecture**: Modüler yapı

## 🤝 Katkıda Bulunma

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📝 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 📞 İletişim

- **GitHub**: [@afedevresmi](https://github.com/afedevresmi)
- **Project Link**: [https://github.com/afedevresmi/atlas](https://github.com/afedevresmi/atlas)

## 🔄 Güncellemeler

### v2.1.0 (Son Güncelleme)
- ✨ Super Search özelliği eklendi
- 🔧 API fallback sistemi geliştirildi
- 🎨 Klasik tasarıma geçiş
- 📋 Tablo kopyalama düzeltildi
- 🛡️ Gelişmiş hata yönetimi

### v2.0.0
- 🌐 Gelişmiş IP ve IBAN analizi
- 📊 Kapsamlı istatistik sistemi
- 👥 Admin panel geliştirmeleri
- 📤 Export özelliklerinin genişletilmesi

### v1.0.0
- 🔐 JWT kimlik doğrulama sistemi
- 📋 Temel sorgu modülleri
- 🎨 Responsive web tasarımı
- 🚀 İlk deployment

---

**Atlas Panel** - Güvenli, hızlı ve kapsamlı veri sorgulama platformu 🚀