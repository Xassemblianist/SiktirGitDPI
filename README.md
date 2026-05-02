<p align="center">
  <b>SiktirGitDPI</b><br>
  <i>Türkiye ISP'lerinin DPI sansürünü delmek için açık kaynak araç</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/language-C%2B%2B17-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/version-0.2.0-green?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" />
</p>

---

## 🤔 Bu Ne?

Türk ISP'leri (Türk Telekom, Turkcell Superonline, Vodafone, TurkNet) internet trafiğini **Deep Packet Inspection (DPI)** ile denetliyor ve bazı siteleri engelliyor/yavaşlatıyor.

**SiktirGitDPI** bu filtreleri kernel seviyesinde paket değiştirerek bypass eder. VPN **kullanmaz**, hızını **düşürmez**.

> GoodbyeDPI'nin yaptığı her şeyi yapar + **wrong-checksum stratejisi**, **ISP RST koruması**, **otomatik strateji seçimi** ve **GUI** ekler.

---

## ⚡ Hızlı Başlangıç (2 dakika)

### İndirip Çalıştır (build gerektirmez)

1. [Releases](../../releases) sayfasından `sgdpi-v0.2.0-win64.zip` indir
2. ZIP'i aç
3. ISP'ne göre çift tıkla:

| Dosya | Ne yapar |
|---|---|
| `GUI.cmd` | **Grafik arayüz** — profil seç, başlat tıkla |
| `1_GUVENLI_BASLA.cmd` | Sadece engelli siteleri bypass eder, bankalara dokunmaz |
| `2_TT_TurkTelekom.cmd` | Türk Telekom için optimize |
| `3_Turkcell_Superonline.cmd` | Turkcell için optimize |
| `4_Vodafone.cmd` | Vodafone için optimize |
| `5_TurkNet.cmd` | TurkNet için optimize |
| `7_OTOMATIK_BUL.cmd` | Hangi strateji çalışıyor otomatik test eder |

4. UAC penceresi çıkacak → **Evet** de (admin gerekli)
5. İnternet kullan 🎉

> **Durdurmak:** Pencerede `Ctrl+C` veya `stop.cmd`'ye çift tıkla

---

## 🛡️ Neler Yapıyor

| Strateji | Açıklama |
|---|---|
| **TLS Split** | TCP segmentini SNI'nin ortasında ikiye bölüyor |
| **Wrong Checksum** | Kasıtlı yanlış checksum ile DPI'yı zehirliyor |
| **Fake TTL** | Düşük TTL'li sahte paket gönderiyor |
| **Inbound RST Drop** | ISP'nin gönderdiği sahte RST paketlerini düşürüyor |
| **HTTP Mangle** | `Host:` başlığını DPI'nın tanıyamayacağı şekilde değiştiriyor |
| **DNS Redirect** | DNS hijack'e karşı trafiği 1.1.1.1'e yönlendiriyor |
| **TCP Disorder** | Paketleri ters sırada gönderiyor |
| **OOB / MD5 / Zero-Window** | Ek DPI karıştırma teknikleri |

### GoodbyeDPI'den Farkları

| Özellik | GoodbyeDPI | SiktirGitDPI |
|---|:---:|:---:|
| TLS Split + Fake TTL | ✅ | ✅ |
| Wrong Checksum | ✅ | ✅ |
| HTTP Mangle | ✅ | ✅ |
| ISP RST Drop | ❌ | ✅ |
| Auto-tune (otomatik strateji) | ❌ | ✅ |
| Auto-TTL (ICMP ile keşif) | ❌ | ✅ |
| DNS Redirect (transparent) | ❌ | ✅ |
| Domain Filter (allowlist/blocklist) | ❌ | ✅ |
| GUI (grafik arayüz) | ❌ | ✅ |
| ISP preset'leri | ❌ | ✅ |
| Flow tracking | ❌ | ✅ |

---

## 🖥️ GUI

`GUI.cmd`'ye çift tıkla:

- ISP profilini dropdown'dan seç
- **BAŞLAT** tıkla
- Canlı istatistik panelinde paket akışını izle
- Sistem tepsisinden gizle/göster
- X'e basınca tepside çalışmaya devam eder

---

## ⚙️ Komut Satırı Kullanımı

```powershell
# Varsayılan profil
sgdpi.exe --preset tt --stats

# Otomatik strateji bulma
sgdpi.exe --auto youtube.com

# Manuel ayar
sgdpi.exe --strategies tls-split,fake-ttl,wrong-chksum --fake-ttl auto --inbound-rst-drop

# Mevcut stratejileri listele
sgdpi.exe --list-strategies

# Versiyon
sgdpi.exe --version
```

---

## 🏗️ Kaynaktan Derleme

### Gereksinimler
- Windows 10/11 (x64)
- CMake ≥ 3.20
- MinGW-w64 veya Visual Studio 2022

### Build

```powershell
# 1. WinDivert SDK indir
.\scripts\get-windivert.ps1

# 2. Derle
.\scripts\build.bat

# 3. Test et
ctest --test-dir build -C Release
```

Çıktı: `build\Release\sgdpi.exe`

### Release Paketi Oluşturma

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package.ps1
```

---

## 📁 Proje Yapısı

```
SiktirGitDPI/
├── src/                    C++ kaynak kodları
├── include/sgdpi/          Header dosyaları
├── tests/                  Birim testler (39 test)
├── presets/                ISP profilleri (.conf)
│   ├── tt.conf             Türk Telekom
│   ├── turkcell.conf       Turkcell Superonline
│   ├── vodafone.conf       Vodafone
│   ├── turknet.conf        TurkNet
│   ├── safe.conf           Güvenli mod (allowlist)
│   ├── aggressive.conf     Tüm stratejiler
│   ├── blocked-sites.txt   Engellenen siteler listesi
│   └── banks-safelist.txt  Dokunulmaması gereken siteler
├── releases/x64/           GUI + launcher script'leri
├── scripts/                Build/package script'leri
└── third_party/            WinDivert SDK (otomatik indirilir)
```

---

## 🔧 SSS

**S: SmartScreen engelledi**
C: "Daha fazla bilgi" → "Yine de çalıştır" tıkla. Kod açık kaynak.

**S: Hiçbir profil işe yaramadı**
C: `7_OTOMATIK_BUL.cmd` dene. 30-60 saniyede en iyi stratejiyi bulur.

**S: Banka/devlet sitelerinde sorun**
C: `1_GUVENLI_BASLA.cmd` kullan — sadece engelli sitelere müdahale eder.

**S: Açılışta otomatik çalışsın**
C: `service_install.cmd`'ye çift tıkla. Windows servisi olarak kurar.

**S: WinDivert hatası alıyorum**
C: Admin olarak çalıştırdığından emin ol. `WinDivert.dll` ve `WinDivert64.sys` dosyaları `sgdpi.exe` ile aynı klasörde olmalı.

---

## 📋 Yasal Uyarı

Bu yazılım kişisel kullanım, ağ araştırması ve sansür baypası için yazılmıştır. Trafiğinizi nasıl yönlendirdiğinizden siz sorumlusunuz.

## 📄 Lisans

MIT
