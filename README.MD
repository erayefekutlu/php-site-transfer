# PHP File Transfer Script

Tam otomatik, güvenli sunucu geçişi için tasarlanmış dosya transfer sistemi. Eski hostinginizden yeni hostinginize tek bir komutla dosyaları güvenli şekilde aktarır.

## Özellikler

- ✅ **Tam Otomatik** - Sadece domain girin, geri kalanı otomatik
- ✅ **SHA256 Hash Doğrulama** - Dosya bütünlüğü garantisi
- ✅ **Otomatik Temizleme** - Transfer sonrası eski sunucudaki zip otomatik silinir
- ✅ HTTPS zorunluluğu
- ✅ IP whitelist koruması
- ✅ Rate limiting (sadece yanlış şifrede devreye girer)
- ✅ HTTP Basic Authentication
- ✅ SSRF saldırı koruması
- ✅ Symlink ve path traversal koruması
- ✅ Disk alanı kontrolü

## Kurulum

### 1. Eski Hosting (Kaynak)
`oldServer.php` dosyasını eski hostinginizin root dizinine yükleyin.

### 2. Yeni Hosting (Hedef)
`newServer.php` dosyasını yeni hostinginizin root dizinine yükleyin.

## Yapılandırma

### Her iki dosyada da değiştirmeniz gerekenler:

```php
$validUsername = 'admin';              // KESİNLİKLE DEĞİŞTİRİN!
$validPassword = 'securepassword123';  // KESİNLİKLE DEĞİŞTİRİN!
$secretKey = 'your-secret-key';        // KESİNLİKLE DEĞİŞTİRİN!
$allowedIPs = ['yeni-sunucu-ip'];      // Yeni hostingin IP'sini ekleyin
```

**ÖNEMLİ:** `oldServer.php` dosyasındaki `$allowedIPs` dizisine yeni hostinginizin IP adresini eklemeyi unutmayın!

## Kullanım

### Otomatik Transfer (Tek Komut)

```bash
curl -X POST https://yeni-hosting.com/newServer.php \
  -d "password=securepassword123" \
  -d "old_server_domain=eski-hosting.com"
```

**Başarılı Yanıt:**
```json
{
  "status": "success",
  "message": "Dosya başarıyla indirildi ve doğrulandı.",
  "file_name": "oldServer_abc123_1234567890_a1b2.zip",
  "file_size": 52428800,
  "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hash_verified": true,
  "old_server_domain": "eski-hosting.com",
  "old_server_cleanup": {
    "status": "success",
    "message": "Zip dosyası başarıyla silindi.",
    "deleted_file": "oldServer_abc123_1234567890.zip"
  },
  "warning": "Dosya 24 saat sonra otomatik silinecektir."
}
```

### Web Arayüzü Üzerinden

Tarayıcınızda `https://yeni-hosting.com/newServer.php` adresini açın ve:
1. Parolanızı girin
2. Eski hosting domain'inizi girin (örn: `eski-hosting.com`)
3. "Transfer Başlat" butonuna tıklayın

Sistem otomatik olarak:
1. Eski sunucuya bağlanır
2. Zip dosyası oluşturulur ve SHA256 hash hesaplanır
3. Yeni sunucuya indirilir
4. Hash doğrulaması yapılır
5. Doğrulama başarılıysa eski sunucudaki zip silinir
6. Size detaylı rapor sunar

## Nasıl Çalışır?

1. **newServer.php** eski hosting domain'ini alır
2. **oldServer.php**'ye otomatik istek atar
3. Eski hosting tüm dosyaları zip'ler (oldServer.php hariç)
4. Zip'in SHA256 hash'i hesaplanır ve URL ile birlikte döner
5. Yeni sunucu zip'i indirir
6. İndirilen dosyanın hash'i hesaplanır ve karşılaştırılır
7. Hash eşleşirse eski sunucuya silme isteği gönderilir
8. Eski sunucudaki zip otomatik silinir

## Hata Durumları

**"Eski sunucuya bağlanılamadı"**
- Eski hosting HTTPS destekliyor mu kontrol edin
- oldServer.php dosyası doğru konumda mı?
- Kullanıcı adı/şifre her iki dosyada da aynı mı?

**"IP adresi yetkili değil"**
- oldServer.php'deki `$allowedIPs` dizisine yeni hostingin IP'sini ekleyin

**"Yetersiz disk alanı"**
- Yeni hostinginizde yeterli disk alanı olduğundan emin olun

**"Dosya bütünlüğü doğrulanamadı! Hash eşleşmiyor"**
- Dosya aktarım sırasında bozulmuş olabilir
- Tekrar deneyin veya ağ bağlantınızı kontrol edin

## Güvenlik Notları

⚠️ **ÖNEMLİ:** Transfer işlemi bittikten sonra her iki dosyayı da sunuculardan silin!

- ✅ **SHA256 Hash Doğrulama** - Dosya bütünlüğü garanti altında
- ✅ **Otomatik Temizleme** - Transfer başarılı olunca eski sunucudaki zip otomatik silinir
- ✅ Sadece HTTPS bağlantıları kabul edilir
- ✅ Rate limiting sadece yanlış şifre girişlerinde devreye girer
- ✅ Internal IP'lere (localhost, LAN) erişim engellenmiştir
- ✅ Sadece .zip dosyaları indirilebilir
- ✅ Symlink saldırıları engellenmiştir

## Lisans

MIT License - Detaylar için `LICENSE.MD` dosyasına bakın.

## Yazar

**Eray Efe Kutlu**  
Website: https://erayefekutlu.com

---

⭐ Bu projeyi faydalı bulduysan yıldız vermeyi unutma!