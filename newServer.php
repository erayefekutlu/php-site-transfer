<?php
/*
 * PHP Dosya TransferScripti
 * @author Eray Efe Kutlu
 * @license MIT
 * @version 1.0
 * @URL https://erayefekutlu.com
 * @description oldServer dosyasının oluşturduğu dosyayı indirir.
 * @note İşlem bittikten sonra dosyayı sunucudan silin.
 */

// Hard Coded Parola (Güvenlik için değiştirin)
$validUsername = "admin"; // KESİNLİKLE DEĞİŞTİRİN!
$validPassword = "securepassword123"; // KESİNLİKLE DEĞİŞTİRİN!
$secretKey = 'ec-php-file-transfer-secret-key'; // Rate limit için gizli anahtar (KEŞİNLİKLE DEĞİŞTİRİN!)
$allowedIPs = ['127.0.0.1']; // İzin verilen IP adresleri - KESİNLİKLE DEĞİŞTİRİN!

// HTTPS kontrolü
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Sadece HTTPS bağlantıları kabul edilir.']);
    exit;
}

// IP whitelist kontrolü
if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $checkIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
} else {
    $checkIp = $_SERVER['REMOTE_ADDR'];
}

if (!in_array($checkIp, $allowedIPs)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'IP adresi yetkili değil.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    $oldServerDomain = $_POST['old_server_domain'] ?? '';

    // Parola doğrulama
    if ($password !== $validPassword) {
        // Rate Limit ile brute-force saldırılarını önleme
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } else {
            $clientIp = $_SERVER['REMOTE_ADDR'];
        }

        $ipHash = hash_hmac('sha256', $clientIp, $secretKey);
        $rateLimitFile = sys_get_temp_dir() . '/.ec_rate_' . substr($ipHash, 0, 16) . '.dat';
        $attempts = [];

        // Mevcut denemeleri oku
        if (file_exists($rateLimitFile)) {
            $rateLimitData = file($rateLimitFile, FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
            foreach ($rateLimitData as $line) {
                $parts = explode(',', $line);
                if (count($parts) === 2) {
                    list($storedHash, $timestamp) = $parts;
                    if (time() - (int) $timestamp < 600) { // Son 10 dakika
                        $attempts[$storedHash] = isset($attempts[$storedHash]) ? $attempts[$storedHash] + 1 : 1;
                    }
                }
            }
        }

        // Deneme sayısını kontrol et
        if (isset($attempts[$ipHash]) && $attempts[$ipHash] >= 5) {
            http_response_code(429);
            echo json_encode(['status' => 'error', 'message' => 'Çok fazla başarısız deneme. 10 dakika sonra tekrar deneyin.']);
            exit;
        }

        // Başarısız denemeyi kaydet
        file_put_contents($rateLimitFile, $ipHash . ',' . time() . PHP_EOL, FILE_APPEND | LOCK_EX);

        http_response_code(403);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz parola.']);
        exit;
    }

    // Eski sunucu domain doğrulama
    if (empty($oldServerDomain)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Eski sunucu domain\'i gerekli.']);
        exit;
    }
    
    // Domain formatını düzenle ve URL parse et
    $oldServerDomain = trim($oldServerDomain);
    
    // Eğer tam URL girilmişse parse et
    if (preg_match('#^https?://#', $oldServerDomain)) {
        $parsedInput = parse_url($oldServerDomain);
        
        if (!$parsedInput || !isset($parsedInput['host'])) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Geçersiz URL formatı.']);
            exit;
        }
        
        $oldServerDomain = $parsedInput['host'];
        
        // Eğer path varsa ve /oldServer.php değilse hata ver
        if (isset($parsedInput['path']) && $parsedInput['path'] !== '/' && $parsedInput['path'] !== '/oldServer.php') {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Sadece domain adı veya oldServer.php URL\'si girin.']);
            exit;
        }
    } else {
        // Sadece domain girilmiş, protokol yok
        // Sondaki / varsa temizle
        $oldServerDomain = rtrim($oldServerDomain, '/');
        
        // Eğer /oldServer.php ile bitiyorsa temizle
        if (substr($oldServerDomain, -14) === '/oldServer.php') {
            $oldServerDomain = substr($oldServerDomain, 0, -14);
            $oldServerDomain = rtrim($oldServerDomain, '/');
        }
    }
    
    // Domain validasyonu
    if (empty($oldServerDomain)) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz domain formatı.']);
        exit;
    }
    
    // Geçerli domain formatı kontrolü (en az bir nokta içermeli)
    if (strpos($oldServerDomain, '.') === false) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Geçerli bir domain adı girin (örn: example.com).']);
        exit;
    }
    
    // Domain içinde path karakteri kalmamalı
    if (strpos($oldServerDomain, '/') !== false) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Sadece domain adı girin, path eklemeyin.']);
        exit;
    }
    
    // oldServer.php URL'ini oluştur
    $oldServerUrl = 'https://' . $oldServerDomain . '/oldServer.php';
    
    $ch = curl_init($oldServerUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 60,
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_USERAGENT => 'ErayCode File Transfer Script/1.0',
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_USERPWD => $validUsername . ':' . $validPassword,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    if ($httpCode !== 200 || $response === false) {
        http_response_code(500);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Eski sunucuya bağlanılamadı.',
            'http_code' => $httpCode,
            'error' => $curlError,
            'old_server_url' => $oldServerUrl
        ]);
        exit;
    }
    
    $oldServerResponse = json_decode($response, true);
    
    if (!$oldServerResponse || $oldServerResponse['status'] !== 'success' || empty($oldServerResponse['zip_url'])) {
        http_response_code(500);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Eski sunucudan geçersiz yanıt alındı.',
            'response' => $response
        ]);
        exit;
    }
    
    $fileUrl = $oldServerResponse['zip_url'];
    $expectedHash = $oldServerResponse['zip_hash'] ?? '';
    $zipFileName = $oldServerResponse['zip_file'] ?? '';
    
    // SSRF koruması - sadece HTTPS
    $parsedUrl = parse_url($fileUrl);
    if (!isset($parsedUrl['scheme']) || $parsedUrl['scheme'] !== 'https') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Sadece HTTPS URL\'leri kabul edilir.']);
        exit;
    }
    
    // Internal IP kontrolü (SSRF koruması)
    $urlHost = $parsedUrl['host'];
    $ip = gethostbyname($urlHost);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Internal IP adreslerine erişim yasak.']);
        exit;
    }

    // Dosyayı indirme - güvenli dosya adı
    $fileName = basename(parse_url($fileUrl, PHP_URL_PATH));
    
    // Path traversal koruması
    $fileName = str_replace(['..', '/', '\\'], '', $fileName);
    if (empty($fileName)) {
        $fileName = 'download_' . time() . '.zip';
    }
    
    // Sadece .zip dosyalarına izin ver
    $fileExt = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
    if ($fileExt !== 'zip') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Sadece .zip dosyaları indirilebilir.']);
        exit;
    }
    
    // Benzersiz dosya adı oluştur (üzerine yazma koruması)
    $uniqueFileName = pathinfo($fileName, PATHINFO_FILENAME) . '_' . bin2hex(random_bytes(4)) . '.' . $fileExt;
    $savePath = __DIR__ . '/downloads/' . $uniqueFileName;

    // downloads dizini yoksa oluştur ve .htaccess ile koru
    $downloadDir = __DIR__ . '/downloads';
    if (!is_dir($downloadDir)) {
        mkdir($downloadDir, 0755, true);
        // PHP çalıştırmayı engelle
        file_put_contents($downloadDir . '/.htaccess', "php_flag engine off\nOptions -Indexes", LOCK_EX);
    }
    
    // Dosya boyutunu kontrol et (HEAD request ile)
    $ch = curl_init($fileUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'ErayCode File Transfer Script/1.0',
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_USERPWD => $validUsername . ':' . $validPassword,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    curl_exec($ch);
    $fileSize = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    $headHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($headHttpCode !== 200) {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Dosya bilgisi alınamadı. HTTP: ' . $headHttpCode]);
        exit;
    }
    
    // Disk alanı kontrolü
    $freeSpace = disk_free_space(__DIR__);
    if ($fileSize > 0 && $freeSpace < $fileSize) {
        http_response_code(507);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Yetersiz disk alanı.',
            'required_space' => round($fileSize / 1024 / 1024, 2) . ' MB',
            'available_space' => round($freeSpace / 1024 / 1024, 2) . ' MB'
        ]);
        exit;
    }

    // CURL ile dosya indirme
    $ch = curl_init($fileUrl);
    $fp = fopen($savePath, 'wb');
    
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => false,
        CURLOPT_FILE => $fp,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_USERAGENT => 'ErayCode File Transfer Script/1.0',
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_USERPWD => $validUsername . ':' . $validPassword,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $downloadedSize = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
    $curlError = curl_error($ch);
    curl_close($ch);
    fclose($fp);
    
    if ($result === false || $httpCode !== 200) {
        unlink($savePath); // Başarısız dosyayı sil
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Dosya indirilemedi. HTTP: ' . $httpCode, 'error' => $curlError]);
        exit;
    }
    
    // İndirilen dosyanın hash'ini hesapla
    $downloadedHash = hash_file('sha256', $savePath);
    
    // Hash kontrolü
    if (!empty($expectedHash) && $downloadedHash !== $expectedHash) {
        unlink($savePath); // Bozuk dosyayı sil
        http_response_code(500);
        echo json_encode([
            'status' => 'error', 
            'message' => 'Dosya bütünlüğü doğrulanamadı! Hash eşleşmiyor.',
            'expected_hash' => $expectedHash,
            'downloaded_hash' => $downloadedHash
        ]);
        exit;
    }
    
    // Hash eşleşti, eski sunucuya silme isteği gönder
    $deleteResult = ['status' => 'not_attempted', 'message' => 'Silme isteği gönderilmedi.'];
    
    if (!empty($zipFileName)) {
        $deleteUrl = 'https://' . $oldServerDomain . '/oldServer.php';
        
        $ch = curl_init($deleteUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                '_method' => 'DELETE',
                'zip_file' => $zipFileName
            ]),
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'ErayCode File Transfer Script/1.0',
            CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
            CURLOPT_USERPWD => $validUsername . ':' . $validPassword,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        
        $deleteResponse = curl_exec($ch);
        $deleteHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($deleteHttpCode === 200 && $deleteResponse) {
            $deleteResult = json_decode($deleteResponse, true);
            if (!$deleteResult) {
                $deleteResult = ['status' => 'error', 'message' => 'Geçersiz yanıt', 'raw_response' => $deleteResponse];
            }
        } else {
            $deleteResult = [
                'status' => 'error', 
                'message' => 'Eski sunucuya silme isteği gönderilemedi.',
                'http_code' => $deleteHttpCode
            ];
        }
    }
    
    // Eski indirmeleri temizle (24 saatten eski)
    $oldFiles = glob($downloadDir . '/*');
    foreach ($oldFiles as $oldFile) {
        if (is_file($oldFile) && time() - filemtime($oldFile) > 86400) {
            unlink($oldFile);
        }
    }
    
    echo json_encode([
        'status' => 'success', 
        'message' => 'Dosya başarıyla indirildi ve doğrulandı.', 
        'file_name' => $uniqueFileName,
        'file_size' => $downloadedSize,
        'file_hash' => $downloadedHash,
        'hash_verified' => true,
        'old_server_domain' => $oldServerDomain,
        'old_server_cleanup' => $deleteResult,
        'warning' => 'Dosya 24 saat sonra otomatik silinecektir.'
    ]);
} else {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Yalnızca POST istekleri kabul edilir.']);
}
?>
<doctype html>
    <html lang="tr">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PHP Dosya TransferScripti</title>
    </head>

    <body>
        <h1>oldServer Dosyasını İndir</h1>
        <form method="POST" action="">
            <label for="password">Parola:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <label for="old_server_domain">Eski Sunucu Domain:</label><br>
            <input type="text" id="old_server_domain" name="old_server_domain" placeholder="eski-hosting.com" required><br><br>
            <input type="submit" value="Transfer Başlat">
        </form>
    </body>

    </html>