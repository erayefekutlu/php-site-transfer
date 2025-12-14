<?php
/*
 * PHP Dosya TransferScripti
 * @author Eray Efe Kutlu
 * @license MIT
 * @version 1.0
 * @URL https://erayefekutlu.com
 * @description newServer dosyasının indirmesi için .zip dosyası ve url oluşturur.
 * @note İşlem bittikten sonra dosyayı sunucudan silin.
 */

// HTTPS kontrolü
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Sadece HTTPS bağlantıları kabul edilir.']);
    exit;
}

// HTTP BASIC AUTH kontrolü
$validUsername = 'admin'; // KESİNLİKLE DEĞİŞTİRİN!
$validPassword = 'securepassword123'; // KESİNLİKLE DEĞİŞTİRİN!
$secretKey = 'ec-oldserver-secret-key-change-this'; // KESİNLİKLE DEĞİŞTİRİN!
$allowedIPs = ['']; // İzin verilen IP adresleri, Yeni sunucunun ip adresini girin.

// DELETE isteği - Zip dosyasını sil
if ($_SERVER['REQUEST_METHOD'] === 'DELETE' || ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_method']) && $_POST['_method'] === 'DELETE')) {
    $zipFile = $_POST['zip_file'] ?? $_GET['zip_file'] ?? '';
    
    if (empty($zipFile)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Zip dosya adı gerekli.']);
        exit;
    }
    
    // Güvenlik: Sadece oldServer_ ile başlayan zip dosyaları silinebilir
    if (!preg_match('/^oldServer_[a-f0-9]{16}_\d+\.zip$/', $zipFile)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Geçersiz dosya adı.']);
        exit;
    }
    
    $zipPath = __DIR__ . '/' . $zipFile;
    
    if (!file_exists($zipPath)) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Dosya bulunamadı.']);
        exit;
    }
    
    if (unlink($zipPath)) {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'success', 'message' => 'Zip dosyası başarıyla silindi.', 'deleted_file' => $zipFile]);
    } else {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Dosya silinemedi.']);
    }
    exit;
}

// IP whitelist kontrolü
if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
} else {
    $clientIp = $_SERVER['REMOTE_ADDR'];
}

if (!in_array($clientIp, $allowedIPs)) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'IP adresi yetkili değil.']);
    exit;
}

// User-Agent kontrolü
if (!isset($_SERVER['HTTP_USER_AGENT']) || strpos($_SERVER['HTTP_USER_AGENT'], 'ErayCode File Transfer Script/1.0') === false) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Erişim reddedildi.']);
    exit;
}

// HTTP Basic Auth kontrolü ve Rate Limiting
if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) ||
    $_SERVER['PHP_AUTH_USER'] !== $validUsername || $_SERVER['PHP_AUTH_PW'] !== $validPassword) {
    
    // Yanlış kimlik bilgisi - Rate Limit uygula
    $ipHash = hash_hmac('sha256', $clientIp, $secretKey);
    $rateLimitFile = sys_get_temp_dir() . '/.ec_oldserver_rate_' . substr($ipHash, 0, 16) . '.dat';
    $maxAttempts = 3;
    $timeWindow = 600; // 10 dakika

    if (file_exists($rateLimitFile)) {
        $attempts = (int)file_get_contents($rateLimitFile);
        $fileTime = filemtime($rateLimitFile);
        
        if (time() - $fileTime < $timeWindow) {
            if ($attempts >= $maxAttempts) {
                http_response_code(429);
                header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => 'Çok fazla başarısız deneme. 10 dakika bekleyin.']);
                exit;
            }
            file_put_contents($rateLimitFile, $attempts + 1, LOCK_EX);
        } else {
            file_put_contents($rateLimitFile, 1, LOCK_EX);
        }
    } else {
        file_put_contents($rateLimitFile, 1, LOCK_EX);
    }
    
    header('WWW-Authenticate: Basic realm="Restricted Area"');
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Yetkilendirme gerekli.']);
    exit;
}

// zip eklentisi kontrolü
if (!extension_loaded('zip')) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Zip uzantısı etkin değil.']);
    exit;
}

// Hassas dosyaları zip'e ekleme
$excludeFiles = ['oldServer.php']; // Eklenmesini istemediğiniz dosya ve klasörler
$excludeExtensions = [];

// Eski zip dosyalarını temizle (1 saatten eski)
$oldZips = glob(__DIR__ . '/oldServer_*.zip');
foreach ($oldZips as $oldZip) {
    if (file_exists($oldZip) && time() - filemtime($oldZip) > 3600) {
        unlink($oldZip);
        if (file_exists($oldZip . '.delete')) {
            unlink($oldZip . '.delete');
        }
    }
}

// Dizindeki dosya ve klasörleri al
$files = scandir(__DIR__);
$zip = new ZipArchive();
$zipFileName = 'oldServer_' . bin2hex(random_bytes(8)) . '_' . time() . '.zip';
$zipFilePath = sys_get_temp_dir() . '/' . $zipFileName;
if ($zip->open($zipFilePath, ZipArchive::CREATE) !== TRUE) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Zip dosyası oluşturulamadı.']);
    exit;
}

foreach ($files as $file) {
    if ($file === '.' || $file === '..' || $file === $zipFileName) {
        continue;
    }
    
    // Hassas dosyaları atla
    $skip = false;
    foreach ($excludeFiles as $pattern) {
        if (strpos($pattern, '*') !== false) {
            if (fnmatch($pattern, $file)) {
                $skip = true;
                break;
            }
        } else {
            if ($file === $pattern) {
                $skip = true;
                break;
            }
        }
    }
    
    $fileExt = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    if (in_array($fileExt, $excludeExtensions)) {
        $skip = true;
    }
    
    if ($skip) {
        continue;
    }
    
    $filePath = __DIR__ . '/' . $file;
    
    // Symlink kontrolü
    if (is_link($filePath)) {
        continue;
    }
    
    if (is_dir($filePath)) {
        $zip->addEmptyDir($file);
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($filePath), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach ($iterator as $subFile) {
            if (!$subFile->isDir() && !is_link($subFile->getPathname())) {
                $subFileExt = strtolower(pathinfo($subFile->getFilename(), PATHINFO_EXTENSION));
                if (!in_array($subFileExt, $excludeExtensions)) {
                    $relativePath = $file . '/' . substr($subFile->getPathname(), strlen($filePath) + 1);
                    $zip->addFile($subFile->getPathname(), $relativePath);
                }
            }
        }
    } else {
        $zip->addFile($filePath, $file);
    }
}
$zip->close();

// Zip dosyasını web dizinine kopyala
$webZipPath = __DIR__ . '/' . $zipFileName;
copy($zipFilePath, $webZipPath);
unlink($zipFilePath);

// Zip dosyasının hash'ini hesapla
$zipHash = hash_file('sha256', $webZipPath);

header('Content-Type: application/json');
echo json_encode([
    'status' => 'success',
    'message' => 'Zip dosyası oluşturuldu.',
    'zip_url' => 'https://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['REQUEST_URI']) . '/' . $zipFileName,
    'zip_hash' => $zipHash,
    'zip_file' => $zipFileName
]);