# OWASP S007 - Do not store OTP codes in plaintext

## Mô tả
Rule S007 phát hiện việc lưu trữ OTP (One-Time Password) codes dưới dạng plaintext, đây là một lỗ hổng bảo mật nghiêm trọng có thể dẫn đến việc rò rỉ thông tin nhạy cảm.

## Tại sao đây là vấn đề?
- OTP codes được sử dụng để xác thực người dùng
- Lưu trữ OTP dưới dạng plaintext cho phép kẻ tấn công dễ dàng truy cập
- Vi phạm nguyên tắc bảo mật "defense in depth"
- Có thể dẫn đến tài khoản bị xâm phạm

## Các pattern được phát hiện

### 1. Basic OTP Patterns
```php
$otp_code = "123456";
$verification_code = "789012";
$sms_code = "345678";
```

### 2. CakePHP 3 Specific Patterns
```php
// Request data
$otp = $this->request->getData('otp');

// Session storage
$this->Session->write('user_otp', '123456');

// Flash messages
$this->Flash->set('Your OTP is: 789012');

// Configuration
Configure::write('default_otp', '345678');

// Model operations
$this->loadModel('Users');
$user = $this->Users->newEntity(['otp_code' => '456789']);
```

### 3. Dangerous Sink Patterns
```php
// Output functions
echo "Your OTP is: " . $otp;
print "Verification code: " . $verification_code;
var_dump($otp);

// File operations
file_put_contents('otp_log.txt', "OTP: " . $otp);

// Network operations
mail('user@example.com', 'OTP Code', 'Your OTP is: ' . $otp);

// Serialization
$response = json_encode(['otp' => $otp]);
$data = serialize(['otp' => $otp]);
```

## Cách khắc phục

### 1. Sử dụng Hashing
```php
// Thay vì
$otp_code = "123456";

// Sử dụng
$otp = random_int(100000, 999999);
$hashedOtp = password_hash($otp, PASSWORD_BCRYPT);
$_SESSION['otp_hash'] = $hashedOtp;
```

### 2. CakePHP 3 Secure Implementation
```php
// Secure OTP generation
$otp = random_int(100000, 999999);
$hashedOtp = Security::hash($otp);

// Secure storage
$otpEntity = $this->OtpCodes->newEntity([
    'user_id' => $userId,
    'otp_hash' => $hashedOtp,
    'expires_at' => new \DateTime('+5 minutes')
]);
```

### 3. TOTP Implementation
```php
class TotpService
{
    public function generateCode($timestamp = null)
    {
        $timeSlice = floor($timestamp / 30);
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $timeSlice), $this->secret, true);
        // ... implementation
    }
}
```

### 4. Environment Variables
```php
// Configuration
$config = [
    'otp' => [
        'secret' => env('OTP_SECRET'),
        'issuer' => env('OTP_ISSUER', 'MyApp'),
        'expiry' => env('OTP_EXPIRY', 300)
    ]
];
```

## CFG Analysis Features

Rule S007 sử dụng CFG (Control Flow Graph) analysis để:

1. **Tìm nguồn OTP**: Phát hiện các biến chứa OTP codes
2. **Theo dõi data flow**: Theo dõi luồng dữ liệu từ nguồn đến sink
3. **Phát hiện sink nguy hiểm**: Tìm các hàm có thể rò rỉ OTP
4. **Đánh giá rủi ro**: Xác định mức độ nghiêm trọng của lỗ hổng

## Các file ví dụ

- `vulnerable/otp_plaintext_vulnerable.php`: Các ví dụ lỗ hổng
- `clean/otp_plaintext_safe.php`: Các ví dụ an toàn

## Cấu hình

Rule S007 được cấu hình với:
- **Severity**: High
- **CWE**: CWE-798
- **OWASP**: A02:2021 (Cryptographic Failures)
- **Languages**: PHP, JavaScript, Python, Java, C#, Go

## Khuyến nghị

1. Luôn hash OTP codes trước khi lưu trữ
2. Sử dụng thời gian hết hạn cho OTP
3. Implement rate limiting cho OTP requests
4. Sử dụng environment variables cho secrets
5. Regular cleanup expired OTP codes
6. Log security events (không log OTP values)
