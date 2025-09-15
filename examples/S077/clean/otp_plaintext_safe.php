<?php
/**
 * OWASP S007 - OTP Plaintext Safe Examples
 * This file contains examples of secure OTP code storage patterns
 */

use Cake\Utility\Security;
use Cake\ORM\TableRegistry;

// Example 1: Secure OTP generation and storage
class SecureOtpService
{
    private $expiry = 300; // 5 minutes
    
    public function generateOtp($userId)
    {
        $otp = random_int(100000, 999999);
        $hashedOtp = password_hash($otp, PASSWORD_BCRYPT);
        
        // Store hashed OTP with expiry
        $_SESSION['otp_hash'] = $hashedOtp;
        $_SESSION['otp_expiry'] = time() + $this->expiry;
        
        return $otp;
    }
    
    public function verifyOtp($inputOtp)
    {
        if (!isset($_SESSION['otp_hash']) || !isset($_SESSION['otp_expiry'])) {
            return false;
        }
        
        if (time() > $_SESSION['otp_expiry']) {
            unset($_SESSION['otp_hash'], $_SESSION['otp_expiry']);
            return false;
        }
        
        $isValid = password_verify($inputOtp, $_SESSION['otp_hash']);
        
        if ($isValid) {
            unset($_SESSION['otp_hash'], $_SESSION['otp_expiry']);
        }
        
        return $isValid;
    }
}

// Example 2: CakePHP 3 secure implementation
class SecureOtpController extends AppController
{
    public function verifyOtp()
    {
        // Secure: Use environment variables
        $otpSecret = env('OTP_SECRET', 'default-secret');
        
        // Secure: Generate OTP with proper randomness
        $otp = $this->generateSecureOtp();
        
        // Secure: Hash OTP before storage
        $hashedOtp = Security::hash($otp);
        
        // Secure: Store in database with proper hashing
        $this->loadModel('OtpCodes');
        $otpEntity = $this->OtpCodes->newEntity([
            'user_id' => $this->Auth->user('id'),
            'otp_hash' => $hashedOtp,
            'expires_at' => new \DateTime('+' . $this->expiry . ' seconds'),
            'created_at' => new \DateTime()
        ]);
        $this->OtpCodes->save($otpEntity);
        
        // Secure: Send OTP via secure channel (not stored)
        $this->sendOtpViaSms($otp);
        
        // Secure: No direct output of OTP
        $this->Flash->success('OTP sent to your phone');
        
        return $this->redirect(['action' => 'verify']);
    }
    
    private function generateSecureOtp()
    {
        return random_int(100000, 999999);
    }
    
    private function sendOtpViaSms($otp)
    {
        // Send via SMS service without storing
        $smsService = new SmsService();
        $smsService->send($this->Auth->user('phone'), "Your OTP is: $otp");
    }
    
    public function validateOtp()
    {
        $inputOtp = $this->request->getData('otp');
        
        if (empty($inputOtp)) {
            $this->Flash->error('OTP is required');
            return $this->redirect(['action' => 'verify']);
        }
        
        // Secure: Validate against hashed OTP
        $otpTable = TableRegistry::getTableLocator()->get('OtpCodes');
        $otpEntity = $otpTable->find()
            ->where(['user_id' => $this->Auth->user('id')])
            ->where(['expires_at >' => new \DateTime()])
            ->order(['created_at' => 'DESC'])
            ->first();
            
        if (!$otpEntity) {
            $this->Flash->error('Invalid or expired OTP');
            return $this->redirect(['action' => 'verify']);
        }
        
        $isValid = Security::hash($inputOtp) === $otpEntity->otp_hash;
        
        if ($isValid) {
            $otpTable->delete($otpEntity);
            $this->Flash->success('OTP verified successfully');
            return $this->redirect(['action' => 'dashboard']);
        } else {
            $this->Flash->error('Invalid OTP');
            return $this->redirect(['action' => 'verify']);
        }
    }
}

// Example 3: TOTP implementation
class TotpService
{
    private $secret;
    private $issuer;
    
    public function __construct($secret, $issuer = 'MyApp')
    {
        $this->secret = $secret;
        $this->issuer = $issuer;
    }
    
    public function generateSecret()
    {
        // Generate secure random secret
        return base32_encode(random_bytes(20));
    }
    
    public function generateCode($timestamp = null)
    {
        if ($timestamp === null) {
            $timestamp = time();
        }
        
        $timeSlice = floor($timestamp / 30);
        $hash = hash_hmac('sha1', pack('N*', 0) . pack('N*', $timeSlice), $this->secret, true);
        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
        
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
    
    public function verifyCode($code, $timestamp = null)
    {
        if ($timestamp === null) {
            $timestamp = time();
        }
        
        // Allow 30-second window
        for ($i = -1; $i <= 1; $i++) {
            if ($this->generateCode($timestamp + ($i * 30)) === $code) {
                return true;
            }
        }
        
        return false;
    }
}

// Example 4: Configuration with environment variables
$config = [
    'otp' => [
        'secret' => env('OTP_SECRET'),
        'issuer' => env('OTP_ISSUER', 'MyApp'),
        'expiry' => env('OTP_EXPIRY', 300)
    ],
    'sms' => [
        'api_key' => env('SMS_API_KEY'),
        'api_secret' => env('SMS_API_SECRET')
    ]
];

// Example 5: Secure OTP validation
class OtpValidator
{
    public function validate($otp, $userId)
    {
        // Check format
        if (!preg_match('/^\d{6}$/', $otp)) {
            return false;
        }
        
        // Check against stored hash
        $otpTable = TableRegistry::getTableLocator()->get('OtpCodes');
        $otpEntity = $otpTable->find()
            ->where(['user_id' => $userId])
            ->where(['expires_at >' => new \DateTime()])
            ->order(['created_at' => 'DESC'])
            ->first();
            
        if (!$otpEntity) {
            return false;
        }
        
        return Security::hash($otp) === $otpEntity->otp_hash;
    }
}

// Example 6: Rate limiting for OTP requests
class OtpRateLimiter
{
    private $maxAttempts = 3;
    private $timeWindow = 300; // 5 minutes
    
    public function canRequestOtp($userId)
    {
        $attempts = $this->getAttempts($userId);
        return $attempts < $this->maxAttempts;
    }
    
    public function recordAttempt($userId)
    {
        $key = "otp_attempts_$userId";
        $attempts = $this->getAttempts($userId) + 1;
        $_SESSION[$key] = [
            'count' => $attempts,
            'timestamp' => time()
        ];
    }
    
    private function getAttempts($userId)
    {
        $key = "otp_attempts_$userId";
        if (!isset($_SESSION[$key])) {
            return 0;
        }
        
        $data = $_SESSION[$key];
        if (time() - $data['timestamp'] > $this->timeWindow) {
            unset($_SESSION[$key]);
            return 0;
        }
        
        return $data['count'];
    }
}

// Example 7: Secure OTP cleanup
class OtpCleanupService
{
    public function cleanupExpiredOtps()
    {
        $otpTable = TableRegistry::getTableLocator()->get('OtpCodes');
        $expiredOtps = $otpTable->find()
            ->where(['expires_at <' => new \DateTime()])
            ->toArray();
            
        foreach ($expiredOtps as $otp) {
            $otpTable->delete($otp);
        }
        
        return count($expiredOtps);
    }
}

// Helper function for base32 encoding
function base32_encode($data)
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output = '';
    $v = 0;
    $vbits = 0;
    
    for ($i = 0, $j = strlen($data); $i < $j; $i++) {
        $v <<= 8;
        $v += ord($data[$i]);
        $vbits += 8;
        
        while ($vbits >= 5) {
            $vbits -= 5;
            $output .= $alphabet[$v >> $vbits];
            $v &= ((1 << $vbits) - 1);
        }
    }
    
    if ($vbits > 0) {
        $v <<= (5 - $vbits);
        $output .= $alphabet[$v];
    }
    
    return $output;
}
