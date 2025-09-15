<?php
/**
 * OWASP S007 - OTP Plaintext Vulnerability Examples
 * This file contains examples of vulnerable OTP code storage patterns
 */

// Example 1: Basic OTP assignment in plaintext
$otp_code = "123456";
$verification_code = "789012";
$sms_code = "345678";

// Example 2: CakePHP 3 specific patterns
class OtpController extends AppController
{
    public function verifyOtp()
    {
        // Vulnerable: OTP from request data stored as plaintext
        $otp = $this->request->getData('otp');
        $this->Session->write('user_otp', '123456');
        
        // Vulnerable: Flash message with OTP
        $this->Flash->set('Your OTP is: 789012');
        
        // Vulnerable: Configuration with OTP
        Configure::write('default_otp', '345678');
        
        // Vulnerable: Model save with OTP
        $this->loadModel('Users');
        $user = $this->Users->newEntity([
            'otp_code' => '456789',
            'verification_code' => '567890'
        ]);
        $this->Users->save($user);
        
        // Vulnerable: Auth user with OTP
        $userOtp = $this->Auth->user('otp');
        
        // Vulnerable: Direct echo of OTP
        echo "Your OTP is: " . $otp;
        
        // Vulnerable: Print OTP
        print "Verification code: " . $verification_code;
        
        // Vulnerable: Log OTP
        error_log("OTP generated: " . $sms_code);
        
        // Vulnerable: File write with OTP
        file_put_contents('otp_log.txt', "OTP: " . $otp);
        
        // Vulnerable: Mail with OTP
        mail('user@example.com', 'OTP Code', 'Your OTP is: ' . $otp);
        
        // Vulnerable: JSON encode with OTP
        $response = json_encode(['otp' => $otp, 'status' => 'success']);
        
        // Vulnerable: Session write with OTP
        $this->Session->write('otp_data', $otp);
        
        // Vulnerable: Cookie with OTP
        setcookie('otp', $otp, time() + 3600);
        
        // Vulnerable: Serialize with OTP
        $data = serialize(['otp' => $otp, 'user_id' => 123]);
    }
    
    public function generateOtp()
    {
        // Vulnerable: TOTP secret in plaintext
        $totp_secret = "JBSWY3DPEHPK3PXP";
        $totp_code = "123456";
        
        // Vulnerable: Database insert with OTP
        $this->loadModel('OtpCodes');
        $otpEntity = $this->OtpCodes->newEntity([
            'user_id' => 1,
            'otp_code' => '789012',
            'expires_at' => date('Y-m-d H:i:s', strtotime('+5 minutes'))
        ]);
        $this->OtpCodes->save($otpEntity);
        
        // Vulnerable: Update with OTP
        $this->OtpCodes->updateAll(
            ['otp_code' => '345678'],
            ['user_id' => 1]
        );
        
        // Vulnerable: Query with OTP
        $otpRecord = $this->OtpCodes->find()
            ->where(['otp_code' => '567890'])
            ->first();
    }
}

// Example 3: Configuration file patterns
$config = [
    'otp' => [
        'default_code' => '123456',
        'verification_code' => '789012',
        'sms_code' => '345678'
    ],
    'totp' => [
        'secret' => 'JBSWY3DPEHPK3PXP',
        'issuer' => 'MyApp'
    ]
];

// Example 4: Function return with OTP
function getOtpCode() {
    return "123456";
}

function getVerificationCode() {
    return "789012";
}

// Example 5: Class property with OTP
class OtpService
{
    private $otpCode = "123456";
    private $verificationCode = "789012";
    
    public function generateOtp()
    {
        $otp = "345678";
        return $otp;
    }
    
    public function validateOtp($inputOtp)
    {
        $storedOtp = "567890";
        return $inputOtp === $storedOtp;
    }
}

// Example 6: Array with OTP
$otpData = [
    'user_id' => 1,
    'otp_code' => '123456',
    'verification_code' => '789012',
    'sms_code' => '345678'
];

// Example 7: String concatenation with OTP
$message = "Your OTP is: " . $otp_code;
$emailBody = "Please use this verification code: " . $verification_code;

// Example 8: Conditional with OTP
if ($otp_code === "123456") {
    echo "OTP is correct";
}

// Example 9: Loop with OTP
for ($i = 0; $i < 3; $i++) {
    echo "Attempt " . ($i + 1) . " - OTP: " . $otp_code;
}

// Example 10: Method call with OTP
$result = processOtp($otp_code);
$response = sendSms($sms_code);
