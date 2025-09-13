Security Rules
Rule ID
	Rule Name
	ESLint
	SunLint
	OpenAI
	sunlint-vscode
	Picked
	Done

S001
	Fail securely when access control errors occur
	✅
	-
	-
	✅

	*

S002
	Avoid IDOR vulnerabilities in CRUD operations
	✅
	-
	-
	✅

	*

S003
	URL redirects must be within an allow list
	✅
	-
	-
	✅

	*

S004
	Do not log login credentials, payment information, and unencrypted tokens
	-
	-
	-
	✅

	*

S005
	Do not use Origin header for authentication or access control
	✅
	✅
	-
	✅
	NgocP
	*

S006
	Do not send recovery or activation codes in plaintext
	✅
	✅
	-
	✅
	NgocP
	*

S007
	Do not store OTP codes in plaintext
	✅
	✅
	-
	✅
	NgocP
	*

S008
	Encryption algorithms and parameters must support flexible configuration and upgrades
	✅
	-
	-
	✅

	*

S009
	Do not use insecure encryption modes, padding, or cryptographic algorithms
	✅
	✅
	-
	✅
	NgocP
	*

S010
	Must use cryptographically secure random number generators (CSPRNG) for security purposes
	✅
	✅
	-
	✅
	NgocP
	*

S011
	GUIDs used for security purposes must be generated according to UUID v4 standard with CSPRNG
	✅
	-
	-
	✅

	*

S012
	Protect secrets and encrypt sensitive data
	✅
	-
	-
	✅

	*

S013
	Always use TLS for all connections
	✅
	-
	-
	✅

	*

S014
	Only use TLS 1.2 or 1.3
	✅
	-
	-
	✅

	*

S015
	Only accept trusted TLS certificates and eliminate weak ciphers
	✅
	✅
	-
	✅

	*

S016
	Do not pass sensitive data via query string
	✅
	✅
	-
	✅
	An
	*

S017
	Always use parameterized queries
	✅
	✅
	-
	✅
	An
	*

S018
	Prefer Allow List for Input Validation
	✅
	-
	-
	✅

	*

S019
	Sanitize input before sending emails to prevent SMTP Injection
	✅
	-
	-
	✅

	*

S020
	Avoid using eval() or executing dynamic code
	✅
	-
	-
	✅

	*

S021
	Sanitize user-generated Markdown, CSS, and XSL content
	-
	-
	-
	✅

	*

S022
	Escape data properly based on output context
	✅
	-
	-
	✅

	*

S023
	Prevent JSON Injection and JSON eval attacks
	✅
	✅
	-
	✅

	*

S024
	Protect against XPath Injection and XML External Entity (XXE)
	-
	✅
	-
	✅
	NgocP
	*

S025
	Always validate client-side data on the server
	✅
	✅
	-
	✅
	NgocP
	*

S026
	Apply JSON Schema Validation to input data
	✅
	✅
	-
	✅

	*

S027
	Never expose secrets in source code or Git
	✅
	✅
	-
	✅

	*

S028
	Limit upload file size and number of files per user
	-
	inprogress
	-
	✅
	NgocP
	*

S029
	Apply CSRF protection for authentication-related features
	✅
	✅
	-
	✅

	*

S030
	Disable directory browsing and protect sensitive metadata files
	✅
	-
	-
	✅

	*

S031
	Set Secure flag for Session Cookies to protect via HTTPS
	-
	✅
	-
	✅
	An
	*

S032
	Set HttpOnly attribute for Session Cookies to prevent JavaScript access
	-
	✅
	-
	✅
	An
	*

S033
	Set SameSite attribute for Session Cookies to reduce CSRF risk
	✅
	✅
	-
	✅
	An
	*

S034
	Use __Host- prefix for Session Cookies to prevent subdomain sharing
	✅
	✅
	-
	✅
	An
	*

S035
	Set Path attribute for Session Cookies to limit access scope
	✅
	✅
	-
	✅
	An
	*

S036
	Prevent LFI and RFI by controlling paths and using allow lists
	✅
	-
	-
	✅

	*

S037
	Configure comprehensive cache headers to prevent sensitive data leakage
	✅
	-
	-
	✅

	*

S038
	Do not expose version information in response headers
	✅
	-
	-
	✅

	*

S039
	Do not pass Session Tokens via URL parameters
	✅
	-
	-
	✅

	*

S040
	Generate new Session Token after user login to prevent Session Fixation attacks
	-
	-
	-
	✅

	*

S041
	Session Tokens must be invalidated after logout or expiration
	✅
	inprogress
	-
	✅
	NgocP
	*

S042
	Long-term sessions need periodic re-authentication or when performing sensitive actions
	✅
	-
	-
	✅

	*

S043
	Password changes must invalidate all other login sessions
	✅
	-
	-
	✅

	*

S044
	Yêu cầu xác thực lại trước khi thay đổi thông tin quan trọng
	✅
	inprogress
	-
	✅
	NgocP
	*

S045
	Bảo vệ chống đoán mật khẩu tự động (Brute-force Protection)
	✅
	-
	-
	✅

	*

S046
	Gửi thông báo khi có thay đổi quan trọng trong tài khoản
	✅
	-
	-
	✅

	*

S047
	Bảo vệ mã tạm thời và mật khẩu kích hoạt
	✅
	-
	-
	✅

	*

S048
	Không tiết lộ mật khẩu hiện tại trong quy trình đặt lại mật khẩu
	✅
	✅
	-
	✅
	Ngoc
	*

S049
	Mã xác thực chỉ có hiệu lực trong thời gian ngắn
	-
	✅
	-
	✅
	Ngoc
	*

S050
	Session Token phải có entropy tối thiểu 64-bit và sử dụng thuật toán an toàn
	✅
	-
	-
	✅

	*

S051
	Hỗ trợ mật khẩu dài từ 12–64 ký tự, từ chối nếu >128 ký tự
	-
	-
	-
	✅

	*

S052
	OTP phải có ít nhất 20-bit entropy để tránh bị đoán
	✅
	-
	-
	✅

	*

S053
	Chỉ sử dụng thuật toán OTP an toàn như HOTP/TOTP
	-
	-
	-
	✅

	*

S054
	Không sử dụng tài khoản mặc định như "admin", "root", "sa"
	✅
	-
	-
	✅

	*

S055
	Kiểm tra Content-Type đầu vào trong dịch vụ REST
	✅
	✅
	-
	✅
	NgocP
	*

S056
	Bảo vệ chống tấn công Log Injection
	-
	✅
	-
	✅
	NgocP
	*

S057
	Ghi log với thời gian đồng bộ và sử dụng múi giờ UTC
	✅
	✅
	-
	✅
	HoaiBN
	*

S058
	Bảo vệ ứng dụng khỏi tấn công SSRF
	✅
	✅
	-
	✅
	HoaiBN
	*

S059
	Cấu hình Allow List cho tài nguyên truy cập từ Server
	-
	-
	-
	✅

	*

