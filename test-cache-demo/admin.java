// Java file with SQL injection
public class UserQuery {
    public void getUser(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        // SQL injection vulnerability
    }
}
EOFecho ""
echo "📁 Created test files:"
echo "  - test-cache-demo/sample.go (Go with SQL injection vulnerability)"
echo "  - test-cache-demo/sample.php (PHP with multiple vulnerabilities)"

echo ""
echo "⏱️  First scan with 3 file limit (building symbol tables)..."
time ./security-scanner test-cache-demo --verbose --allow-dir test-cache-demo --max-files 3 2>/dev/null

echo ""
echo "⚡ Second scan with 3 file limit (using cached symbol tables)..."
time ./security-scanner test-cache-demo --verbose --allow-dir test-cache-demo --max-files 3 2>/dev/null

echo ""
echo "📊 Cache statistics:"
if [ -d ".security-scanner-cache" ]; then
    echo "  - Cache directory: .security-scanner-cache"
    echo "  - Cache files: $(find .security-scanner-cache -name "*.json" | wc -l)"
    echo "  - Total cache size: $(du -sh .security-scanner-cache 2>/dev/null | cut -f1)"
else
    echo "  - No cache directory found"
fi

echo ""
echo "🗑️  Cleanup test files..."
rm -rf test-cache-demo

echo ""
echo "✅ Demo completed!"
echo ""
echo "💡 Performance Tips:"
echo "  - Use --allow-dir to scan only specific directories"
echo "  - Use --exclude-dir to skip large build/vendor directories"
echo "  - Cache is automatically managed (1GB max, 7 days retention)"
echo "  - Use --no-cache to disable caching for CI/testing"
echo "  - Use --cache-dir to specify custom cache location"
