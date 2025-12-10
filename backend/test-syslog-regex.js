// Test to understand RFC 3164 regex matching issue

const testMessages = [
  'Dec 10 20:45:39 komodo NGINX: [10/Dec/2025:20:43:00 +0000] - 200 200 - GET https',
  'Dec 10 20:45:39 komodo NGINX: 2025/12/10 20:12:13 [warn] 1583#1583: *1858063 a c',
  'Dec 10 20:45:40 komodo NGINX: 198.235.24.182 - - [10/Dec/2025:20:32:55 +0000] "\\"',
  'Dec 10 20:45:41 komodo NGINX: [10/Dec/2025:19:45:23 +0000] 400 - GET http 73.155',
];

const rfc3164Pattern = /^(\S+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$/;

console.log('Testing RFC 3164 pattern matching:\n');

testMessages.forEach((msg, index) => {
  console.log(`Test ${index + 1}:`);
  console.log(`  Message: "${msg}"`);
  console.log(`  Length: ${msg.length}`);
  console.log(`  First space at: ${msg.indexOf(' ')}`);

  const match = msg.match(rfc3164Pattern);
  console.log(`  Match: ${match ? 'YES' : 'NO'}`);

  if (match) {
    console.log(`    Timestamp: "${match[1]}"`);
    console.log(`    Hostname: "${match[2]}"`);
    console.log(`    Rest: "${match[3].substring(0, 50)}"`);
  } else {
    // Debug why it failed
    const parts = msg.split(/\s+/);
    console.log(`    Split parts (first 5): ${parts.slice(0, 5).join(' | ')}`);

    // Test individual components
    const timestampTest = msg.match(/^(\S+\s+\d+\s+\d+:\d+:\d+)/);
    console.log(`    Timestamp part matches: ${timestampTest ? 'YES' : 'NO'}`);
    if (timestampTest) {
      const afterTimestamp = msg.substring(timestampTest[0].length);
      console.log(`    After timestamp: "${afterTimestamp}"`);
      console.log(`    Starts with space: ${/^\s/.test(afterTimestamp)}`);
    }
  }
  console.log('');
});
