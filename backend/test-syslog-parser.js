const { parseSyslogMessage } = require('./dist/services/syslog/syslogParser.js');

const testMessage = '<134>Dec 09 18:16:01 komodo NGINX: [09/Dec/2025:18:16:00 +0000] - 200 200 - GET https stream.7pineapples.com';

console.log('Testing syslog parser...');
console.log('Input:', testMessage);
console.log('\n--- Parsed Result ---');
const result = parseSyslogMessage(testMessage);
console.log(JSON.stringify(result, null, 2));
console.log('\n--- Extracted Message ---');
console.log('Message field:', result.message);
