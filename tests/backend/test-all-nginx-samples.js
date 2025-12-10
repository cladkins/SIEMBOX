const { parseSyslogMessage } = require('./dist/services/syslog/syslogParser.js');

const samples = [
  '<134>Dec 09 20:36:20 komodo NGINX: [09/Dec/2025:20:35:53 +0000] - 200 200 - GET',
  '<134>Dec 09 20:36:19 komodo NGINX: [09/Dec/2025:20:12:14 +0000] 301 - GET http w',
  '<134>Dec 09 20:36:19 komodo NGINX: 2025/12/08 19:37:36 [error] 1484#1484: *17597',
  '<134>Dec 09 19:52:03 komodo NGINX: 68.218.17.107 -'
];

console.log('=== NGINX LOG SAMPLES AFTER SYSLOG EXTRACTION ===\n');

let i = 1;
for (const sample of samples) {
  console.log('Sample ' + i + ':');
  console.log('Original:', sample);
  const parsed = parseSyslogMessage(sample);
  console.log('Extracted message:', parsed.message);
  console.log('');
  i++;
}
