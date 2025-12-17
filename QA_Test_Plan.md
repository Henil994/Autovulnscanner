# QA Test Plan – Autovulnscanner

## Objective
Validate Autovulnscanner's scanning, reporting, and GUI functionality.

## Scope
- Tool integrations (Nmap, Nikto, SQLMap, WHOIS, YARA, VirusTotal)
- GUI operation
- Report generation

## Test Types
- Functional Testing
- GUI Usability Testing
- Integration Testing
- Error Handling & Boundary Testing
- Performance Testing

## Test Cases
| ID    | Test Case Description              | Steps                                                      | Expected Result                                      | Status |
|-------|-------------------------------------|-------------------------------------------------------------|------------------------------------------------------|--------|
| TC001 | Nmap scan valid host                | Input `scanme.nmap.org`                                    | Displays open ports                                 | Pass   |
| TC002 | Invalid host scan                   | Input `invalidhost`                                        | Error message shown                                 | Pass   |
| TC003 | Nikto scan                          | Target `http://testphp.vulnweb.com`                        | Detects vulnerabilities                             | Pass   |
| TC004 | SQLMap injection test               | Target vulnerable form                                     | SQL injection found                                 | Pass   |
| TC005 | VirusTotal malicious file scan      | Upload `eicar.com`                                         | Flags as malicious                                  | Pass   |
| TC006 | YARA suspicious file scan           | Upload malware sample                                      | Matches YARA rule                                   | Pass   |
| TC007 | Report export                       | Export after scan                                          | Creates `.md` or `.pdf` file without errors         | Pass   |
| TC008 | GUI responsiveness                  | Resize window, navigate tabs                               | UI adjusts without breaking                         | Pass   |

## Tools Used
- Pytest
- Nmap, Nikto, SQLMap
- VirusTotal API
- YARA Rules
- Manual QA Checklist

## Pass/Fail Criteria
- Pass: All tools work as expected, no crashes
- Fail: Any major integration breaks
