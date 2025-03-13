# LogHawk-Script

This script helps cyber-security analyst quickly scan log files for security threats, system errors, and usual activity.

Some features include:
- A brute force check which looks at SSH failed login attemps
- Web-Failed Logins - Displays specific 401 failure attempts 
- Unusual traffic - Which check's for IP address and whether it reaches threshold
- Critical system errors - which check for windows log events and if anything is out of the normal if they are CRITICAL or ERROR.
- Displays suspicious CRON actions and also filters for CMD actions securely monitoring it
- Displays total occurance of 404, 401, 200 comparitve to pre-determined sensor thresholds
