# LogHawk-Script

This script helps cyber-security analyst quickly scan log files for security threats, system errors, and usual activity.

Some features include:
- A brute force check which looks at SSH failed login attemps
- Web-Failed Logins - Displays specific 401 failure attempts 
- Unusual traffic - Which check's for IP address and whether it reaches threshold
- Critical system errors - which check for windows log events and if anything is out of the normal if they are CRITICAL or ERROR.
- Displays suspicious CRON actions and also filters for CMD actions securely monitoring it
- Displays total occurance of 404, 401, 200 comparitve to pre-determined sensor thresholds

How to use:
- For this python script run the following: python loghawk.py (with your file configuration in the program - mentioned in the "before use"

Setting up CRON:
- To have it running ensure that you use: crontab -e. This will set up a jobs
Set up job to your likeing ensure you FollowL
* * * * * /path/to/file/file.py > /var/spool/cron/crontabs/name_of_log_report.log >/dev/null 2>&1
  - * * * * * - Crontab syntax
  - /path/to/file/file.py - Path to file
  - /var/spool/cron/crontabs/name_of_log_report.log - Path to report log
  - /dev/null 2>&1 - responsible for reporting if successful.


Before you use loghawk Script:
- Make sure you have python 3
- Make sure you configure the log_file in the script to where your .txt file is.
- Make sure you adjust any additional status_count you want to check. Right now only looking at 404, 401, 200


