
#BDOS Baseline deviation ratio and alert threshold
DET_MARGIN_RATIO = 0.3 #sets the virtual baseline ratio. For example 1 = Virtual baseline is the same as the actual baseline (100% of the actual Normal bassline), 0.3 = 30% etc.
DET_ALARM_THRESHOLD = 10 #sets threshold for the number of occurances where the actual traffic went above the Virtual baseline. In case there were more occurrences than the defined threshold, these policies and protocols will be listed in the “low_bdos_baselines.csv”
DURATION = 6 # sets the time frame in days for the data collection period

VISION_IP = "1.1.1.1" # APSolute Vision IP
VISION_USER = "radware" # APSolute Vision username
VISION_PASS = "radware" # APSolute Vision password

# Log set up parameters
LOG_FILE_PATH = "./log/" # folder to save the script logging events
LOG_ROTATION_SIZE = 20000000 # Maximum rotation log file size in Bytes after which it will be split to another file
LOG_ROTATION_HISTORY = 10 # Maximum amount of files to keep
SYSLOG_SERVER = "2.2.2.2" # Syslog server destination IP
SYSLOG_PORT = 514 # Syslog server destination UDP port

# Email set up parameters for sending email with reports
SMTP_SERVER = "smtp.gmail.com" # SMTP server name
SMTP_SERVER_PORT = 587 # SMTP server port
SMTP_SENDER = 'example@gmail.com' # Email sender address setting
SMTP_PASSWORD = 'Radware123' # Email password (optional)
SMTP_LIST = ['someemail@radware.com'] # Email address/address list recepient/s(comma separated)
SMTP_SUBJECT_PREFIX = "ALARM:DP - " # Email Subject
SMTP_MSG_BODY = "This email was automated by the DefensePro monitoring script" # Email message body