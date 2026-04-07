// Standalone sample strings for the converter page.
// Deliberately decoupled from the Detection data model so converter/page.tsx
// does not break if the Detection interface or detections array changes.

export const sigmaSample = `title: Suspicious PowerShell Encoded Command
id: det-001
status: stable
description: Detects PowerShell with base64 encoded -EncodedCommand parameter
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Detection Engineering Team
date: 2024/11/15
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -EncodedCommand '
      - ' -enc '
      - ' -ec '
  condition: selection
falsepositives:
  - Legitimate automation scripts using encoded commands
  - Software deployment tools
level: high`;

export const splunkSample = `index=endpoint sourcetype=WinEventLog:Security EventCode=4688
  Image="*\\powershell.exe"
  (CommandLine="* -EncodedCommand *" OR CommandLine="* -enc *" OR CommandLine="* -ec *")
| eval decoded_cmd=base64decode(mvindex(split(CommandLine, " "), -1))
| table _time, host, user, CommandLine, decoded_cmd, ParentImage
| sort -_time`;

export const pysparkSample = `from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower, when, base64, regexp_extract

spark = SparkSession.builder.appName("PowerShellEncodedCmd").getOrCreate()

df = spark.read.parquet("s3://security-lake/endpoint/process_creation/")

detections = df.filter(
    lower(col("image")).endswith("\\\\powershell.exe")
).filter(
    lower(col("command_line")).contains("-encodedcommand") |
    lower(col("command_line")).rlike("\\\\s-enc\\\\s") |
    lower(col("command_line")).rlike("\\\\s-ec\\\\s")
).select(
    "timestamp", "host", "user", "command_line",
    "parent_image", "process_id"
).withColumn("severity", lit("high"))

detections.write.mode("append").parquet("s3://detections/output/")`;
