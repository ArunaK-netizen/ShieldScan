rule SuspiciousFile
{
    strings:
        $malicious_string = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $suspicious_func = "system("
    condition:
        $malicious_string or $suspicious_func
}
