rule Detect_Evil_Strings
{
    meta:
        description = "Detects files with suspicious keywords"
        author = "Shams"
        date = "2025-07-29"

    strings:
        $evil1 = "malware"
        $evil2 = "backdoor"
        $evil3 = "ransom"
        $evil4 = "cmd.exe"
        $evil5 = "powershell"

    condition:
        any of them
}
