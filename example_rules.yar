/*
    Example Yara Rules for Sanitizer Engine
    These rules detect common malware patterns and suspicious files.
*/

rule Suspicious_PE_Headers
{
    meta:
        description = "Detects suspicious PE file characteristics"
        author = "Sanitizer Engine"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
        
    condition:
        $mz at 0 and $pe
}

rule Embedded_Executable
{
    meta:
        description = "Detects embedded executable in non-PE file"
        author = "Sanitizer Engine"
        severity = "high"
        category = "suspicious"
    
    strings:
        $mz = "MZ"
        
    condition:
        $mz and not ($mz at 0)
}

rule Suspicious_Obfuscation
{
    meta:
        description = "Detects common obfuscation techniques"
        author = "Sanitizer Engine"
        severity = "medium"
        category = "obfuscation"
    
    strings:
        $base64_1 = /[A-Za-z0-9+\/]{50,}={0,2}/ nocase
        $xor_loop = { 30 ?? 40 75 ?? }  // xor + inc + jnz pattern
        
    condition:
        any of them
}

rule Ransomware_Keywords
{
    meta:
        description = "Detects common ransomware-related strings"
        author = "Sanitizer Engine"
        severity = "critical"
        category = "ransomware"
    
    tags:
        ransomware malware
    
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = ".locked" nocase
        $r5 = "ransom" nocase
        $r6 = "restore your files" nocase
        
    condition:
        3 of them
}

rule Webshell_PHP
{
    meta:
        description = "Detects common PHP webshell patterns"
        author = "Sanitizer Engine"
        severity = "high"
        category = "webshell"
    
    tags:
        webshell backdoor
    
    strings:
        $php = "<?php"
        $eval = "eval("
        $base64_decode = "base64_decode("
        $system = "system("
        $exec = "exec("
        $shell_exec = "shell_exec("
        $passthru = "passthru("
        
    condition:
        $php and ($eval or $base64_decode) and 2 of ($system, $exec, $shell_exec, $passthru)
}

rule Suspicious_Script
{
    meta:
        description = "Detects suspicious script behavior"
        author = "Sanitizer Engine"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $powershell = "powershell" nocase
        $download = "downloadstring" nocase
        $webclient = "net.webclient" nocase
        $invoke = "invoke-expression" nocase
        $hidden = "-windowstyle hidden" nocase
        
    condition:
        $powershell and 2 of ($download, $webclient, $invoke, $hidden)
}

rule Macro_Auto_Execution
{
    meta:
        description = "Detects Office macro auto-execution"
        author = "Sanitizer Engine"
        severity = "high"
        category = "macro"
    
    tags:
        macro malware
    
    strings:
        $auto_open = "AutoOpen" nocase
        $auto_exec = "AutoExec" nocase
        $auto_close = "AutoClose" nocase
        $document_open = "Document_Open" nocase
        $workbook_open = "Workbook_Open" nocase
        
        $shell = "Shell" nocase
        $wscript = "WScript.Shell" nocase
        $createobject = "CreateObject" nocase
        
    condition:
        any of ($auto_open, $auto_exec, $auto_close, $document_open, $workbook_open) and
        any of ($shell, $wscript, $createobject)
}

rule Suspicious_Registry_Modification
{
    meta:
        description = "Detects registry modification patterns"
        author = "Sanitizer Engine"
        severity = "medium"
        category = "persistence"
    
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        
    condition:
        any of them
}

rule Keylogger_Indicators
{
    meta:
        description = "Detects potential keylogger functionality"
        author = "Sanitizer Engine"
        severity = "high"
        category = "keylogger"
    
    tags:
        keylogger malware
    
    strings:
        $a1 = "GetAsyncKeyState" nocase
        $a2 = "GetKeyState" nocase
        $a3 = "GetKeyboardState" nocase
        $a4 = "SetWindowsHookEx" nocase
        
        $b1 = "WM_KEYDOWN" nocase
        $b2 = "WM_KEYUP" nocase
        
    condition:
        2 of ($a*) or (1 of ($a*) and 1 of ($b*))
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network-related strings"
        author = "Sanitizer Engine"
        severity = "medium"
        category = "network"
    
    strings:
        $url1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
        $c2_1 = "command and control" nocase
        $c2_2 = "C&C" nocase
        $upload = "upload.php" nocase
        $beacon = "beacon" nocase
        
    condition:
        2 of them
}

rule Cryptocurrency_Miner
{
    meta:
        description = "Detects cryptocurrency mining indicators"
        author = "Sanitizer Engine"
        severity = "high"
        category = "miner"
    
    tags:
        miner malware
    
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "mining pool" nocase
        $m3 = "monero" nocase
        $m4 = "cryptonight" nocase
        $m5 = "xmrig" nocase
        $m6 = "claymore" nocase
        
    condition:
        2 of them
}

rule SQL_Injection_Attempt
{
    meta:
        description = "Detects SQL injection patterns"
        author = "Sanitizer Engine"
        severity = "high"
        category = "injection"
    
    strings:
        $sql1 = "' OR '1'='1" nocase
        $sql2 = "' OR 1=1--" nocase
        $sql3 = "UNION SELECT" nocase
        $sql4 = "; DROP TABLE" nocase
        $sql5 = "'; EXEC" nocase
        
    condition:
        any of them
}
