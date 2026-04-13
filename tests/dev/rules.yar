rule EICAR_Test_FIle {
strings:
$eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
condition:
$eicar
}
