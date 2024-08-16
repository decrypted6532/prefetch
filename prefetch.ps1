$directory = "C:\Windows\Prefetch"

Clear-Host

Write-Host @"
 ▄████▄  ▓█████  ██▀███   ▒█████   ██▒   █▓ ██▓ ███▄    █  ▄▄▄      
▒██▀ ▀█  ▓█   ▀ ▓██ ▒ ██▒▒██▒  ██▒▓██░   █▒▓██▒ ██ ▀█   █ ▒████▄    
▒▓█    ▄ ▒███   ▓██ ░▄█ ▒▒██░  ██▒ ▓██  █▒░▒██▒▓██  ▀█ ██▒▒██  ▀█▄  
▒▓▓▄ ▄██▒▒▓█  ▄ ▒██▀▀█▄  ▒██   ██░  ▒██ █░░░██░▓██▒  ▐▌██▒░██▄▄▄▄██ 
▒ ▓███▀ ░░▒████▒░██▓ ▒██▒░ ████▓▒░   ▒▀█░  ░██░▒██░   ▓██░ ▓█   ▓██▒
░ ░▒ ▒  ░░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▒░▒░    ░ ▐░  ░▓  ░ ▒░   ▒ ▒  ▒▒   ▓▒█░
  ░  ▒    ░ ░  ░  ░▒ ░ ▒░  ░ ▒ ▒░    ░ ░░   ▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░
░           ░     ░░   ░ ░ ░ ░ ▒       ░░   ▒ ░   ░   ░ ░   ░   ▒   
░ ░         ░  ░   ░         ░ ░        ░   ░           ░       ░  ░
░                                      ░                            
                                                                       

...........*UHWHН!hhhhН!?M88WHXХWWWWSW$o
.......X*#M@$Н!eeeeНXНM$$$$$$WWxХWWW9S0
…...ХН!Н!Н!?HН..ХН$Н$$$$$$$$$$8XХDDFDFW9W$
....Н!f$$$$gХhН!jkgfХ~Н$Н#$$$$$$$$$$8XХKKW9W$,
....ХНgХ:НHНHHHfg~iU$XН?R$$$$$$$$MMНGG$9$R$$
....~НgН!Н!df$$$$$JXW$$$UН!?$$$$$$RMMНLFG$9$$$
......НХdfgdfghtХНM"T#$$$$WX??#MRRMMMН$$$$99$$
......~?W…fiW*`........`"#$$$$8Н!Н!?WWW?Н!J$99999$$$
...........M$$$$.............`"T#$T~Н8$WUXUQ$$$$$99$9$$
...........~#$$$mХ.............~Н~$$$?$$$$$$$F$$$990$0
..............~T$$$$8xx......xWWFW~##*"''""''"I**9999о
...............$$$.P$T#$$@@W@*/**$$.............,,*90о
.............$$$L!?$$.XXХXUW....../....$$,,,,....,,ХJ;09*
............$$$.......LM$$$$Ti......../.....n+НHFG$9$*
..........$$$H.Нu....""$$B$$MEb!MХUНT$$0
............W$@WTL...""*$$$W$TH$Н$$0
..............?$$$B$Wu,,''***PF~***$/ ***0
...................*$$g$$$B$$eeeХWP0
........................"*0$$$$M$$00F''

"@ -ForegroundColor Red
Write-Host ""
Write-Host "Balkan School Community - " -ForegroundColor Blue -NoNewline
Write-Host -ForegroundColor Red "cerovina$"

Write-Host ""
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

Start-Sleep -s 3

# Specify the path to the Prefetch folder
$directory = "C:\Windows\Prefetch"
$files = Get-ChildItem -Path $directory -Filter *.pf

$hashTable = @{}
$suspiciousFiles = @{}

# Define simplified pattern for detection
$suspiciousPatterns = @(".*\.(jpg|png|bmp|gif|pdf|scr|doc|xls|ppt|bat|cmd|vbs|js|ps1|jar|pif|lnk|hta|wsf|vbe|ws|sh|bash|ksh|zsh|csh|txt|msi|dll|sys|drv|inf|reg|ocx|xsl|ini|url|dot|tmp|dat|bin|htm|html|php|asp|aspx|cer|crt|csr|cfg|log|bak|gadget|mht|mhtml|svg|tiff|swf|flv|xla|xlam|xll|chm|torrent|scf|pif|class|vb|vbe|vbs|sql|shb|shs|dmg|iso|vmdk|xpi|jsf|zip|rar|7z|xml|tar|gz|bz2|xz|cab|z|tgz|zipx|apk|war)-[A-F0-9]{8}\.pf$")

foreach ($file in $files) {
    try {
        Write-Host "Processing file: $($file.Name)"

        # Check if the file is read-only
        if ($file.IsReadOnly) {
            if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                $suspiciousFiles[$file.Name] = "$($file.Name) is read-only"
            }
        }

        # Check if the file is a valid prefetch file
        $reader = [System.IO.StreamReader]::new($file.FullName)
        $buffer = New-Object char[] 3
        $null = $reader.ReadBlock($buffer, 0, 3)
        $reader.Close()
        $firstThreeChars = -join $buffer

        if ($firstThreeChars -ne "MAM") {
            if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                $suspiciousFiles[$file.Name] = "$($file.Name) nije validan prefetch file"
            }
        }

        # Check hash for duplicate detection
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        if ($hashTable.ContainsKey($hash.Hash)) {
            $hashTable[$hash.Hash].Add($file.Name)
        } else {
            $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$hash.Hash].Add($file.Name)
        }

        # Debug output for pattern matching
        Write-Host "File Name: $($file.Name)"
        foreach ($pattern in $suspiciousPatterns) {
            if ($file.Name -match $pattern) {
                Write-Host "Pattern Match: $pattern"
                if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                    $suspiciousFiles[$file.Name] = "$($file.Name) sadrzi sumnjiv pattern ----> CHEAT"
                }
            }
        }
    } catch {
        Write-Host "Error with file: $($file.FullName): $($_.Exception.Message)"
    }
}

$repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

if ($repeatedHashes) {
    foreach ($entry in $repeatedHashes) {
        foreach ($file in $entry.Value) {
            if (-not $suspiciousFiles.ContainsKey($file)) {
                $suspiciousFiles[$file] = "$file je modifikovan sa type ili echo"
            }
        }
    }
}

if ($suspiciousFiles.Count) {
    Write-Host "Sumnjivi fajlovi pronadjeni:" -ForegroundColor Red
    foreach ($key in $suspiciousFiles.Keys) {
        Write-Host "$key : $($suspiciousFiles[$key])"
    }
} else {
    Write-Host "Prefetch folder nije modifikovan"
}
