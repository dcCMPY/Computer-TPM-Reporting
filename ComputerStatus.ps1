$ErrorActionPreference = 'SilentlyContinue'
$Results = @()
foreach ($computersystem in (Get-Content \\filserver\computerreporting\PC_info_check.txt)){
    $computerinfo = get-wmiobject -computername $computersystem Win32_ComputerSystem -Authentication PacketPrivacy
    $computerBIOS = get-wmiobject -computername $computerSystem Win32_BIOS -Authentication PacketPrivacy
    $computerOS = get-wmiobject -computername $computerSystem Win32_OperatingSystem -Authentication PacketPrivacy

    $tpm = Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ComputerName $computerSystem -Authentication PacketPrivacy
    $tpm1 = Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ComputerName $computerSystem -Authentication PacketPrivacy
    $tpm2 = Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm -ComputerName $computerSystem -Authentication PacketPrivacy

    $bdeObject = @()
    $bde = manage-bde -cn $computersystem -status
    $ConversionStatus = $bde | Select-String "Conversion Status:"
    $ConversionStatus = ($ConversionStatus -split ": ")[1]
    $ConversionStatus = $ConversionStatus -replace '\s','' #removes the white space in this field

    $ProtectionStatus = $bde | Select-String "Protection Status:"
    $ProtectionStatus = ($ProtectionStatus -split ": ")[1]

    $PercentageEncrypted = $bde | Select-String "Percentage Encrypted:"
    $PercentageEncrypted = ($PercentageEncrypted -split ": ")[1]

    #Add all fields to an array that contains custom formatted objects with desired fields
    $bdeObject += New-Object psobject -Property @{'Conversion Status'=$ConversionStatus; 'Percentage Encrypted'=$PercentageEncrypted; 'Protection Status' = $ProtectionStatus;}

    $object = [pscustomobject]@{
        "System Information for" = $computerinfo.Name
        "Manufacturer" = $computerinfo.Manufacturer
        "Model" = $computerinfo.Model
        "Serial Number" = $computerBIOS.SerialNumber
        "Bios Version" = $computerBIOS.Version
        "TPM" = $tpm.SpecVersion
        "TPM Activation Status" = $tpm1.IsActivated_InitialValue
        "TPM Enabled Status" = $tpm2.IsEnabled_InitialValue
        "Bitlocker Protection Status" = $ConversionStatus + $PercentageEncrypted + $ProtectionStatus    
        "Operating System" = $computerOS.caption
        "User logged In" = $computerinfo.UserName
        "Last Reboot" = $computerinfo.ConvertToDateTime($computerOS.LastBootUpTime)

    }
    $Results += $object
}
$results | export-csv \\filserver\computerreporting\TPMResults.csv -Append -notypeinformation
