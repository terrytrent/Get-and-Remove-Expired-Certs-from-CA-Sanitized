$ServerAndCA=""

$AllCerts = $(certutil -view -config $ServerAndCA -out "RequestID,RequesterName,RequestType,NotAfter,CommonName,Certificate Template,Revocation Date,SerialNumber" csv | convertfrom-csv)

$ExpiredCerts = $AllCerts | where {$(get-date($_.'Certificate Expiration Date')) -lt (get-date) -and $_.'Issued Common Name' -notlike "*-Xchg" -and $_.'Revocation Date' -eq "Empty"}

$CATemplates=$(
    
    $templates=certutil -config $ServerAndCA -CATemplates
    $templates=$templates | select -first $($templates.count -1)

    foreach($template in $templates){
        
        $template.substring(0,$template.indexof(":"))
    
    }
)

#May not work if using revocation reason, was able to get it to work without it

if($ExpiredCerts.count -gt 0){
    write-host "The following certificates have expired and not yet been revoked:" -NoNewline
    ExpiredCerts
    $revokeCertsQuery=Read-Host "Do you want to revoke these certificates? (Yes or No)"

    if($revokeCertsQuery -eq "Yes"){
        $revocationReasonCode=Read-Host "`nWhich revocation reason?`
    `
        Reason for revoking a certificate	Reason code`
        Unspecified...................................0`
        Key Compromise................................1`
        CA Compromise.................................2`
        Affiliation Changed...........................3`
        Superseded....................................4`
        Cessation of Operation........................5`
        Certificate Hold..............................6`
    `
    Answer"

        foreach($cert in $allIssuedExpiredCertificates){

            $serialNumber=$cert.'Serial Number'
        
            # Currently throws error. without this the script does not work.  Need to fix.:
            #
            #   Revoking "Serial Number" -- Reason: Superseded
            #   ICertAdmin::RevokeCertificate: The parameter is incorrect. 0x80070057 (WIN32: 87)
            #   CertUtil: -revoke command FAILED: 0x80070057 (WIN32: 87)
            #   CertUtil: The parameter is incorrect.

            certutil -config $ServerAndCA -revoke $SerialNumber $revocationReasonCode

        }

    }
    else{
        write-host "OK, Leaving the certificates alone"
        break
    }
}
else{
    write-host "No Expired Certs."
    break
}