
# Author: amoranio
# How to: https://amoran.io/2023/05/25/prevent-crowdstrike-rfm-with-tanium/

# -- Global --
$noauth = 0

# -- Falcon API --
$clientid = ""
$csecret = ""


#-- Tanium
$tantoken = ""
$tanreportID = ""
$tantokenloc = ""



### location output
$kernellist = ""

$distbl = @()
$usver = @()
$outp = @()


######### Functions


function Set-Token {
  param (
    [string]$token
  )
    
  $v = @{
    tokenString = $token
  }

$q = '
mutation RotateAPIToken($tokenString: String!) {
  apiTokenRotate(input: {tokenString: $tokenString}) {
    token {
      created
      expiration
      id
      lastUsed
      notes
      persona {
        name
      }
      tokenString
      trustedIPAddresses
    }
    error {
      message
      retryable
      timedOut
    }
  }
}
' 

$body = @{
query = $q
variables = $v
} | ConvertTo-Json



$param = @{
URI = "https://l2l4us-api.cloud.tanium.com/plugin/products/gateway/graphql"
Method = 'POST'
Headers = @{
      "session" = $tantoken
      'Content-Type' = 'application/json'
      }
     Body = $body

}

$req = Invoke-RestMethod @param
return $req
      

}





################


# ---- logo -----

$Logo = @('

                          .------._ 
                    .-"""`-.<")    `-._ 
                   (.--. _   `._       `"---.__.-"
   Prevent RFM! -      `   `;"-.-"         "-    ._
                      .--"``   ""._      - "   .
                       `"""-.    `---"    ,
                             `\
                               `\      ."
                                 `". "
                                    `".   jgs

@amoranio / Crowdstrike/ Tanium API Script

')
$logo


# -------------------------- login to CrowdStrike ----------------------------------------

$param = @{
    URI = 'https://api.crowdstrike.com/oauth2/token'
    Method = 'post'
    Headers = @{

        accept = 'application/json'
        'content-type' = 'application/x-www-form-urlencoded'
    
    }
    Body = "client_id=$clientid&client_secret=$csecret"


}
# -- Request Token --

$ctoken = try { (Invoke-RestMethod @param).Access_Token; } catch { Write-Host "[!] Status: Failed to issue access token" -ForegroundColor Red ; $noauth = 1 }


# -------------------------- logged into CrowdStrike ---------------------------------------- 

# -------------------------- Get Report From Tanium -----------------------------------------


$results = @()

Write-Host "[*] Getting Tanium Report: $tanreportID" -ForegroundColor Yellow

$v = @{
    id = $tanreportID
    first = 20
}

$q = '
query getReportResultData($id: ID!, $first: Int) {
    reportResultData(id: $id, first: $first, after: null) {
      edges {
        node {
          columns {
            values
          }
        }
        cursor
      }
      viewDetails {
        columns {
          name
          sourceName
          sourceColumnName
        }
      }
      pageInfo {
        startCursor
        endCursor
        hasPreviousPage
        hasNextPage
      }
      totalRecords
    }
  }
' 



$body = @{
query = $q
variables = $v
} | ConvertTo-Json



$param = @{
URI = "https://l2l4us-api.cloud.tanium.com/plugin/products/gateway/graphql"
Method = 'POST'
Headers = @{
      "session" = $tantoken
      'Content-Type' = 'application/json'
      }
     Body = $body

}

$req = Invoke-RestMethod @param

# add break
if (!$req){exit}
$results += $req.data.reportResultData.edges.node # can remove


while ($req.data.reportResultData.pageinfo.hasNextPage) {

  $start = $req.data.reportResultData.pageinfo.startCursor
  $end = $req.data.reportResultData.pageinfo.endCursor



  Write-Host "Running while loop..." -ForegroundColor Blue

  $v = @{
    id = $tanreportID
    first = 20
    after = $end
  }

  #      reportResultData(id: $id, after: ' + "'" + $end + "'" + ', first: $first) {

  $q = '
  query getReportResultData($id: ID!, $first: Int, $after: Cursor) {
      reportResultData(id: $id, after: $after, first: $first) {
        edges {
          node {
            columns {
              values
            }
          }
          cursor
        }
        viewDetails {
          columns {
            name
            sourceName
            sourceColumnName
          }
        }
        pageInfo {
          startCursor
          endCursor
          hasPreviousPage
          hasNextPage
        }
        totalRecords
      }
    }
  ' 

  $body = @{
    query = $q
    variables = $v
    } | ConvertTo-Json
    
    
    
    $param = @{
    URI = "https://l2l4us-api.cloud.tanium.com/plugin/products/gateway/graphql"
    Method = 'POST'
    Headers = @{
          "session" = $tantoken
          'Content-Type' = 'application/json'
          }
         Body = $body
    
    }
    
    $req = Invoke-RestMethod @param
    $results += $req.data.reportResultData.edges.node 


    #$req.data.reportResultData.pageinfo.hasNextPage
    
  
}

Write-Output ""

# breakout results
$filter = @($results.columns.values -split "," -replace " ","")
$findings = @()
$disgard = @()

# This isn't perfect and needs improving

foreach ($f in $filter){
  
  if ($f -notcontains "*kernel*" -and $f -notlike "*.rpm*" -and $f -notlike "*update*" -and $f -notlike "*:*"){
    $hn = $f


  } else {
    
    if ($f.StartsWith("kernel") -and $f -like "*.rpm*" -and $f -notlike "*.noarch*" -and $f -notlike "*debug*" -and $f -notlike "*tools*" -and $f -notlike "*devel*" -and $f -notlike "*headers*" -and $f -notlike "*modules*" -and $f -notlike "*core*" -and $f -notlike "*container*"){

      $kern = $f -replace "kernel-", "" -replace "uek-", "" -replace ".rpm", "" -replace ".src", ".x86_64" -replace "firmware-", "" -replace "firmware-", ""

      $tbl = New-Object PSObject
      $tbl | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $hn
      $tbl | Add-Member -MemberType NoteProperty -Name 'Kernel' -Value $kern
      $findings += $tbl

    } else {

      $disgard += $f

    }


}

}




Write-Host "[*] Found Results For $($findings.Count) Endpoints" -ForegroundColor Yellow


# -------------------------- End Of Report From Tanium -----------------------------------------

# -------------------------- Check CrowdStrike Kernel Support ----------------------------------


$usver = @()
$norfm = @()
$willrfm = @()

foreach ($k in $findings){

  $param = @{
    URI = "https://api.crowdstrike.com/policy/combined/sensor-update-kernels/v1?filter=release:'$($k.kernel)'"
    Method = 'GET'
    Headers = @{
            Authorization = "Bearer $ctoken"  
            "Content-Type" = "application/json" 
            }
    }
  
    $rfmchk = (Invoke-RestMethod @param).resources

    if ($rfmchk){

      $inf = New-Object PSObject
      $inf | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $k.HostName
      $inf | Add-Member -MemberType NoteProperty -Name 'Kernel' -Value $k.kernel
      $inf | Add-Member -MemberType NoteProperty -Name 'Supported' -Value "Y"

      $norfm += $inf

  } else {

    $inf = New-Object PSObject
    $inf | Add-Member -MemberType NoteProperty -Name 'HostName' -Value $k.HostName
    $inf | Add-Member -MemberType NoteProperty -Name 'Kernel' -Value $k.kernel
    $inf | Add-Member -MemberType NoteProperty -Name 'Supported' -Value "N"
    
    $willrfm += $inf

    if ($usver -notcontains $k.Kernel){
      $usver += $k.Kernel
    }


  } 



}

Write-Output ""

Write-Host "[*] CrowdStrike Results: " -ForegroundColor Yellow
Write-Output ""

Write-Host "[!] Problem Kernel/s:" -ForegroundColor "Red"
$usver | Format-Table

Write-Output ""

Write-Host "[!] Will Go RFM:" -ForegroundColor "Red"
$willrfm | Format-Table

Write-Output ""

Write-Host "[*] Should Be ok: $($norfm.count)" -ForegroundColor "Green"
#$norfm | Format-Table

Write-Output ""



$newkernel = @()
$nowsupported = @()

foreach ($i in (Get-Content $kernellist)){

  $param = @{
    URI = "https://api.crowdstrike.com/policy/combined/sensor-update-kernels/v1?filter=release:'$($i)'"
    Method = 'GET'
    Headers = @{
            Authorization = "Bearer $ctoken"  
            "Content-Type" = "application/json" 
            }
    }
  
    $rfmchk = (Invoke-RestMethod @param).resources
  
    if ($rfmchk){ 
      $nowsupported += $i
    }
  
}


### output to checker ###

$newkernel += $usver
$newkernel > $kernellist


Write-Output ""


Write-Host "Kernels Now Supported:" -ForegroundColor Green
if ($nowsupported){
  $nowsupported
} else { Write-Host "No Update..."}

Write-Output ""

Write-Host "Current Kernels Not Supported:" -ForegroundColor Red
$newkernel

Write-Output ""

Write-Host "[*] Rotating Token..." -ForegroundColor Yellow
$newtoken = Set-Token -token $tantoken
if ($newtoken.data.apiTokenRotate.token.tokenString){
    $newtoken.data.apiTokenRotate.token.tokenString > $tantokenloc
    Write-Host "[*] Rotation Succesfull" -ForegroundColor Green

} else {
    Write-Host "[!] Rotation Failed" -ForegroundColor Red

}



