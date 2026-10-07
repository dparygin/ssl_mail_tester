param (
    [Parameter(Mandatory=$true, HelpMessage="Укажите FQDN или IP адрес сервера")]
    [string]$Server,
    
    [Parameter(Mandatory=$false, HelpMessage="Укажите порт")]
    [int]$Port = 443,
    
    [Parameter(Mandatory=$false, HelpMessage="Таймаут в секундах")]
    [int]$TimeoutSeconds = 5,

    [Parameter(Mandatory=$false, HelpMessage="Использовать явное шифрование (STARTTLS)")]
    [ValidateSet('None', 'SMTP')]
    [string]$StartTls = 'None'
)

# Принудительно включаем поддержку современных протоколов TLS
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

try {
    $TcpClient = New-Object System.Net.Sockets.TcpClient
    
    $ConnectTask = $TcpClient.ConnectAsync($Server, $Port)
    if (-not $ConnectTask.Wait($TimeoutSeconds * 1000)) { throw "Таймаут подключения к $Server" }
    if (-not $TcpClient.Connected) { throw "Не удалось подключиться к порту $Port." }

    $NetStream = $TcpClient.GetStream()
    $NetStream.ReadTimeout = $TimeoutSeconds * 1000
    $NetStream.WriteTimeout = $TimeoutSeconds * 1000
    
    # Блок обработки явного шифрования (STARTTLS)
    if ($StartTls -eq 'SMTP') {
        $Reader = New-Object System.IO.StreamReader($NetStream)
        $Writer = New-Object System.IO.StreamWriter($NetStream)
        $Writer.AutoFlush = $true

        while (($line = $Reader.ReadLine()) -match "^220-") { }

        $Writer.WriteLine("EHLO localhost")
        while (($line = $Reader.ReadLine()) -match "^250-") { }

        $Writer.WriteLine("STARTTLS")
        $startTlsResponse = $Reader.ReadLine()
        if ($startTlsResponse -notmatch "^220") {
            throw "Сервер не поддерживает STARTTLS или ответил ошибкой: $startTlsResponse"
        }
    }

    $SslStream = New-Object System.Net.Security.SslStream($NetStream, $false, { $true })
    $SslStream.AuthenticateAsClient($Server)

    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
    
    Write-Host "--- Сертификат для ${Server}:${Port} ---" -ForegroundColor Cyan
    $Cert | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint | Format-List
    
} catch {
    $BaseError = $_.Exception.GetBaseException().Message
    Write-Host "Ошибка: $BaseError" -ForegroundColor Red
} finally {
    if ($SslStream) { $SslStream.Dispose() }
    if ($TcpClient) { $TcpClient.Dispose() }
}
