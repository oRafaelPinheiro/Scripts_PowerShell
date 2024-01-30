# Define the username and password
$nomeUsuario = "Scanner"
$password = ConvertTo-SecureString -String "Senha para usuário Scanner" -AsPlainText -Force


# Verificar se o usuário existe
if (Get-LocalUser -Name $nomeUsuario -ErrorAction SilentlyContinue) {
    # Se o usuário existir, alterar a senha
    Set-LocalUser -Name $nomeUsuario -Password (ConvertTo-SecureString -AsPlainText $password -Force)
    Write-Host "Senha do usuário '$nomeUsuario' alterada com sucesso."
} else {
    # Se o usuário não existir, criar o usuário
    New-LocalUser -Name $nomeUsuario -Password (ConvertTo-SecureString -AsPlainText $password -Force) -AccountNeverExpires $true
    Write-Host "Usuário '$nomeUsuario' criado com sucesso."
}

# Check if the folder exists, if not create it
$folderPath = "C:\Scanner"
if (!(Test-Path $folderPath)) {
    New-Item -ItemType Directory -Path $folderPath
}

# Check if the share exists, if not create it
$shareName = "Scanner"
$sharePath = $folderPath
if (!(Get-SmbShare | Where-Object { $_.Name -eq $shareName })) {
    New-SmbShare -Name $shareName -Path $sharePath -FullAccess $username
} else {
    # Se o compartilhamento já existir, verificar e conceder permissões totais ao usuário
    $existingShare = Get-SmbShare | Where-Object { $_.Name -eq $shareName }
    $acl = Get-Acl $existingShare.PSPath

    # Verificar se o usuário tem permissões
    $existingPermissions = $acl.Access | Where-Object { $_.IdentityReference -eq $username }
    if ($existingPermissions -eq $null) {
        # Se o usuário não tiver permissões, conceder permissões totais
        $permissions = "FullControl"
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($username, $permissions, "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl $existingShare.PSPath $acl
        Write-Host "Permissões totais concedidas para o usuário '$username'."
    } else {
        Write-Host "O usuário '$username' já possui permissões totais."
    }
}

