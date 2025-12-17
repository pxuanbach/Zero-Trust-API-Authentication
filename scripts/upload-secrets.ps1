$PROJECT_NAME = "NT2205-CH191-api"
$AWS_REGION = "us-east-1"
$CERTS_PATH = ".\src\certs"

# Array of certificate paths
$SECRETS = @(
    @{
        LocalPath = "$CERTS_PATH\gateway\gateway.crt"
        SecretId  = "$PROJECT_NAME/gateway/cert"
        Name      = "Gateway Certificate"
    },
    @{
        LocalPath = "$CERTS_PATH\gateway\gateway.key"
        SecretId  = "$PROJECT_NAME/gateway/key"
        Name      = "Gateway Key"
    },
    @{
        LocalPath = "$CERTS_PATH\ca\ca.crt"
        SecretId  = "$PROJECT_NAME/ca/cert"
        Name      = "CA Certificate"
    },
    @{
        LocalPath = "$CERTS_PATH\extension-app1\extension-app1.crt"
        SecretId  = "$PROJECT_NAME/extension-app1/cert"
        Name      = "Extension App Certificate"
    },
    @{
        LocalPath = "$CERTS_PATH\extension-app1\extension-app1.key"
        SecretId  = "$PROJECT_NAME/extension-app1/key"
        Name      = "Extension App Key"
    },
    @{
        LocalPath = "$CERTS_PATH\crm-app\crm-app.crt"
        SecretId  = "$PROJECT_NAME/crm-app/cert"
        Name      = "CRM App Certificate"
    },
    @{
        LocalPath = "$CERTS_PATH\crm-app\crm-app.key"
        SecretId  = "$PROJECT_NAME/crm-app/key"
        Name      = "CRM App Key"
    }
)

# Upload each secret
foreach ($secret in $SECRETS) {
    Write-Host "Uploading $($secret.Name)..." -ForegroundColor Cyan

    if (-not (Test-Path $secret.LocalPath)) {
        Write-Host "❌ File not found: $($secret.LocalPath)" -ForegroundColor Red
        continue
    }

    $content = Get-Content -Path $secret.LocalPath -Raw

    $updateResult = aws secretsmanager put-secret-value `
        --secret-id $secret.SecretId `
        --secret-string $content `
        --region $AWS_REGION 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "$($secret.Name) updated!" -ForegroundColor Green
    } else {
        if ($updateResult -like "*ResourceNotFoundException*") {
            Write-Host "  Secret not found, creating new secret..." -ForegroundColor Yellow
            aws secretsmanager create-secret `
                --name $secret.SecretId `
                --secret-string $content `
                --region $AWS_REGION `
                --tags "Key=Project,Value=$PROJECT_NAME" | Out-Null
            Write-Host "$($secret.Name) created!" -ForegroundColor Green
        } else {
            Write-Host "Error: $updateResult" -ForegroundColor Red
        }
    }
}
