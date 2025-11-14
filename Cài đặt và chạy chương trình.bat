@echo off
chcp 65001 >nul
title Trình khởi chạy Nhóm 6

set GIT_LINK=https://github.com/Minhdzct/ATBMTT/blob/main/Nhom6.py

echo ======================================================
echo   Đang kiểm tra cài đặt và khởi chạy chương trình...
echo ======================================================
echo.

if not exist Nhom6.py (
    echo Không tìm thấy file Nhom6.py.
    powershell -NoLogo -Command "Add-Type -AssemblyName PresentationFramework; if([System.Windows.MessageBox]::Show('Không tìm thấy file Nhom6.py. Mở GitHub để tải không?','Lỗi','OKCancel','Error') -eq 'OK'){Start-Process '%GIT_LINK%'}"
    pause
    exit /b
)

echo Đã tìm thấy file Nhom6.py.
echo.

echo Kiểm tra Python...
py --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    powershell -Command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Python chưa được cài. Hãy tải tại python.org','Lỗi','OK','Error')"
    echo Python CHƯA được cài. Tải tại: https://www.python.org/downloads/
    pause
    exit /b
)
echo Python OK.
echo.

echo Cài thư viện pycryptodome (nếu chưa có)...
pip install pycryptodome
echo.

echo Đang chạy Nhom6.py...
py Nhom6.py

echo.
pause
