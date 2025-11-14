@echo off
chcp 65001 >nul
title Trình khởi chạy Nhóm 6

echo ================================================
echo   Đang khởi chạy chương trình...
echo ================================================
echo.

if not exist Nhom6.py (
    echo Không tìm thấy file Nhom6.py

    powershell -command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Không tìm thấy file Nhom6.py. Tải xuống ở https://github.com/Minhdzct/ATBMTT/tree/main','Lỗi',0,16)"

    pause
    exit /b
)

echo File Nhom6.py đã được tìm thấy.
echo.

echo Kiểm tra Python...
py --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python chưa được cài. Cài tại:
    echo https://www.python.org/downloads/

    powershell -command "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Python chưa được cài! Vui lòng cài đặt trước khi chạy chương trình.','Lỗi',0,16)"
    pause
    exit /b
)

echo Python OK.
echo.

echo Cài thư viện pycryptodome (nếu chưa có)...
pip install pycryptodome

echo.
echo Đang chạy Nhom6.py...
echo.

py Nhom6.py

echo.
pause
