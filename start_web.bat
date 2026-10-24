@echo off
chcp 65001 >nul
title RunningHub Web Controller
echo ============================================================
echo        RunningHub Web 控制台 (本地 / 局域网服务)
echo ============================================================
echo.
echo 正在启动 Web 服务...
echo 局域网/本机访问地址: http://127.0.0.1:8000 (若 8000 被占用则为 http://127.0.0.1:8080)
echo.
python app.py
pause
