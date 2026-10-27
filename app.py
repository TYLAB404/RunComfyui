"""
RunComfyui - High-Performance Enterprise ComfyUI / RunningHub Web Application Gateway
Architecture 2.0: Modular, thread-safe, connection-pooled, zero-regression.
"""
import os
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Core imports
from core.config import (
    BASE_DIR,
    DATA_DIR,
    OUTPUTS_DIR,
    STATIC_DIR,
    WORKFLOWS_DIR,
    CONFIG_PATH,
    TASKS_PATH,
    load_config,
    save_config,
    get_active_api_key,
    get_imgbed_config,
    get_system_config_safe,
    sort_workflows,
    filter_workflows_for_user,
)
from core.database import (
    init_database,
    get_db_connection,
    db_save_task,
    db_update_task,
    db_get_task,
    db_delete_task,
    db_load_tasks,
    db_deduct_user_points,
    db_refund_user_points,
    db_bump_token_version,
)
from core.security import (
    encrypt_key,
    decrypt_key,
    mask_key,
    verify_key_with_runninghub,
    is_key_fatal_error,
)
from core.auth import (
    USER_EVENT_CHANNELS,
    notify_user,
    get_current_user,
    get_current_admin,
    get_current_user_optional,
    load_users,
    save_users,
    sanitize_user,
    get_user_by_id,
    get_user_by_identifier,
    create_user,
    update_user_fields,
    set_user_password,
    delete_user_by_id,
    verify_password,
    create_jwt_token,
    decode_jwt_token,
    verify_turnstile_token,
)

# Services imports
from services.key_pool import (
    KEY_POOL_MANAGER,
    KeyPoolManager,
    key_pool_watchdog_loop,
    key_pool_health_inspector_loop,
)
from services.runninghub import RUNNINGHUB_API_URL

# Router imports
from routers import (
    auth_router,
    keys_router,
    cdkeys_router,
    workflows_router,
    tasks_router,
    gallery_router,
    admin_router,
)

# Re-export request models for backwards compatibility
from routers.auth_router import RegisterRequest, LoginRequest, ChangePasswordRequest
from routers.keys_router import ConfigUpdateModel, AddKeyModel
from routers.cdkeys_router import RedeemCDKeyRequest, GenerateCDKeysRequest
from routers.workflows_router import WorkflowModel
from routers.tasks_router import GenerateRequest
from routers.admin_router import (
    AdminUpdateUserRequest,
    AdminSystemConfigRequest,
    AdminResetPasswordRequest,
    AnnouncementCreateRequest,
    AnnouncementUpdateRequest,
    SmtpConfigRequest,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Initializes database schema and starts background watchdog and inspector workers.
    Ensures safe shutdown by cancelling active background tasks.
    """
    # 1. 确保数据库表和默认管理员初始化完毕
    init_database()

    # 2. 启动后台自愈看门狗与健康巡检循环
    watchdog_task = asyncio.create_task(key_pool_watchdog_loop())
    inspector_task = asyncio.create_task(key_pool_health_inspector_loop())

    yield

    # 3. 优雅停止后台协程
    watchdog_task.cancel()
    inspector_task.cancel()
    await asyncio.gather(watchdog_task, inspector_task, return_exceptions=True)


app = FastAPI(
    title="RunningHub Web Controller",
    version="2.0.0",
    description="High-Performance Enterprise RunningHub ComfyUI Cloud Gateway",
    lifespan=lifespan,
)

# 生产级安全 CORS 配置：严禁 wildcard * 与 allow_credentials=True 混用
_CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS")
if _CORS_ORIGINS_ENV:
    _ALLOWED_ORIGINS = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # 默认同源及本地开发环回地址白名单
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# 注册各个功能模块的路由
app.include_router(auth_router.router)
app.include_router(keys_router.router)
app.include_router(cdkeys_router.router)
app.include_router(workflows_router.router)
app.include_router(tasks_router.router)
app.include_router(gallery_router.router)
app.include_router(admin_router.router)

# 挂载静态资源
app.mount("/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    # host 0.0.0.0 允许局域网或公网通过服务器 IP / 域名访问
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
