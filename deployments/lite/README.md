# 单机精简部署（lite）

`TheStandard/docker-compose.lite.yml` 的运维说明。**唯一口径**见
`GhostReveal/docs/ecosystem-architecture.md` 第 9 节（端口）与第 12.6 节（本批部署范围）。

本栈只有三个服务，不引入数据库、缓存、队列或任何外部托管服务：

| 服务 | 角色 | 构建上下文 | 容器端口 | 宿主绑定（默认） |
| --- | --- | --- | --- | --- |
| `the-standard` | 法仪检测引擎（L2） | `.`（TheStandard） | `8081` | `127.0.0.1:8081` |
| `ghost-reveal-server` | 明鬼归档服务（L3） | `../GhostReveal` | `8090` | `127.0.0.1:8090` |
| `ghost-reveal-frontend` | 明鬼静态前端（L3，nginx） | `../GhostReveal` | `8080` | `127.0.0.1:3001` |

端口与第 9 节一致：法仪 `8081`、归档 `8090`、静态预览 `3001`（宿主）→ `8080`（容器）。
`5174` 是开发模式端口，本栈不涉及。

镜像 tag 与仓库既有 compose 保持一致：`the-standard-service:0.1.1015`
（与 `TheStandard/docker-compose.yml` 完全相同，未另造镜像名）。

---

## 1. 前置条件

1. Docker Engine 24+ 与 Docker Compose v2（`docker compose version`）。
2. **先构建明鬼前端产物 `dist/`**。归档镜像 `deployments/docker/server.Dockerfile` 里有
   `COPY dist /app/dist`，静态前端镜像则在自己的构建阶段里 `npm ci && npm run build`：

   ```bash
   cd /Volumes/DA/Dli.li/E/GhostReveal
   npm ci
   npm run build
   ```

3. **注意 `.dockerignore`**：`GhostReveal/.dockerignore` 当前包含 `dist` 一行，
   会让 `server.Dockerfile` 的 `COPY dist` 直接失败。构建归档镜像前需要把该行改为
   `!dist`（或在发布流程里删除该行）。这是仓库侧的一次性修复，本目录不修改任何既有文件。
   只跑静态前端（`ghost-reveal-frontend`）不受影响。

---

## 2. 一键启动

所有命令都在 **TheStandard** 目录执行（构建上下文是相对本 compose 文件解析的）：

```bash
cd /Volumes/DA/Dli.li/E/TheStandard

# 生产必须设置随机令牌；否则法仪会接受任意调用方
export THE_STANDARD_AUTH_TOKEN="$(openssl rand -hex 32)"
export THE_STANDARD_REQUIRE_AUTH=true

docker compose -f docker-compose.lite.yml up -d --build
docker compose -f docker-compose.lite.yml ps
```

停止 / 清理：

```bash
docker compose -f docker-compose.lite.yml down          # 保留报告数据卷
docker compose -f docker-compose.lite.yml down -v       # 连数据卷一起删除（不可恢复）
```

---

## 3. 环境变量

compose 只使用四个仓库里**已有的**变量名，全部带默认值，未设置时按默认值运行。

必需（生产）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `THE_STANDARD_AUTH_TOKEN` | 空 | 法仪 Bearer 令牌；为空且未开鉴权时任何人都能驱动检测 |
| `THE_STANDARD_REQUIRE_AUTH` | `false` | 生产应设为 `true` |
| `GHOST_REVEAL_ADMIN_TOKEN` | 空 | 归档服务管理端（`/api/feedback*` 导出）所需的 Bearer 令牌，见第 12.4 节 |

常用可选（名称与默认值取自 `TheStandard/docker-compose.yml`）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `THE_STANDARD_ALLOWED_ORIGINS` | `http://localhost:3001,http://127.0.0.1:3001,http://localhost:8090,http://127.0.0.1:8090,http://localhost:5174,http://127.0.0.1:5174` | 浏览器直连法仪时允许的来源；走同源 `/core` 代理时不需要 |
| `THE_STANDARD_ALLOW_PRIVATE_TARGETS` | `false` | **保持 false**，见第 7 节 |
| `THE_STANDARD_DEMO_TARGETS` | 空 | 只有需要确定性演示传输时才填逗号分隔的精确 HTTP(S) Origin |
| `THE_STANDARD_RULE_MANIFEST_URL` | `https://raw.githubusercontent.com/MoBalance/SanBiao/main/manifest.json` | 三表 manifest 地址 |
| `THE_STANDARD_RULE_REFRESH_SECONDS` | `300` | 规则刷新周期 |
| `THE_STANDARD_PORT` / `GHOST_REVEAL_SERVER_PORT` / `GHOST_REVEAL_PORT` | `8081` / `8090` / `3001` | 只改宿主端口，容器内端口不变 |

其余 `THE_STANDARD_ENGINE_*`、`THE_STANDARD_SERVICE_*`、`THE_STANDARD_TRANSPORT_*`、
`THE_STANDARD_RULE_*` 与 `TheStandard/docker-compose.yml` 逐项同名同默认值。

归档服务的其余配置来自挂载的 `GhostReveal/config.toml`（只读）：
`[storage].report_directory`、`retention_days`、`share_ttl_hours`、`feedback_directory`
与 `[core].upstream_url` 都在那里。容器启动时会在 `/app/config.runtime.toml` 生成一份
**运行时副本**，只把 `[server].host` 改为 `0.0.0.0`、`[core].upstream_url` 改为
`http://the-standard:8081`（否则 `127.0.0.1` 在容器里指向它自己）；被挂载的原始文件不会被改写。

---

## 4. 数据与备份

报告与反馈都落在命名卷 `the-standard-lite_ghost-reveal-data`，容器内路径 `/app/data`：

| 容器路径 | 来源 | 说明 |
| --- | --- | --- |
| `/app/data/reports` | `[storage].report_directory` | 脱敏报告，ULID 命名的不可变单文件 JSON |
| `/app/data/feedback` | `[storage].feedback_directory` | 反馈单文件 JSON（0600），不随报告清理删除 |

备份（导出为 tgz）：

```bash
docker run --rm \
  -v the-standard-lite_ghost-reveal-data:/data:ro \
  -v "$PWD":/backup \
  alpine tar czf /backup/ghost-reveal-data-$(date +%Y%m%d).tgz -C /data .
```

恢复：把归档解回同一个卷，再 `docker compose -f docker-compose.lite.yml up -d`。
因为报告是 ULID 命名的不可变文件，覆盖恢复不会产生歧义。

---

## 5. 验收

```bash
# 1) 法仪就绪（规则已从三表加载完成才会 200）
curl -fsS http://127.0.0.1:8081/health/ready
curl -fsS http://127.0.0.1:8081/health

# 2) 归档服务健康
curl -fsS http://127.0.0.1:8090/api/health

# 3) 静态前端可访问
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3001/

# 4) 同源 /core 代理（静态前端 → 法仪）
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3001/core/health/ready
```

一次端到端检测（UI）：

1. 打开 `http://127.0.0.1:8090/`（归档服务同时托管静态前端，单源同时提供 `/api` 与 `/core`，
   报告归档可直接落盘）。
   只做检测时也可以用 `http://127.0.0.1:3001/`（nginx 静态前端，仅同源代理 `/core`；
   它的 `/api` 需要外层反向代理转发，见第 7 节）。
2. 在“连接设置”里填法仪地址 `/core` 与 `THE_STANDARD_AUTH_TOKEN`；令牌只留在当前页面内存。
3. 填一个可探测的目标模型地址，选择模式（quick / standard / full），运行检测。
4. 期望：进度条走完，报告页显示 `totalScore` / `verdict` / `presentation` 分区；
   在 8090 打开的页面里报告会归档，可复制 `/reports/{ulid}` 分享链接。
5. 若步骤 1 的 `/health/ready` 尚未 200，界面会明确显示“规则未就绪”并禁用检测，这是预期行为。

---

## 6. 升级

- 法仪：改 `docker-compose.lite.yml` 里的 `the-standard-service:<tag>`（或重建），
  `docker compose -f docker-compose.lite.yml up -d --build the-standard`。
- 归档服务：**不要**原地重启。按 `GhostReveal/docs/deploy/rolling-upgrade.md`
  的双实例切流流程做零中断升级（报告是不可变文件，不需要 recovery 标志）。
- 前端：重建 `ghost-reveal-frontend` 即可，无状态。

---

## 7. 安全注意事项

1. **默认只绑回环**。三个端口都发布为 `127.0.0.1:*`。要对外提供服务，必须由外层反向代理
   终止 TLS，并显式决定暴露面；不要把 `8081` / `8090` 直接绑到公网接口。
2. **外层代理路由**（TLS 终止后）：
   - `/` → `ghost-reveal-frontend:8080`（或归档服务）
   - `/core/*` → `the-standard:8081`
   - `/api/*` → `ghost-reveal-server:8090`

   这样浏览器只看到单一来源，跨域与 `THE_STANDARD_ALLOWED_ORIGINS` 的维护成本都降到最低。
3. **`allow_private_targets` 必须保持 `false`**。法仪会对调用方给出的目标 URL 主动发起请求，
   一旦允许私网目标，它就成了一个 SSRF 原语：任何能调用 `/v1/detect` 的人都能拿它探测
   内网、云元数据（169.254.169.254）或同宿主上的其他服务。本栈把三个服务放在同一宿主 /
   同一 Docker 网络上，私网暴露面更大，因此这条红线不能为了“方便联调”而放开；
   演示传输请用 `THE_STANDARD_DEMO_TARGETS` 白名单，而不是打开私网。
4. **鉴权默认关闭只是开发默认值**。生产必须同时设置 `THE_STANDARD_AUTH_TOKEN` 与
   `THE_STANDARD_REQUIRE_AUTH=true`；`/health*` 与 `/openapi.json` 不要求令牌。
5. **归档分享链接是公开的**（ULID 即公开键）。需要限制可见期时用
   `[storage].share_ttl_hours`（过期返回 `410 Gone`），需要物理清理时用 `retention_days`，
   两者互相独立。`/api/feedback*` 与导出必须带 `GHOST_REVEAL_ADMIN_TOKEN`。
6. **报告在浏览器内先脱敏**再 `POST /api/reports`；服务端也会拒绝已知敏感字段中的明文凭据。
   但报告内容仍可能包含目标模型的响应片段，不要把数据卷放在共享/多租户宿主的可读路径上。
7. 令牌、`.env`、导出的反馈文件都不要提交进仓库，也不要写进静态 `dist` 目录。
