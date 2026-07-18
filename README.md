# Sangfor XDR Mock 系统

深信服 Sangfor XDR 平台的状态化 mock 系统，用于在没有企业 XDR、探针和真实终端时
进行 Agent 联调与可重复评测。AK/SK 签名算法和六类数据结构依据官方 SDK、
`DataOpenDocument` 与 `OpenAPIDocument`；项目自定义能力使用独立命名空间，不能当作
厂商正式接口。

## 三大功能

1. **状态化 XDR 接口**：告警、事件、日志、资产、白名单与响应任务可查询和更新
2. **严格格式校验**：两层校验（pydantic 字段级 + 业务规则/状态机/链路），67 条真实样例全部通过
3. **关联场景评测**：可重复播种告警、证据、资产和白名单，并隔离保存 ground truth

## 部署前提：先克隆 trustguard-docs

XDR Mock 不在代码仓库中重复保存厂商规范和官方样例。运行前必须先取得
`trustguard-docs`，其中的 `DataOpenDocument` 是查询、生成和完整规范回归测试的
数据来源。

请将 `trustguard-docs` 和 `trustguard-xdr-mock` 克隆到**同一个父目录**。
`trustguard-docs` 如果是私有仓库，需要先确认当前 GitHub 账号或 SSH Key 具有读取权限。

PowerShell：

```powershell
New-Item -ItemType Directory -Force trustguard-workspace | Out-Null
Set-Location trustguard-workspace

# 必须先克隆资料仓库
git clone git@github.com:hdu-sangfor/trustguard-docs.git

# 再克隆 XDR Mock
git clone https://github.com/hdu-sangfor/trustguard-xdr-mock.git
```

Linux/macOS：

```bash
mkdir -p trustguard-workspace
cd trustguard-workspace

# 必须先克隆资料仓库
git clone git@github.com:hdu-sangfor/trustguard-docs.git

# 再克隆 XDR Mock
git clone https://github.com/hdu-sangfor/trustguard-xdr-mock.git
```

期望目录结构：

```text
trustguard-workspace/
├── trustguard-docs/
│   └── xdr-api-data-specs/
│       ├── DataOpenDocument/
│       └── OpenAPIDocument/
└── trustguard-xdr-mock/
    ├── app/
    ├── tests/
    └── config.example.yaml
```

部署前可以确认数据目录存在。

PowerShell：

```powershell
Test-Path .\trustguard-docs\xdr-api-data-specs\DataOpenDocument
```

Linux/macOS：

```bash
test -d ./trustguard-docs/xdr-api-data-specs/DataOpenDocument
```

结果必须为 `True` 或退出码 `0`。如果目录不存在，服务仍可能启动，但样例查询、
模拟生成和部分测试将没有可用数据。

## 安装依赖

依赖用 [uv](https://docs.astral.sh/uv/) 管理（与 trustguard-agent 一致），版本锁定在
`uv.lock`。`uv sync` 会自动创建 `.venv` 并按锁文件精确安装：

```bash
cd trustguard-xdr-mock
uv sync              # 运行时 + 测试依赖
uv sync --no-dev     # 仅运行时依赖（部署场景）
```

后续命令都可用 `uv run` 前缀在该环境中执行，无需手动 activate。

## 配置

首次运行先复制示例配置：

```powershell
Copy-Item config.example.yaml config.yaml
```

Linux/macOS：

```bash
cp config.example.yaml config.yaml
```

`config.yaml` 是本地配置并被 Git 忽略；共享默认值维护在
`config.example.yaml`。可编辑本地 `config.yaml`：

- `credentials`：ak → sk 凭证对（客户端用对应 ak 签名）
- `sign_date_window_seconds`：签名时间窗口（默认 ±15 分钟）
- `validate_strictness`：校验严格度
- `data_root`：样例数据根目录，默认指向
  `../trustguard-docs/xdr-api-data-specs/DataOpenDocument`
- `state_db_path`：SQLite 状态库，默认 `data/xdr_mock.sqlite3`
- `enable_mock_extensions`：是否启用显式的 Mock 查询扩展
- `mock_admin_token`：`/mock/v1/**` 场景管理接口的第二重凭证

默认配置要求两个仓库保持前述同级布局：

```yaml
data_root: ../trustguard-docs/xdr-api-data-specs/DataOpenDocument
```

容器、CI 或自定义仓库布局可使用环境变量覆盖：

```powershell
$env:XDR_DATA_ROOT = 'D:\path\to\DataOpenDocument'
$env:XDR_STATE_DB_PATH = 'D:\state\xdr_mock.sqlite3'
$env:XDR_MOCK_ADMIN_TOKEN = 'replace-with-a-random-secret'
```

Linux/macOS：

```bash
export XDR_DATA_ROOT=/absolute/path/to/DataOpenDocument
export XDR_STATE_DB_PATH=/absolute/path/to/xdr_mock.sqlite3
export XDR_MOCK_ADMIN_TOKEN=replace-with-a-random-secret
```

环境变量优先级高于 `config.yaml`。使用绝对路径时不要求两个仓库位于同一父目录。

启动时会校验该目录是否存在，缺失则拒绝启动并提示如何设置 `XDR_DATA_ROOT`。

## Docker 运行（规范数据不入镜像）

镜像只打包代码，`DataOpenDocument` 通过 volume 挂载注入——既符合「不在仓库重复保存
厂商规范」的原则，也避免镜像与某个 docs 版本死锁。默认仍按同级目录布局：

```bash
docker compose up --build
```

`docker-compose.yml` 把 `../trustguard-docs/xdr-api-data-specs` 只读挂到容器 `/data`，
并使用命名卷保存 `/state/xdr_mock.sqlite3`。`OpenAPIDocument` 作为兄弟目录一并可见。

若 docs 不在默认位置，覆盖挂载源即可：

```bash
docker run --rm -p 8443:8443 \
  -v /abs/path/to/xdr-api-data-specs:/data:ro \
  -v xdr-mock-state:/state \
  -e XDR_DATA_ROOT=/data/DataOpenDocument \
  -e XDR_STATE_DB_PATH=/state/xdr_mock.sqlite3 \
  -e XDR_MOCK_ADMIN_TOKEN=replace-with-a-random-secret \
  trustguard-xdr-mock:latest
```

与 trustguard-agent 联调时，把上述 service 片段并入 agent 的 `docker-compose.yml`
即可让 mock 随栈一起起来。

## 启动

确认当前目录是 `trustguard-xdr-mock`：

```bash
uv run uvicorn app.main:app --host 0.0.0.0 --port 8443
```

启动后检查：

```text
http://localhost:8443/health
http://localhost:8443/docs
http://localhost:8443/openapi.json
```

接口文档和健康检查无需签名，业务接口需要 AK/SK 签名。

## 签名

完全复现官方 SDK 算法（Python/Go/Java 字节级一致）：

- 签名要素：method + path（强制尾 `/`）+ 排序后的 query + header block + payload hash
- payload hash：**移除空格 → 有符号字节排序 → SHA256 → 大写 hex**
- Authorization：`algorithm=HMAC-SHA256, Access=<ak>, SignedHeaders=<...>, Signature=<UPPERHEX>`
- 注入 header：`Authorization` / `sdk-host` / `sdk-content-type` / `sign-date`
- 支持 authCode 解码（AES-CBC-NoPadding）或 ak/sk 直接配置

客户端可直接用原系统 SDK 签名后调用本 mock，无需改动。

**关键约束**（与 readme.pdf 一致）：签名后请求不可修改；签名时的 body 字节必须与发送时完全一致。

Apifox 调试可以直接使用完整前置脚本：

- [`examples/apifox-pre-request-sign.js`](examples/apifox-pre-request-sign.js)

脚本会先调用无需签名的 `/health` 获取服务端 `signDate`，再生成业务请求签名，
从而自动兼容 Windows、Docker、WSL 和不同时区。Apifox 环境中需要配置
`xdr_ak`、`xdr_sk` 两个变量。

## 接口边界

除 `/health`、`/docs` 和 `/openapi.json` 外，所有接口都要求 AK/SK 签名。
实现依据为
`trustguard-docs/xdr-api-data-specs/OpenAPIDocument/深信服XDR平台接口开放列表.html`；
“兼容”表示路径、方法、主要请求字段和响应分页结构与该离线官方文档对齐，不表示已覆盖
官方全部 129 个接口。

### 1. 官方兼容层：`/api/xdr/v1/**`

Agent 在 `official` 模式下只使用这一层。

| 接口 | 当前实现 |
|---|---|
| `POST /alerts/list`、`POST /incidents/list` | 分页、时间、ID、IP、资产、严重级别等过滤 |
| `POST /securitylog/list` | 端点与网络安全日志查询 |
| `POST /analysislog/networksecurity/list` | 网络安全日志查询 |
| `GET /alerts/{uuid}/proof`、`GET /incidents/{uuid}/proof` | 证据详情 |
| `POST /alerts/dealstatus`、`POST /incidents/dealstatus` | 状态化处置，跨请求保留 |
| `POST/PUT/DELETE /assets/list` | 资产查询、写入、删除 |
| `POST /whitelists/list`、`POST /whitelists` | 白名单查询与创建 |
| `PUT /whitelists/{id}`、`PUT /whitelists/{id}/status` | 白名单更新与启停 |
| `DELETE /whitelists` | 白名单删除，DELETE 请求体参与签名 |
| `POST /responses/blockiprule/{network\|endpoint\|unblock\|reblock\|list\|detail}` | 封禁规则生命周期 |
| `POST /responses/virusscantask`、`GET /responses/virusscantask/{taskId}` | 查杀任务状态机 |

分页响应同时返回官方文档常见的 `data.item` 和旧 Mock 使用的 `data.list` 别名；
顶层同时返回 `message` 和 `msg`。新代码优先读取 `item`、`message`。

### 2. Agent 开发扩展：`/api/trustguard-mock/v1/query/**`

该层不是官方接口，响应带 `x-mock-extension: true`。仅当 Connector 配置为
`mock_extended` 时使用：

| 接口 | 说明 |
|---|---|
| `POST /query/dns` | DNS 原始日志查询 |
| `POST /query/endpoint-security` | 端点安全原始日志查询 |
| `POST /query/endpoint-behavior` | 终端行为日志查询 |
| `POST /query/whitelist-match` | 用告警上下文执行 Mock 白名单匹配 |

官方文档没有 `/api/xdr/v1/whitelists/match`、`/api/xdr/v1/history/alerts/list`，
本项目不会伪造这两个官方路径。历史研判结论应由 TrustGuard Evidence 存储。

### 3. 测试编排层：`/mock/v1/**`

这一层要求 AK/SK 和 `X-Mock-Admin-Token`，只供测试驱动程序调用，Agent 禁止访问。

| 接口 | 说明 |
|---|---|
| `GET /scenarios` | 查看可用场景 |
| `POST /scenarios/{scenarioId}:seed` | 幂等播种关联数据 |
| `POST /scenarios:reset` | 清除所有场景数据并重置虚拟时钟 |
| `POST /clock:advance` | 推进任务状态所用虚拟时钟 |
| `GET /scenarios/{scenarioId}/timeline` | 查看完整场景时间线 |
| `GET /scenarios/{scenarioId}/ground-truth` | 获取评测标准答案 |

内置 `false-positive-powershell-001`：已审批的资产盘点 PowerShell 脚本触发告警，
关联两条端点日志、资产 `17820`、白名单 `WL-PS-001` 和审批单
`CHG-2026-0718-001`。Agent 收到的是官方告警/资产/白名单响应及显式 Mock 日志响应，
不会收到 ground truth。

### 4. 旧版调试兼容入口

`GET /api/xdr/v1/{data_type}/list`、`/validate/**` 和 `/export/**` 是早期 Mock
调试能力，并非官方 OpenAPI。为了不破坏已有脚本暂时保留；新 Connector 不应依赖它们。

### 校验（POST，返回校验报告）

| 接口 | 说明 |
|---|---|
| `POST /api/xdr/v1/validate/{data_type}` | 校验单条数据 |
| `POST /api/xdr/v1/validate/batch/{data_type}` | 批量校验（body: `{"records":[...]}`) |

返回：`{valid, errors:[{path,msg,code,value}], warnings:[...]}`

### 导出（GET，每行一条 JSON）

| 接口 | 说明 |
|---|---|
| `GET /api/xdr/v1/export/{data_type}?count=N` | 导出 N 条样例 |
| `GET /api/xdr/v1/export/{data_type}?count=N&generate=true` | 导出生成数据 |

## 校验规则

### 第一层：字段级（pydantic v2）

- 类型、必填、格式（regionId 24 位、uuId 格式、v 版本公式）
- 单层 vs 双层：事件/告警双层（字段在 `data` 内），DNS/网络/端点/终端行为单层
- `extra="allow"`：规范外字段记 warning 不报错（样例有额外字段）

严格度行为：

- `normal`：必填、类型和硬枚举错误会拒绝；历史格式和模型外字段记 warning。
- `strict`：UUID、regionId、版本偏差和模型外字段升级为 error。
- `lenient`：仅执行 Pydantic 必填字段和类型校验，跳过业务规则。

非法 JSON、非对象记录、未知数据类型和非法时间范围会返回对应的 HTTP 4xx，
不再使用 HTTP 200 包装业务错误。

### 第二层：业务规则

- **logTraceInfo 节点链**（每类数据期望的 appName 序列）：
  - DNS/网络：`logDetect → logUpload → collect → transfer`
  - 事件：`collect → transfer → edr → alert → nae → incident`
  - 告警：`collect → transfer → [alphaApp → seclog → ndr] → alert`
  - 端点：`collect → transfer`
  - 终端行为：无 logTraceInfo
- **时间不变式**：`insertTimestamp ≥ uploadTimestamp`；`cloudTs` 偏差异常检测
- **状态机**：`dealStatus`（告警 9 态）、`attackState`（4 态）、`detectionStatus` 流转
- **枚举校验**：硬枚举（非法值报错）+ 软枚举（哨兵值/偏离记 warning）

## 数据类型与样例

| 类型 | 结构 | type | logTraceInfo 链 |
|---|---|---|---|
| 安全事件 | 双层 | INCIDENT/update-incident | collect→transfer→edr→alert→nae→incident |
| 安全告警 | 双层 | ALERT | collect→transfer→[alphaApp→seclog→ndr]→alert |
| DNS日志 | 单层 | — | logDetect→logUpload→collect→transfer |
| 端点安全日志 | 单层 | — | collect→transfer |
| 终端行为日志 | 单层 | — | 无 |
| 网络安全日志 | 单层 | — | logDetect→logUpload→collect→transfer |

## 测试

```bash
cd xdr-mock
uv run pytest -q
```

- `test_signing.py`：签名与原 SDK 字节级互通 + 端到端校验
- `test_validators.py`：67 条样例全部通过 + 反例检测
- `test_api.py`：接口端到端
- `test_stateful_mock.py`：状态持久化、权限边界、关联误报场景与任务生命周期

## 客户端调用示例

```python
from app.signing.signer import Signature
import requests, json

sig = Signature(ak="test_ak_0001", sk="test_sk_0001_secret")
url = "https://localhost:8443/api/xdr/v1/alerts/list"
body_bytes = json.dumps({"page": 1, "pageSize": 5}).encode("utf-8")
headers = sig.sign_headers(
    "POST", url, headers={"content-type": "application/json"}, body=body_bytes
)
r = requests.post(url, data=body_bytes, headers=headers, verify=False)
print(r.json())
```

> POST 请求须保证签名时的 body 字节与发送时一致：先 `body_bytes = json.dumps(data).encode()`，签名与 `requests.post(data=body_bytes)` 共用同一字节串。

## 目录结构

```
xdr-mock/
├── app/
│   ├── signing/        # 签名：canonical/auth_code/signer/verifier
│   ├── models/         # 六类 pydantic 模型 + enums + process_chain
│   ├── validators/     # logtrace/time/state_machine/enum_check/registry
│   ├── generators/     # loader/synthetic/exporter
│   ├── api/            # 官方兼容、Mock 扩展、场景管理路由
│   ├── repositories/   # SQLite 状态仓库
│   ├── scenarios/      # 可重复关联场景与 ground truth
│   ├── config.py / main.py
├── tests/
├── config.example.yaml # 可追踪的配置模板
├── config.yaml         # 本地配置，Git 忽略
├── pyproject.toml      # 依赖声明（uv）
├── uv.lock             # 锁定的依赖版本
├── Dockerfile          # uv 多阶段构建，数据不入镜像
└── docker-compose.yml  # 挂载 trustguard-docs 规范数据
```
