# Sangfor XDR Mock 系统

深信服 Sangfor XDR 平台的 mock 系统，用于在无法部署原系统时进行联调与测试。
**所有约束与规范与原系统一致**：AK/SK 签名算法字节级对齐官方 SDK，六类数据校验完全依据规范。

## 三大功能

1. **样例数据输出**：接口返回 + 批量导出 + 参数化生成
2. **严格格式校验**：两层校验（pydantic 字段级 + 业务规则/状态机/链路），67 条真实样例全部通过
3. **接口服务**：六类数据查询 + 校验 + 导出，完整 AK/SK 签名校验

## 安装

```bash
cd xdr-mock
pip install -r requirements.txt
```

## 启动

```bash
cd xdr-mock
python -m uvicorn app.main:app --host 0.0.0.0 --port 8443
```

访问 `http://localhost:8443/docs` 查看接口文档（无需签名）。

## 配置

编辑 `config.yaml`：

- `credentials`：ak → sk 凭证对（客户端用对应 ak 签名）
- `sign_date_window_seconds`：签名时间窗口（默认 ±15 分钟）
- `validate_strictness`：校验严格度
- `data_root`：样例数据根目录（默认指向同级 `../DataOpenDocument`）

## 签名

完全复现官方 SDK 算法（Python/Go/Java 字节级一致）：

- 签名要素：method + path（强制尾 `/`）+ 排序后的 query + header block + payload hash
- payload hash：**移除空格 → 有符号字节排序 → SHA256 → 大写 hex**
- Authorization：`algorithm=HMAC-SHA256, Access=<ak>, SignedHeaders=<...>, Signature=<UPPERHEX>`
- 注入 header：`Authorization` / `sdk-host` / `sdk-content-type` / `sign-date`
- 支持 authCode 解码（AES-CBC-NoPadding）或 ak/sk 直接配置

客户端可直接用原系统 SDK 签名后调用本 mock，无需改动。

**关键约束**（与 readme.pdf 一致）：签名后请求不可修改；签名时的 body 字节必须与发送时完全一致。

## 接口

所有 `/api/xdr/v1/` 接口需签名（`/health`、`/docs` 除外）。

### 查询（GET，分页 + 时间过滤 + 可选生成）

| 接口 | 说明 |
|---|---|
| `GET /api/xdr/v1/alerts/list` | 安全告警 |
| `GET /api/xdr/v1/incidents/list` | 安全事件 |
| `GET /api/xdr/v1/dns/list` | DNS 日志 |
| `GET /api/xdr/v1/endpoint_security/list` | 端点安全日志 |
| `GET /api/xdr/v1/endpoint_behavior/list` | 终端行为日志 |
| `GET /api/xdr/v1/network_security/list` | 网络安全日志 |
| `GET /api/xdr/v1/assets/list` | 资产列表（对齐 SDK demo） |
| `GET /api/xdr/v1/assets/department` | 部门 |

为兼容官方 OpenAPI，另提供以下 POST 查询入口（请求参数放在 JSON body）：

| 接口 | 说明 |
|---|---|
| `POST /api/xdr/v1/alerts/list` | 官方风格安全告警查询 |
| `POST /api/xdr/v1/incidents/list` | 官方风格安全事件查询 |
| `POST /api/xdr/v1/assets/list` | 官方风格资产查询 |

参数：`page`、`pageSize`、`startTimestamp`、`endTimestamp`、`generate=true`（返回参数化生成数据）、`count`。

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
python -m pytest tests/ -q
```

- `test_signing.py`：签名与原 SDK 字节级互通 + 端到端校验
- `test_validators.py`：67 条样例全部通过 + 反例检测
- `test_api.py`：接口端到端

## 客户端调用示例

```python
from app.signing.signer import Signature
import requests, json

sig = Signature(ak="test_ak_0001", sk="test_sk_0001_secret")
url = "https://localhost:8443/api/xdr/v1/alerts/list?page=1&pageSize=5"
headers = sig.sign_headers("GET", url, headers={"content-type": "application/json"}, body=None)
r = requests.get(url, headers=headers, verify=False)
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
│   ├── api/            # routes_query/validate/export + responses
│   ├── config.py / main.py
├── tests/
├── config.yaml
└── requirements.txt
```
