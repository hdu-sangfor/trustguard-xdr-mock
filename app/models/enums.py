# -*- coding: utf-8 -*-
"""所有枚举常量（集中管理）。

来源：六类数据规范 + 引用的分类规范（安全日志分类v1.14/事件分类v1.0/风险标签v1.1/设备分类v1.5）。
未知值统一用 -1（安全日志分类规范约定）。
"""
from __future__ import annotations

# ============ 通用枚举 ============
LOG_SAMPLED = {0, 1}                          # 0不采样 1采样
IP_TAG = {0, 1}                               # 0内网 1外网
RELATE_ASSET_TYPE = {0, 1}                    # 0主机 1容器
GROUP_MAP_FLAG = {-1, 0, 1}                   # -1非映射 0 IP+端口 1域名
HOST_OS_PRODUCT_TYPE = {1, 2, 3, 4, 5}        # 1 WinPC 2 WinServer 3 Linux 4 Mac 5国产化

# ============ 攻击/状态机 ============
ATTACK_STATE = {0, 1, 2, 3}                   # 0尝试 1失败 2成功 3失陷
ALERT_DEAL_STATUS = {0, 10, 20, 30, 40, 50, 60, 70, 80}
# 告警处置: 0未处置 10生成事件 20已完成 30已加白 40已驳回 50已忽略 60已遏制 70处置中 80误报
INCIDENT_DEAL_STATUS = {0, 10, 20, 30, 40, 50, 60, 70, 80}
DETECTION_STATUS = {0, 1}                     # 0事中 1事后
WHITE = {0, 1, 2}                             # 0未加白 1系统自动加白 2用户加白
HAS_REPORTED = {0, 1, 2}                      # 0未知 1首次上报 2非首次上报
CASCADE_TYPE = {0, 1}                         # 0非级联 1分布式XDR级联SaaSXDR

# ============ 等级（三套并存）============
RISK_LEVEL = {0, 1, 2, 3, 4, 5}               # 0严重 1高危 2中危 3低危险 4信息 5未知
# severity: 数值区间 (0,10]信息 (10,30]低危 (30,50]中危 (50,70]高危 (70,100]严重；0可用
# confidence: 0未知 (0,40]低 (40,70]中 (70,100]高
def _severity_range(v):
    if v is None:
        return True
    if isinstance(v, int) and 0 <= v <= 100:
        return True
    return False

# ============ 告警特有 ============
DIRECTION = {0, 1, 2, 3}                      # 0无 1内到外 2外到内 3内对内
STAGE = {0, 10, 20, 30, 40, 50, 60, 70, 80}   # 告警阶段(riskLevel研判)
SRC_ASSET_TAG = {0, 1}                        # 0应用 1人
SUBJECT_TYPE = {"user", "hostIp", "app"}
COMBINE_TYPE = {0, 10, 20, 30, 40}            # 0单N 10单E 20N+N 30E+E 40N+E
THREAT_DEFINE = {0, 200, 300, 400, 450, 500, 900}
# 0未知威胁 200业务行为 300脆弱性风险 400扫描器攻击 450疑似定向 500病毒 900定向攻击

# ============ 动作 ============
ACTION_LOG = {0, 1, 2}                        # 网络日志: 0未知 1允许 2拒绝
ACTION_ENDPOINT = {0, 1, 2, 3}                # 端点: 0未知 1允许 2拒绝 3监控

# ============ TCP 会话状态机 ============
TCP_START_STATE = {0, 1, 2, 3, 4, 5, 6}       # 0未知 1syn 2syn-ack 3push-ack 4rst 5fin 6ack
TCP_SESSION_STATE = {0, 1, 2, 3, 4, 5}        # 0未知 1syn 2syn-ack 3established 4fin 5reset

# ============ SOCKS / 协议 ============
SOCKS_VER = {4, 5}                            # 4 socks4 5 socks5
SOCKS_METHOD = {0, 2}                         # 0无认证 2用户名密码
SOCKS_ADDRESS_TYPE = {1, 3, 4}                # 1 IPV4 3域名 4 IPV6
TI_TYPE = {0, 1, 2}                           # 0 domain 1 URL 2 IP
INTEL_TYPE = {0, 1, 2, 3}                     # threatDetail.type: 0domain 1url 2ip 3file

# ============ 暴力破解 / 扫描 ============
BF_DIRECTION = {0, 1}                         # 0发起 1被破解
BF_TYPE = {0, 1, 2, 3}                        # 0快速 1慢速 2分布式快速 3分布式慢速
SCAN_DIRECTION = {0, 1}                       # 0发起 1被扫描

# ============ 登录 ============
LOGIN_TYPE_WIN = {2, 3, 4, 5, 7, 10}          # 2交互式 3网络 4批处理 5服务 7解锁 10远程交互

# ============ 终端行为日志 eventId ============
EVENT_ID = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 255, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    310, 311, 312,
}
REG_OP_TYPE = {0, 1, 2, 3, 4, 5, 6, 9999}     # 注册表操作（9999 样例哨兵）
LINK_TYPE = {0, 1, 2}                         # 0无 1软链接 2硬链接
SERVICE_TYPE = {0, 1, 2, 3, 4}                # 0Boot 1System 2Automatic 3Manual 4Disabled
SERVICE_STATUS = {0, 1}                       # 0停止 1启动
CONNECT_STATUS = {0, 1}                       # 0成功 1失败
FILE_OP_STATUS = {0, 1}                       # 0成功 1失败
REG_TOKEN_TYPE = {1, 2}                       # 1主令牌 2模拟令牌
IMAGE_PLACE = {0, 1, 2}                       # 0本地磁盘 1可移动 2网络
WIN_HOOK_ID = {2, 7, 10}                      # 2键盘 7鼠标 10shell
MEM_PROTECT_TYPE = {1, 2, 4, 16, 32, 64}
USER_STATUS = {0, 1}                          # 账户删除 0成功 1失败

# ============ 端点安全日志 ============
VIRUS_FIND_TYPE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16}
FILE_STATUS = {0, 1, 2}                       # 文件信誉 0黑 1白 2灰
FILE_CLASS = {0, 1, 2, 4, 8, 16}              # 0未分类 1PE 2压缩 4文档 8脚本 16ELF
FILE_OPERATION_TYPE = {4, 5, 6, 7, 8}
PROCESS_HANDLE_STATE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
SAVE_ANALYZE_TYPE = {0, 1, 2, 3, 4, 5, 6, 7, 8}
SAVE_VBA_RESULT = {0, 1, 2, 3}
PS_EXEC_TYPE = {0}
PS_FIND_TYPE = {1}
# alertDetails.alertType
ALERT_DETAIL_TYPE = set(range(0, 16))         # 0-15

# processChain edge.type 行为类型
EDGE_TYPE = set(range(0, 35)) | {100}
# 注入类型 subtype
INJECT_SUBTYPE = set(range(0, 11))

# ============ 病毒扫描引擎（字符串枚举）============
VIRUS_DETECT_ENGINE = {
    "invalid", "local_av_cache", "local_av_cobra", "local_av_frep", "av_cloud",
    "local_av_save", "hot_event", "av_ira", "rsmkiller", "nofile_attack",
    "signature", "classifier", "focalkill", "macro", "webshell_detecter",
    "autocad", "linux_focalkill", "bd", "md", "custom_ioc", "rootkit",
    "hacktool", "pe_repair", "sabfd", "domain_proof_engine",
}

# ============ 告警 alertEngine / 事件 eventEngine（ID 范围宽松）============
# alertEngine: EDR 1-999, NDR 1000-1999（规范大表，此处用范围）
# eventEngine: 1-22, 1000-1016, 1101, 2000/2001/2999
def _in_engine_range(v, ranges):
    if v is None:
        return True
    if isinstance(v, int):
        return any(lo <= v <= hi for lo, hi in ranges)
    return False

ALERT_ENGINE_RANGES = [(1, 999), (1000, 1999)]
EVENT_ENGINE_RANGES = [(1, 22), (1000, 1016), (1101, 1101), (2000, 2001), (2999, 2999)]

# ============ DNS 标志位（0/1）============
DNS_FLAG = {0, 1}
# qr 0请求1响应; opCode 0标准1反向2服务器状态; z 恒0
DNS_OPCODE = {0, 1, 2}

# ============ 安全日志分类（threatClass/threatType/threatSubType, int）============
# 引用安全日志分类规范v1.14：大类/小类/子类三级。完整表很大，此处列大类与部分小类，
# 校验时采用「已知值集合 ∪ {-1未知}」，未命中记 warning（避免误杀客户自定义）。
SEC_LOG_THREAT_CLASS = {
    94, 214, 201, 203, 204, 205, 96, 10, 207, 30, 208, 213, 40, 209, 212,
    218, 219, 216, 217, 220, 230,
}
# 安全事件分类（string 编码）：0001有害程序 0002网络攻击 0003信息破坏
INCIDENT_THREAT_CLASS = {"0001", "0002", "0003"}

# ============ 设备类别 devUId（引用设备分类v1.5）============
# 1-9999 内置, 10000-19999 自定义, 20000-20999 XStream, 21000-29999 自动上架
def _valid_devuid(v):
    if v is None:
        return True
    if isinstance(v, int):
        return 1 <= v <= 29999
    return False

DEVUID_RANGES = [(1, 9999), (10000, 19999), (20000, 20999), (21000, 29999)]

# ============ 风险标签 riskTag（引用风险标签v1.1，Axxx_Bxxx）============
RISK_TAG_PATTERN = __import__("re").compile(r"^A\d{3}_B\d{3}$")

# ============ 登录编码类型 ============
ENCODE_TYPE = {"base64", "raw", "url", "md5", "sha1", "sha256"}

# ============ 文件属性 fileAttr（bitmask，合法位）============
FILE_ATTR_BITS = {0, 1, 2, 4, 16, 32, 256, 2048, 16384, 8388608, 16777216, 33554432}

# ============ fileState（端点文件处置状态）============
FILE_STATE = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99, 100}
