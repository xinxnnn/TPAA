#!/usr/bin/env python3
"""脚手架：生成 TPAA frontend 四方前端骨架（步骤 8）。

按 ARCHITECTURE.md §7 / §10：四个前端各自独立部署、各自独立域名，
每个前端只能访问本方（本区）的后端，跨域访问由 coordination 代理，前端不得直连。

只生成文本文件，不安装依赖、不联网。可重复运行（--force 覆盖）。

    python scripts/gen_frontend_skeleton.py [--force]
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "apps"

# 每个前端的归属区、可访问的 API 前缀（见 §10 部署与网络拓扑）、端口、页面
APPS: dict[str, dict] = {
    "user-web": {
        "title": "TPAA 用户端",
        "zone": "user",
        "port": 5173,
        "api_prefix": "/api/user",
        "services": ["portal-api"],
        "pages": ["auth", "phc", "agent", "subagent", "subagent/confirm", "vault", "lifecycle"],
        "note": "申领 PHC、申领主智能体、派生子智能体（需手动确认）、保险箱、找回/注销",
    },
    "tp-web": {
        "title": "TPAA 可信第三方控制台",
        "zone": "tp",
        "port": 5174,
        "api_prefix": "/api/tp",
        "services": ["identity-service", "review-service", "phc-service", "did-service", "supervision-service"],
        "pages": ["review", "phc", "did", "supervision"],
        "note": "人工核验审批、凭证台账与吊销、DID 与父子关系、举报→立案→协查→取证",
    },
    "ap-web": {
        "title": "TPAA 智能体提供方控制台",
        "zone": "ap",
        "port": 5175,
        "api_prefix": "/api/ap",
        "services": ["agent-service", "subagent-service", "lifecycle-service"],
        "pages": ["modules", "primary-agents", "sub-agents", "lifecycle"],
        "note": "能力模块库、主智能体实例与 CMI、子智能体派生记录、升级/找回任务",
    },
    "ops-web": {
        "title": "TPAA 平台运营台",
        "zone": "ops",
        "port": 5176,
        "api_prefix": "/api/ops",
        "services": ["gateway", "policy-service", "audit-service", "coordination"],
        "pages": ["overview", "module-review", "stats", "permissions"],
        "note": "不属于 User/TP/AP 任何一方，只能访问跨域治理接口的只读视图",
    },
}

PKG_TEMPLATE = """{
  "name": "@tpaa/{{app}}",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2"
  },
  "devDependencies": {
    "@types/react": "^18.3.11",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.2",
    "typescript": "^5.6.3",
    "vite": "^5.4.9"
  }
}
"""

ROOT_PKG = """{
  "name": "@tpaa/frontend",
  "private": true,
  "type": "module",
  "workspaces": [
    "user-web",
    "tp-web",
    "ap-web",
    "ops-web"
  ],
  "scripts": {
    "dev:user": "npm --workspace @tpaa/user-web run dev",
    "dev:tp": "npm --workspace @tpaa/tp-web run dev",
    "dev:ap": "npm --workspace @tpaa/ap-web run dev",
    "dev:ops": "npm --workspace @tpaa/ops-web run dev",
    "typecheck": "npm --workspaces --if-present run typecheck",
    "boundary": "python ../scripts/check_frontend_boundary.py"
  },
  "devDependencies": {
    "@types/react": "^18.3.11",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.2",
    "typescript": "^5.6.3",
    "vite": "^5.4.9"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2"
  }
}
"""

ROOT_README = """# frontend

四个前端各自独立部署、各自独立域名（见 ARCHITECTURE.md §10），这里是它们的 workspace 根。

## 为什么要提升到根安装

`shared/` 与四个 App 是**同级目录**。如果依赖装在单个 App 里（`user-web/node_modules`），
`shared/ui` 向上解析时会找不到 `react` 的类型声明，报 TS2307。

所以依赖必须提升到 `frontend/node_modules` —— 这也是 npm workspaces 的默认行为：

```bash
npm install          # 在 frontend/ 执行，不要进单个 App 里装
npm run typecheck    # 四个 App 一起做类型检查
npm run dev:user     # 起用户端
```

## 区-前缀对照

| App | 区 | 只允许访问 | 端口 |
| --- | --- | --- | --- |
| `user-web` | User | `/api/user` | 5173 |
| `tp-web` | TP | `/api/tp` | 5174 |
| `ap-web` | AP | `/api/ap` | 5175 |
| `ops-web` | 跨域治理 | `/api/ops` | 5176 |

这张表由 `scripts/check_frontend_boundary.py` 在 CI 里静态强制（F1–F5）。
"""

TSCONFIG_TEMPLATE = """{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "moduleResolution": "bundler",
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "skipLibCheck": true,
    "isolatedModules": true,
    "resolveJsonModule": true,
    "allowImportingTsExtensions": false,
    "noEmit": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src"]
}
"""

VITE_TEMPLATE = """import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// {{zone}} 区前端：独立部署、独立域名。
// API 前缀写死为 {{api_prefix}} —— 跨域访问只能在后端 coordination 完成，前端不得直连别的区。
export default defineConfig({
  plugins: [react()],
  server: {
    port: {{port}},
    proxy: {
      '{{api_prefix}}': {
        target: process.env.TPAA_{{zone_code}}_UPSTREAM ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
"""

INDEX_HTML_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{{title}}</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
"""

MAIN_TEMPLATE = """import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
"""

APP_TEMPLATE = """// {{title}}（{{zone}} 区）
//
// 边界约束（由 scripts/check_frontend_boundary.py 强制）：
//   1. 只允许访问 {{api_prefix}} 前缀的本区后端；不得直连其他区
//   2. 前端不持有任何密钥、不做加解密 —— 密码学动作只在后端 crypto.sdk 内发生
//   3. 派生子智能体必须由用户在本端手动确认（见 pages/subagent/confirm）

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
// 相对路径引用同级 shared（避免 node API；依赖提升到 frontend/ 根后才可解析）
import { AppShell } from '../../shared/ui'

{{imports}}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell title="{{title}}" zone="{{zone}}">
        <Routes>
          <Route path="/" element={<Navigate to="{{home}}" replace />} />
{{routes}}
        </Routes>
      </AppShell>
    </BrowserRouter>
  )
}
"""

PAGE_TEMPLATE = """// {{page}} 页面占位（{{app}} / {{zone}} 区）
// 说明：{{desc}}

export interface {{comp}}Props {
  title?: string
}

export default function {{comp}}(props: {{comp}}Props) {
  return (
    <section>
      <h2>{props.title ?? '{{desc}}'}</h2>
      <p>待实现的 {{zone}} 区功能：{{desc}}</p>
    </section>
  )
}
"""

API_CLIENT_TEMPLATE = """// {{title}} 访问后端的唯一出口。
//
// 红线（见 ARCHITECTURE.md §10，由 scripts/check_frontend_boundary.py 静态强制）：
//   ✅ 只允许 {{api_prefix}} —— 对应 {{zone}} 区：{{services}}
//   ❌ 禁止在前端拼接/硬编码其他区的路径（/api/tp、/api/ap、/api/user、/api/ops）
//   ❌ 前端不做加解密、不持有密钥；SecInfo 信封只在后端构造

export const ZONE = '{{zone}}' as const
export const BASE_URL = '{{api_prefix}}' as const
export const UPSTREAM_SERVICES = [{{services_list}}] as const

export interface ApiErrorBody {
  code: string
  message: string
  traceId?: string
}

export class ApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message ?? `HTTP ${status}`)
  }
}

function assertSameZone(path: string): void {
  if (!path.startsWith(BASE_URL)) {
    // 跨域直连在前端层直接抛错 —— 必须改走后端的 coordination 服务
    throw new Error(`[boundary] ${ZONE} 区前端禁止访问 ${path}（只允许 ${BASE_URL}）`)
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  assertSameZone(path)
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  })
  if (!res.ok) {
    let body: ApiErrorBody = { code: 'UNKNOWN', message: res.statusText }
    try {
      body = (await res.json()) as ApiErrorBody
    } catch {
      /* 保留默认 body */
    }
    throw new ApiError(res.status, body)
  }
  return (await res.json()) as T
}

export const get = <T,>(p: string) => request<T>(p)
export const post = <T,>(p: string, body: unknown) =>
  request<T>(p, { method: 'POST', body: JSON.stringify(body) })
"""

SHARED_UI = """// 共用 UI 外壳：四个前端各自独立部署，但共用同一套外观与布局。
// 注意：shared 只放展示型代码；任何与区相关的后端访问都不允许放进 shared。

import type { ReactNode } from 'react'

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

const ZONE_LABEL: Record<Zone, string> = {
  user: 'User 区',
  tp: 'TP 区',
  ap: 'AP 区',
  ops: '跨域治理',
}

export interface AppShellProps {
  title: string
  zone: Zone
  children: ReactNode
}

export function AppShell(props: AppShellProps) {
  return (
    <div data-zone={props.zone} style={{ fontFamily: 'system-ui, sans-serif', padding: 24 }}>
      <header style={{ borderBottom: '1px solid #ddd', paddingBottom: 12, marginBottom: 16 }}>
        <strong>{props.title}</strong>
        <span style={{ marginLeft: 12, color: '#666' }}>{ZONE_LABEL[props.zone]}</span>
      </header>
      <main>{props.children}</main>
    </div>
  )
}
"""

SHARED_AUTH = """// 四个前端的权限模型互不相通：同一个自然人账号，在 user-web / tp-web / ap-web
// 是三套彼此独立的角色体系，不得在 shared 里做统一角色合并。
//
// 这里只定义会话的抽象形状，各区 App 自己决定 roles 的取值来源与校验方式。

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

export interface Session {
  zone: Zone
  subject: string
  roles: readonly string[]
  expiresAt: number
}

export function hasRole(s: Session, role: string): boolean {
  return s.roles.includes(role)
}

// 会话只允许存 sessionStorage（关闭标签页即失效），禁止 localStorage 持久化（红线 F3）。
const KEY = 'tpaa.session'

export function loadSession(): Session | null {
  const raw = sessionStorage.getItem(KEY)
  return raw ? (JSON.parse(raw) as Session) : null
}

export function saveSession(s: Session): void {
  sessionStorage.setItem(KEY, JSON.stringify(s))
}

export function clearSession(): void {
  sessionStorage.removeItem(KEY)
}
"""

SHARED_API_CLIENT = """// 跨四端共用的请求工具：只做「序列化 + 错误归一」，
// 具体的 BASE_URL 与区划属由各 App 的 services/api-client.ts 决定（不允许下沉到 shared）。

export interface ApiErrorBody {
  code: string
  message: string
  traceId?: string
}

export class ApiError extends Error {
  constructor(public status: number, public body: ApiErrorBody) {
    super(body.message ?? `HTTP ${status}`)
  }
}

export function toQuery(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) usp.set(k, String(v))
  }
  const s = usp.toString()
  return s ? `?${s}` : ''
}
"""

SHARED_TYPES = """// 与 contracts/ 对齐的共享类型（见 ARCHITECTURE.md §19）。
// 这里的字段是四个前端都要用到的最小公约数；区特有的字段放在各 App 的 types 里。

export type Zone = 'user' | 'tp' | 'ap' | 'ops'

/** PHC 申领单状态机，见 §12.1 */
export type PhcApplicationState =
  | 'draft'
  | 'pending_review'
  | 'reviewing'
  | 'approved'
  | 'issuing'
  | 'issued'
  | 'rejected'
  | 'revoked'

/** 智能体凭证状态 */
export type AgentCredentialState = 'active' | 'suspended' | 'revoked' | 'expired'

/** 追溯链路阶段，见 §12 吊销链路 */
export type TraceStage = 'reported' | 'filed' | 'assisting' | 'disclosed' | 'revoked'

export interface AgentSummary {
  did: string
  displayName: string
  parentDid: string | null
  state: AgentCredentialState
  issuedAt: number
  expiresAt?: number
}

export interface PhcSummary {
  applicationId: string
  state: PhcApplicationState
  /** 只传 AF/TPCH 等非秘密值；CRF、RF 密文永不出后端 */
  agentFactor?: string
  updatedAt: number
}
"""

SHARED_README = """# frontend/shared

四个前端（`user-web` / `tp-web` / `ap-web` / `ops-web`）共用的代码。

放进这里的**唯一标准**：不含任何区相关逻辑。一旦某段代码需要知道自己在哪个区，
它就属于那个 App，不属于 shared。

| 目录 | 内容 | 禁止事项 |
| --- | --- | --- |
| `ui/` | 组件外壳、主题 | 发请求、读区配置 |
| `auth/` | 会话抽象形状 | 合并四端权限模型；用 localStorage 持久化会话 |
| `api-client/` | 序列化与错误归一 | 出现任何 `BASE_URL` / `/api/xxx` 字面量 |
| `types/` | 与 `contracts/` 对齐的最小公约数类型 | 定义区特有实体 |
"""


def _camel(page: str) -> str:
    """subagent/confirm -> SubagentConfirmPage"""
    parts = [p for p in page.replace("-", "/").split("/") if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) + "Page"


PAGE_DESC = {
    "auth": "登录与实名会话",
    "phc": "申领 PHC：上传 BI、查看审核进度与结果",
    "agent": "申领主智能体：选配能力 → 生成 → 一键运行",
    "subagent": "派生子智能体：选择能力、设定有效期",
    "subagent/confirm": "派生确认页：展示新 RF 与唯一 DID 的知情条款（必须用户手动确认）",
    "vault": "我的智能体：主/子清单、派生关系树、交互视图",
    "lifecycle": "升级、找回（PHC 在 / PHC 不在）、注销",
    "review": "待审队列、BI 比对、批准/驳回、操作留痕",
    "did": "DID 查询、撤销列表、父子关系",
    "supervision": "举报池、立案、协查、取证包",
    "modules": "能力模块库 CMC、矩阵 CMM 配置、上架",
    "primary-agents": "主智能体实例、CMI、版本",
    "sub-agents": "子智能体实例、派生记录、父指针、TTL",
    "overview": "总览台账",
    "module-review": "模块审核",
    "stats": "统计",
    "permissions": "权限",
}


def _write(p: Path, content: str, force: bool) -> None:
    if p.exists() and not force:
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _render(tpl: str, spec: dict, app: str) -> str:
    return (
        tpl.replace("{{title}}", spec["title"])
        .replace("{{zone}}", spec["zone"])
        .replace("{{zone_code}}", spec["zone"].upper())
        .replace("{{port}}", str(spec["port"]))
        .replace("{{api_prefix}}", spec["api_prefix"])
        .replace("{{app}}", app)
        .replace("{{services}}", "、".join(spec["services"]))
        .replace(
            "{{services_list}}",
            ", ".join(f"'{s}'" for s in spec["services"]),
        )
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    # workspace 根：依赖提升到 frontend/node_modules，shared 才能解析到同一份依赖
    _write(FRONTEND / "package.json", ROOT_PKG, args.force)
    _write(FRONTEND / "README.md", ROOT_README, args.force)

    for app, spec in APPS.items():
        base = FRONTEND / app
        pages = spec["pages"]

        _write(base / "package.json", PKG_TEMPLATE.replace("{{app}}", app), args.force)
        _write(base / "tsconfig.json", TSCONFIG_TEMPLATE, args.force)
        _write(base / "vite.config.ts", _render(VITE_TEMPLATE, spec, app), args.force)
        _write(base / "index.html",
               INDEX_HTML_TEMPLATE.replace("{{title}}", spec["title"]), args.force)
        _write(base / "src" / "main.tsx", MAIN_TEMPLATE, args.force)
        _write(base / "src" / "services" / "api-client.ts",
               _render(API_CLIENT_TEMPLATE, spec, app), args.force)

        imports, routes = [], []
        for page in pages:
            comp = _camel(page)
            imports.append(f"import {comp} from './pages/{page}'")
            routes.append(f'          <Route path="/{page}" element={{<{comp} />}} />')
            _write(
                base / "src" / "pages" / page / "index.tsx",
                PAGE_TEMPLATE.replace("{{page}}", page)
                .replace("{{app}}", app)
                .replace("{{zone}}", spec["zone"])
                .replace("{{comp}}", comp)
                .replace("{{desc}}", PAGE_DESC.get(page, page)),
                args.force,
            )

        app_tpl = (
            APP_TEMPLATE.replace("{{title}}", spec["title"])
            .replace("{{zone}}", spec["zone"])
            .replace("{{api_prefix}}", spec["api_prefix"])
            .replace("{{imports}}", "\n".join(imports))
            .replace("{{routes}}", "\n".join(routes))
            .replace("{{home}}", pages[0])
        )
        _write(base / "src" / "App.tsx", app_tpl, args.force)

        for sub in ("components", "hooks", "store", "types"):
            _write(
                base / "src" / sub / "index.ts",
                f"// {app} / {sub} —— 占位。入口见 ARCHITECTURE.md §7「前端」小节。\n"
                f"// 约束：{spec['note']}\n",
                args.force,
            )

        _write(
            base / "README.md",
            f"# {spec['title']}（{spec['zone']} 区）\n\n{spec['note']}。\n\n"
            f"- 允许访问：`{spec['api_prefix']}` → {', '.join(spec['services'])}\n"
            f"- 禁止：直连其他区的前端 URL；前端做加解密或持有密钥\n"
            f"- 边界由 `scripts/check_frontend_boundary.py` 在 CI 静态强制\n",
            args.force,
        )

    # shared 包
    shared = FRONTEND / "shared"
    _write(shared / "ui" / "index.tsx", SHARED_UI, args.force)
    _write(shared / "auth" / "index.ts", SHARED_AUTH, args.force)
    _write(shared / "api-client" / "index.ts", SHARED_API_CLIENT, args.force)
    _write(shared / "types" / "index.ts", SHARED_TYPES, args.force)
    _write(shared / "README.md", SHARED_README, args.force)

    total_pages = sum(len(s["pages"]) for s in APPS.values())
    print(
        f"frontend 骨架已生成：{len(APPS)} 个前端应用，共 {total_pages} 个页面，"
        "外加 shared/（ui / auth / api-client / types）。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
