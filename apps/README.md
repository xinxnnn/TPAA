# frontend

四个前端各自独立部署、各自独立域名（见 ARCHITECTURE.md §10），这里是它们的 workspace 根。

## 为什么要提升到根安装

`shared/` 与四个 App 是**同级目录**。如果依赖装在单个 App 里（`user-web/node_modules`），
`shared/ui` 向上解析时会找不到 `react` 的类型声明，报 TS2307。

所以依赖必须提升到 `apps/node_modules` —— 这也是 npm workspaces 的默认行为：

```bash
npm install          # 在 apps/ 执行，不要进单个 App 里装
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
