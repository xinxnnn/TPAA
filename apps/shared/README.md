# frontend/shared

四个前端（`user-web` / `tp-web` / `ap-web` / `ops-web`）共用的代码。

放进这里的**唯一标准**：不含任何区相关逻辑。一旦某段代码需要知道自己在哪个区，
它就属于那个 App，不属于 shared。

| 目录 | 内容 | 禁止事项 |
| --- | --- | --- |
| `ui/` | 组件外壳、主题 | 发请求、读区配置 |
| `auth/` | 会话抽象形状 | 合并四端权限模型；用 localStorage 持久化会话 |
| `api-client/` | 序列化与错误归一 | 出现任何 `BASE_URL` / `/api/xxx` 字面量 |
| `types/` | 与 `packages/contracts/` 对齐的最小公约数类型 | 定义区特有实体 |
