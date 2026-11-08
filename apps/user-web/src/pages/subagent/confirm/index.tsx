// subagent/confirm 页面占位（user-web / user 区）
// 说明：派生确认页：展示新 RF 与唯一 DID 的知情条款（必须用户手动确认）

export interface SubagentConfirmPageProps {
  title?: string
}

export default function SubagentConfirmPage(props: SubagentConfirmPageProps) {
  return (
    <section>
      <h2>{props.title ?? '派生确认页：展示新 RF 与唯一 DID 的知情条款（必须用户手动确认）'}</h2>
      <p>待实现的 user 区功能：派生确认页：展示新 RF 与唯一 DID 的知情条款（必须用户手动确认）</p>
    </section>
  )
}
