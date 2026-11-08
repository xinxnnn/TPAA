// subagent 页面占位（user-web / user 区）
// 说明：派生子智能体：选择能力、设定有效期

export interface SubagentPageProps {
  title?: string
}

export default function SubagentPage(props: SubagentPageProps) {
  return (
    <section>
      <h2>{props.title ?? '派生子智能体：选择能力、设定有效期'}</h2>
      <p>待实现的 user 区功能：派生子智能体：选择能力、设定有效期</p>
    </section>
  )
}
