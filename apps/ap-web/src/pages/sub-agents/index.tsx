// sub-agents 页面占位（ap-web / ap 区）
// 说明：子智能体实例、派生记录、父指针、TTL

export interface SubAgentsPageProps {
  title?: string
}

export default function SubAgentsPage(props: SubAgentsPageProps) {
  return (
    <section>
      <h2>{props.title ?? '子智能体实例、派生记录、父指针、TTL'}</h2>
      <p>待实现的 ap 区功能：子智能体实例、派生记录、父指针、TTL</p>
    </section>
  )
}
