// primary-agents 页面占位（ap-web / ap 区）
// 说明：主智能体实例、CMI、版本

export interface PrimaryAgentsPageProps {
  title?: string
}

export default function PrimaryAgentsPage(props: PrimaryAgentsPageProps) {
  return (
    <section>
      <h2>{props.title ?? '主智能体实例、CMI、版本'}</h2>
      <p>待实现的 ap 区功能：主智能体实例、CMI、版本</p>
    </section>
  )
}
