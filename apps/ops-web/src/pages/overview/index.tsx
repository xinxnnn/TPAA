// overview 页面占位（ops-web / ops 区）
// 说明：总览台账

export interface OverviewPageProps {
  title?: string
}

export default function OverviewPage(props: OverviewPageProps) {
  return (
    <section>
      <h2>{props.title ?? '总览台账'}</h2>
      <p>待实现的 ops 区功能：总览台账</p>
    </section>
  )
}
