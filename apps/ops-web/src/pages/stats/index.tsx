// stats 页面占位（ops-web / ops 区）
// 说明：统计

export interface StatsPageProps {
  title?: string
}

export default function StatsPage(props: StatsPageProps) {
  return (
    <section>
      <h2>{props.title ?? '统计'}</h2>
      <p>待实现的 ops 区功能：统计</p>
    </section>
  )
}
