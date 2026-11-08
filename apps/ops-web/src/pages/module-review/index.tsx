// module-review 页面占位（ops-web / ops 区）
// 说明：模块审核

export interface ModuleReviewPageProps {
  title?: string
}

export default function ModuleReviewPage(props: ModuleReviewPageProps) {
  return (
    <section>
      <h2>{props.title ?? '模块审核'}</h2>
      <p>待实现的 ops 区功能：模块审核</p>
    </section>
  )
}
