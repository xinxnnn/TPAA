// modules 页面占位（ap-web / ap 区）
// 说明：能力模块库 CMC、矩阵 CMM 配置、上架

export interface ModulesPageProps {
  title?: string
}

export default function ModulesPage(props: ModulesPageProps) {
  return (
    <section>
      <h2>{props.title ?? '能力模块库 CMC、矩阵 CMM 配置、上架'}</h2>
      <p>待实现的 ap 区功能：能力模块库 CMC、矩阵 CMM 配置、上架</p>
    </section>
  )
}
