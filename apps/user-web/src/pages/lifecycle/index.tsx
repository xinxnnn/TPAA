// lifecycle 页面占位（user-web / user 区）
// 说明：升级、找回（PHC 在 / PHC 不在）、注销

export interface LifecyclePageProps {
  title?: string
}

export default function LifecyclePage(props: LifecyclePageProps) {
  return (
    <section>
      <h2>{props.title ?? '升级、找回（PHC 在 / PHC 不在）、注销'}</h2>
      <p>待实现的 user 区功能：升级、找回（PHC 在 / PHC 不在）、注销</p>
    </section>
  )
}
