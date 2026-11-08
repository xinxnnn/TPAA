// permissions 页面占位（ops-web / ops 区）
// 说明：权限

export interface PermissionsPageProps {
  title?: string
}

export default function PermissionsPage(props: PermissionsPageProps) {
  return (
    <section>
      <h2>{props.title ?? '权限'}</h2>
      <p>待实现的 ops 区功能：权限</p>
    </section>
  )
}
