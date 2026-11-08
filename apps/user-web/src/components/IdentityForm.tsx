import { useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'

const MAX_PHOTO_BYTES = 64 * 1024

type Props = {
  busy: boolean
  disabled: boolean
  testAdapter?: boolean
  onSubmit: (body: { pii: Record<string, string>; bi: Record<string, string> }) => Promise<boolean>
}

function imageType(bytes: Uint8Array): 'jpeg' | 'png' | 'webp' | undefined {
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'jpeg'
  if ([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((value, i) => bytes[i] === value)) return 'png'
  if (bytes.length >= 12 && String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF'
    && String.fromCharCode(...bytes.slice(8, 12)) === 'WEBP') return 'webp'
  return undefined
}

export function IdentityForm({ busy, disabled, testAdapter = false, onSubmit }: Props) {
  const [form, setForm] = useState({ name: '', id: '', nationalId: '', email: '', passport: '', biometric: '' })
  const [photo, setPhoto] = useState<{ name: string; dataUrl: string }>()
  const [photoError, setPhotoError] = useState('')
  const photoInput = useRef<HTMLInputElement>(null)
  const set = (key: keyof typeof form, value: string) => setForm(current => ({ ...current, [key]: value }))

  async function selectPhoto(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    setPhoto(undefined)
    setPhotoError('')
    if (!file) return
    if (file.size === 0 || file.size > MAX_PHOTO_BYTES) {
      setPhotoError('图片必须非空且不超过 64 KiB。请使用合成测试照片。')
      event.target.value = ''
      return
    }
    try {
      const kind = imageType(new Uint8Array(await file.slice(0, 12).arrayBuffer()))
      if (!kind || (file.type && file.type !== `image/${kind}`)) {
        setPhotoError('仅支持内容与格式一致的 JPEG、PNG 或 WebP 图片。')
        event.target.value = ''
        return
      }
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader()
        reader.onerror = () => reject(new Error('无法读取所选图片。'))
        reader.onload = () => typeof reader.result === 'string'
          ? resolve(reader.result)
          : reject(new Error('图片读取结果无效。'))
        reader.readAsDataURL(file)
      })
      setPhoto({ name: file.name, dataUrl })
    } catch (reason) {
      setPhotoError(reason instanceof Error ? reason.message : '无法读取所选图片。')
      event.target.value = ''
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!form.name.trim() || !form.id.trim() || !form.biometric.trim() || !photo) return
    const pii = { ID: form.id.trim(), name: form.name.trim(),
                  ...(form.nationalId.trim() && { nationalId: form.nationalId.trim() }),
                  ...(form.email.trim() && { email: form.email.trim() }),
                  ...(form.passport.trim() && { passport: form.passport.trim() }) }
    const accepted = await onSubmit({ pii, bi: { iris: form.biometric.trim(), facePhoto: photo.dataUrl } })
    if (accepted) {
      setPhoto(undefined)
      if (photoInput.current) photoInput.current.value = ''
    }
  }

  return <section className="card identity-card" aria-labelledby="identity-heading">
    <div className="section-heading"><div><span className="section-kicker">IDENTITY INPUT</span><h2 id="identity-heading">用户基本信息</h2></div><span className="section-note">G1 的 CR 使用加密载荷；Portal 时间线不回显身份材料</span></div>
    {!disabled ? <form onSubmit={event => void submit(event)}>
      <div role="status" className="form-blocked-notice">
        {testAdapter
          ? '本地 test-adapter 流程：只使用合成身份和测试照片。表单提交到本机 Portal/executor，由 executor 构造加密 CR 后提交 TP。'
          : '身份材料仅会在提交时封装进加密申请。'}
      </div>
      <div className="identity-grid">
        <label>姓名 <input autoComplete="name" required disabled={disabled || busy} value={form.name} onChange={e => set('name', e.target.value)} /></label>
        <label>身份编号 ID <input required disabled={disabled || busy} value={form.id} onChange={e => set('id', e.target.value)} /></label>
        <label>身份证号 <span className="optional">选填</span><input disabled={disabled || busy} value={form.nationalId} onChange={e => set('nationalId', e.target.value)} /></label>
        <label>Email <span className="optional">选填</span><input type="email" autoComplete="email" disabled={disabled || busy} value={form.email} onChange={e => set('email', e.target.value)} /></label>
        <label>Passport <span className="optional">选填</span><input disabled={disabled || busy} value={form.passport} onChange={e => set('passport', e.target.value)} /></label>
        <label>生物特征摘要 BI <input required disabled={disabled || busy} value={form.biometric} onChange={e => set('biometric', e.target.value)} /></label>
      </div>
      <div className="form-footer">
        <div className="photo-upload">
          <label htmlFor="photo">生物照片 <span className="optional">必填 · JPEG/PNG/WebP ≤ 64 KiB</span></label>
          <input ref={photoInput} id="photo" type="file" accept="image/jpeg,image/png,image/webp" required
            disabled={disabled || busy} onChange={event => void selectPhoto(event)} />
          <small>{photo?.name ?? '照片进入 G1 加密 CR；本地 test-adapter 审核详情可预览测试照片，其他部署默认不返回原文。'}</small>
          {photoError && <small className="photo-error" role="alert">{photoError}</small>}
          {photo && <img className="photo-preview" src={photo.dataUrl} alt="所选合成测试照片预览" />}
        </div>
        <button className="primary-button" type="submit"
          disabled={disabled || busy || !form.name.trim() || !form.id.trim() || !form.biometric.trim() || !photo}>
          {busy ? '提交中…' : '提交身份申请 · G1'}
        </button>
      </div>
    </form> : <div role="status" className="form-blocked-notice">当前没有有效的用户区会话，身份申请暂不可提交。</div>}
  </section>
}
