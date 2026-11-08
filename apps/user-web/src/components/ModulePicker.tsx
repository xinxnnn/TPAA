import type { CmmCategory, Selection } from '../types'

type Props = {
  catalog: CmmCategory[]
  selection: Selection[]
  onChange: (selection: Selection[]) => void
  disabled?: boolean
}

export function ModulePicker({ catalog, selection, onChange, disabled }: Props) {
  if (!catalog.length) return <p className="inline-hint">能力目录尚未返回；请先拉取 CMM。</p>
  return <div className="module-picker" aria-label="AP 能力目录">
    {catalog.map(category => <fieldset key={category.id} disabled={disabled}>
      <legend>{category.id}</legend>
      <div className="module-versions">{category.options.map(version => {
        const present = selection.some(item => item.moduleId === category.id && item.version === version)
        return <label key={version} className="module-choice">
          <input type="checkbox" checked={present} onChange={() => onChange(present
            ? selection.filter(item => item.moduleId !== category.id || item.version !== version)
            : [...selection, { moduleId: category.id, version }])} />
          <span>{category.id} · {version}</span>
        </label>
      })}</div>
    </fieldset>)}
  </div>
}
