import { ReactNode } from 'react'

interface CardProps {
  children: ReactNode
  className?: string
  title?: string
  headerAction?: ReactNode
}

export default function Card({ children, className = '', title, headerAction }: CardProps) {
  return (
    <div className={`card ${className}`}>
      {(title || headerAction) && (
        <div className="px-6 py-4 border-b border-dark-50 flex items-center justify-between">
          {title && <h3 className="text-lg font-semibold text-gray-100">{title}</h3>}
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className="card-body">{children}</div>
    </div>
  )
}
